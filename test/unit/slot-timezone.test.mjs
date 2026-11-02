import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { ProxyPool } from '../../src/lib/vm/proxy-pool.mjs'
import { syncVmTimezoneFromProxy } from '../../src/lib/vm/proxy-timezone.mjs'
import { followExitGeoChange } from '../../src/lib/vm/slot-timezone-follow.mjs'
import { evaluateSlotGate } from '../../src/lib/pool/schedule-eligibility.mjs'
import { isCodexSlotReady } from '../../src/lib/pool/codex-slot-pool.mjs'
import { stateOfReason } from '../../src/lib/pool/schedule-state.mjs'
import { getVm, persistVmTimezone } from '../../src/lib/vm/vm-registry.mjs'
import { slotTimezoneUnknown } from '../../src/lib/vm/vm-runtime.mjs'

function setup(t, { geo = [] } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-tz-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const answers = [...geo]
  const lookups = []
  const pool = new ProxyPool({
    dataDir: path.join(root, 'data'),
    geoLookup: async (url) => {
      lookups.push(url)
      return answers.length ? answers.shift() : { ok: false, error: 'geo_lookup_failed' }
    },
    geoV6Lookup: async () => ({ ok: false, error: 'no_ipv6' }),
  })
  pool.stopScheduler()
  t.after(() => pool.stopScheduler())
  pool.importLines('10.9.0.1:1080')
  const proxyId = pool.snapshot().proxies[0].id
  return { root, pool, proxyId, lookups }
}

function writeVm(root, rec) {
  const dir = path.join(root, 'vms')
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, `${rec.id}.json`), JSON.stringify(rec))
}

function slot(proxyId, extra = {}) {
  return {
    id: 'vm-01',
    status: 'running',
    timezone: 'America/Los_Angeles',
    timezone_source: 'proxy_geo',
    proxy: { id: proxyId, url: 'socks5://10.9.0.1:1080', host: '10.9.0.1', port: 1080, scheme: 'socks5' },
    proxy_cli_enabled: true,
    fingerprint: { timezone: 'America/Los_Angeles' },
    claude: { has_access: true, has_refresh: true },
    ...extra,
  }
}

const TOKYO = { ok: true, geo: { ip: '203.0.113.7', country: 'Japan', timezone: 'Asia/Tokyo' } }

test('a zone read from the exit is applied and recorded as aligned', async (t) => {
  const { root, pool, proxyId } = setup(t, { geo: [TOKYO] })
  writeVm(root, slot(proxyId))
  const synced = await syncVmTimezoneFromProxy(root, pool, 'vm-01', { proxyId })
  assert.equal(synced.ok, true)
  const vm = getVm(root, 'vm-01')
  assert.equal(vm.timezone, 'Asia/Tokyo')
  assert.equal(vm.fingerprint.timezone, 'Asia/Tokyo')
  assert.equal(vm.exit_timezone.status, 'aligned')
  assert.equal(vm.exit_timezone.timezone, 'Asia/Tokyo')
  assert.notEqual(evaluateSlotGate(vm).reason, 'exit_timezone_unknown')
})

test('an unreadable exit keeps the slot out of the pool instead of keeping the old zone', async (t) => {
  const { root, pool, proxyId } = setup(t, { geo: [{ ok: false, error: 'geo_timeout' }] })
  // Rebound onto a new exit whose location could not be read.
  writeVm(root, slot(proxyId))
  const synced = await syncVmTimezoneFromProxy(root, pool, 'vm-01', { proxyId })
  assert.equal(synced.ok, false)
  const vm = getVm(root, 'vm-01')
  assert.equal(vm.exit_timezone.status, 'unknown')
  assert.equal(vm.exit_timezone.proxy_id, proxyId)
  assert.deepEqual(evaluateSlotGate(vm), { ok: false, reason: 'exit_timezone_unknown' })
  assert.equal(stateOfReason('exit_timezone_unknown').text, '出口时区未知')

  // A later successful lookup clears it.
  pool.state.proxies[0].geo_timezone = 'Asia/Tokyo'
  pool.state.proxies[0].geo_ip = '203.0.113.7'
  await syncVmTimezoneFromProxy(root, pool, 'vm-01', { proxyId, detect: false })
  assert.equal(getVm(root, 'vm-01').exit_timezone.status, 'aligned')
  assert.notEqual(evaluateSlotGate(getVm(root, 'vm-01')).reason, 'exit_timezone_unknown')
})

test('a hand-set zone is the operator call and lifts the unknown verdict', async (t) => {
  const { root, pool, proxyId } = setup(t)
  writeVm(root, slot(proxyId))
  await syncVmTimezoneFromProxy(root, pool, 'vm-01', { proxyId })
  assert.equal(getVm(root, 'vm-01').exit_timezone.status, 'unknown')
  persistVmTimezone(root, 'vm-01', 'Europe/Berlin', { source: 'manual' })
  const vm = getVm(root, 'vm-01')
  assert.equal(vm.exit_timezone.status, 'pinned')
  assert.notEqual(evaluateSlotGate(vm).reason, 'exit_timezone_unknown')

  // A pinned zone is not overwritten by a later follow, and is not "unknown".
  const again = await syncVmTimezoneFromProxy(root, pool, 'vm-01', { proxyId })
  assert.equal(again.reason, 'timezone_pinned')
  assert.equal(getVm(root, 'vm-01').timezone, 'Europe/Berlin')
  assert.equal(getVm(root, 'vm-01').exit_timezone.status, 'pinned')
})

test('a preview sync (persist: false) records nothing', async (t) => {
  const { root, pool, proxyId } = setup(t)
  writeVm(root, slot(proxyId))
  await syncVmTimezoneFromProxy(root, pool, 'vm-01', { proxyId, persist: false })
  assert.equal(getVm(root, 'vm-01').exit_timezone, undefined)
})

test('bound exits are re-read on schedule and a move is reported once', async (t) => {
  const { pool, proxyId, lookups } = setup(t, {
    geo: [{ ok: true, geo: { ip: '198.51.100.9', country: 'Germany', timezone: 'Europe/Berlin' } }],
  })
  pool.importLines('10.9.0.2:1080')
  const idle = pool.snapshot().proxies.find((row) => row.id !== proxyId).id
  assert.equal(pool.bind(proxyId, 'vm-01').ok, true)
  const row = pool.state.proxies.find((p) => p.id === proxyId)
  Object.assign(row, {
    geo_ip: '203.0.113.7',
    geo_timezone: 'Asia/Tokyo',
    geo_checked_at: new Date(Date.now() - 2 * 3600_000).toISOString(),
  })
  const events = []
  pool.on('geo-change', (change) => events.push(change))
  const out = await pool.refreshBoundGeo()
  assert.equal(out.refreshed, 1, 'only the bound row is re-read')
  assert.equal(lookups.length, 1)
  assert.equal(events.length, 1)
  assert.deepEqual(events[0], {
    proxy_id: proxyId,
    from: { ip: '203.0.113.7', timezone: 'Asia/Tokyo' },
    to: { ip: '198.51.100.9', timezone: 'Europe/Berlin' },
    bound_vm_ids: ['vm-01'],
  })
  assert.ok(idle)

  // Fresh again: nothing due. A failed re-read keeps the known location.
  assert.equal((await pool.refreshBoundGeo()).refreshed, 0)
  row.geo_checked_at = new Date(0).toISOString()
  const failed = await pool.refreshBoundGeo()
  assert.equal(failed.changes.length, 0)
  assert.equal(row.geo_timezone, 'Europe/Berlin')

  assert.equal(pool.updateConfig({ geo_refresh_min: 0 }).ok, true)
  pool.stopScheduler()
  row.geo_checked_at = new Date(0).toISOString()
  assert.equal((await pool.refreshBoundGeo()).refreshed, 0, '0 turns it off')
  assert.equal(pool.updateConfig({ geo_refresh_min: 5000 }).ok, false)
})

test('slots follow a moved exit and the new zone goes into the kernel config', async (t) => {
  const { root, pool, proxyId } = setup(t)
  writeVm(root, slot(proxyId))
  writeVm(root, slot(proxyId, { id: 'vm-02', timezone: 'Asia/Tokyo', timezone_source: 'manual' }))
  Object.assign(pool.state.proxies[0], { geo_ip: '198.51.100.9', geo_timezone: 'Europe/Berlin' })
  const kernelWrites = []
  const warnings = []
  const results = await followExitGeoChange(
    {
      proxy_id: proxyId,
      from: { ip: '203.0.113.7', timezone: 'Asia/Tokyo' },
      to: { ip: '198.51.100.9', timezone: 'Europe/Berlin' },
      bound_vm_ids: ['vm-01', 'vm-02'],
    },
    {
      projectRoot: root,
      proxyPool: pool,
      writeKernel: (_root, vm, opts) => {
        kernelWrites.push([vm.id, opts.timezone])
        return { changed: true }
      },
      log: { warn: (line) => warnings.push(line) },
    },
  )
  assert.equal(getVm(root, 'vm-01').timezone, 'Europe/Berlin')
  assert.deepEqual(kernelWrites, [['vm-01', 'Europe/Berlin']])
  assert.equal(results[0].kernel_hot, true)
  // The pinned slot keeps its zone.
  assert.equal(getVm(root, 'vm-02').timezone, 'Asia/Tokyo')
  assert.equal(results[1].reason, 'timezone_pinned')
  assert.match(warnings[0], /proxy-exit-ip-changed/)
})

test('a slot with no zone is refused rather than started on a default zone', () => {
  const refused = slotTimezoneUnknown({ exit_timezone: { status: 'unknown', reason: 'geo_timeout' } })
  assert.equal(refused.ok, false)
  assert.equal(refused.code, 'slot_timezone_unknown')
  assert.match(refused.error, /geo_timeout/)
})

test('GPT slots follow the same rule', () => {
  const gpt = {
    id: 'vm-gpt',
    platform: 'openai',
    family: 'codex',
    status: 'running',
    has_token: true,
    has_refresh: true,
    proxy: { id: 'px-1', url: 'socks5://10.9.0.1:1080' },
  }
  assert.equal(isCodexSlotReady(gpt), true)
  assert.equal(isCodexSlotReady({ ...gpt, exit_timezone: { status: 'unknown' } }), false)
  assert.equal(isCodexSlotReady({ ...gpt, exit_timezone: { status: 'aligned' } }), true)
})
