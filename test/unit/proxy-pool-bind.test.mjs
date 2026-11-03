import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import net from 'node:net'
import { ProxyPool, MAX_VMS_PER_PROXY, clampBindLimit } from '../../src/lib/vm/proxy-pool.mjs'

function tmpDir(prefix = 'kin-px-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix))
}

function makePool() {
  const pool = new ProxyPool({ dataDir: tmpDir() })
  pool.stopScheduler()
  return pool
}

test('proxy pool persists custom dns_primary and rejects invalid URLs without changing it', (t) => {
  const dir = tmpDir()
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const pool = new ProxyPool({ dataDir: dir })
  pool.stopScheduler()
  assert.equal(pool.updateConfig({ dns_primary: '8.8.8.8:53' }).ok, true)
  const primary = 'https://cloudflare-dns.com:8443/dns-query?key=a%2Cb'
  assert.equal(pool.updateConfig({ dns_primary: primary }).ok, true)
  for (const invalid of [
    '9.9.9.9:53',
    'http://cloudflare-dns.com/dns-query',
    'https://user@cloudflare-dns.com/dns-query',
    'https://cloudflare-dns.com/dns-query#fragment',
    'https://cloudflare-dns.com/dns-query?key=a,b',
    'https://cloudflare-dns.com:65536/dns-query',
  ]) {
    const result = pool.updateConfig({ dns_primary: invalid })
    assert.equal(result.ok, false, invalid)
    assert.equal(result.error, 'invalid_dns_primary', invalid)
    assert.equal(pool.snapshot().config.dns_primary, primary)
  }
  const reopened = new ProxyPool({ dataDir: dir })
  reopened.stopScheduler()
  assert.equal(reopened.snapshot().config.dns_primary, primary)
})

test('DNS type suppression persists both toggle states and rejects non-booleans', (t) => {
  const dir = tmpDir()
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const pool = new ProxyPool({ dataDir: dir })
  pool.stopScheduler()
  assert.equal(pool.snapshot().config.dns_disable_svcb_https, false)
  assert.equal(pool.updateConfig({ dns_disable_svcb_https: true }).ok, true)
  for (const value of ['false', 1, null, [], {}]) {
    const result = pool.updateConfig({ dns_disable_svcb_https: value, dns_primary: '8.8.8.8:53' })
    assert.equal(result.error, 'invalid_dns_disable_svcb_https')
    assert.equal(pool.snapshot().config.dns_disable_svcb_https, true)
    assert.equal(pool.snapshot().config.dns_primary, 'auto')
  }
  const reopened = new ProxyPool({ dataDir: dir })
  reopened.stopScheduler()
  assert.equal(reopened.snapshot().config.dns_disable_svcb_https, true)
  assert.equal(reopened.updateConfig({ dns_disable_svcb_https: false }).ok, true)
  const disabled = new ProxyPool({ dataDir: dir })
  disabled.stopScheduler()
  assert.equal(disabled.snapshot().config.dns_disable_svcb_https, false)
})

test('clampBindLimit defaults to 5 and stays in 1..32', () => {
  assert.equal(clampBindLimit(undefined), MAX_VMS_PER_PROXY)
  assert.equal(clampBindLimit(5), 5)
  assert.equal(clampBindLimit(1), 1)
  assert.equal(clampBindLimit(32), 32)
  assert.equal(clampBindLimit(0), 1)
  assert.equal(clampBindLimit(99), 32)
  assert.equal(clampBindLimit('x'), MAX_VMS_PER_PROXY)
})

test('bind_limit defaults to one slot per exit and is configurable', () => {
  const pool = makePool()
  pool.importLines('10.0.0.1:1080')
  const id = pool.snapshot().proxies[0].id
  assert.equal(MAX_VMS_PER_PROXY, 1)
  assert.equal(pool.bindLimit(), 1)
  assert.equal(pool.snapshot().config.bind_limit, 1)
  assert.equal(pool.bind(id, 'vm-01').ok, true)
  const one = pool.bind(id, 'vm-02')
  assert.equal(one.ok, false)
  assert.equal(one.error, 'proxy_bind_limit')
  assert.equal(one.max, 1)

  assert.equal(pool.updateConfig({ bind_limit: 5 }).ok, true)
  pool.stopScheduler()
  for (let i = 2; i <= 5; i++) {
    const r = pool.bind(id, `vm-0${i}`)
    assert.equal(r.ok, true, `bind vm-0${i}`)
  }
  const full = pool.bind(id, 'vm-06')
  assert.equal(full.ok, false)
  assert.equal(full.error, 'proxy_bind_limit')
  assert.equal(full.max, 5)

  const cfg = pool.updateConfig({ bind_limit: 2 })
  pool.stopScheduler()
  assert.equal(cfg.ok, true)
  assert.equal(pool.bindLimit(), 2)
  assert.equal(pool.snapshot().proxies[0].bind_limit, 2)
  assert.equal(pool.snapshot().totals.bind_limit, 2)
  // existing binds stay; new binds still rejected at the new cap
  assert.equal(pool.snapshot().proxies[0].bound_count, 5)
  assert.equal(pool.bind(id, 'vm-07').ok, false)

  pool.unbind(id)
  assert.equal(pool.bind(id, 'vm-01').ok, true)
  assert.equal(pool.bind(id, 'vm-02').ok, true)
  assert.equal(pool.bind(id, 'vm-03').ok, false)
  assert.equal(pool.bind(id, 'vm-03').max, 2)
})

test('two rows that resolve to one exit IP share its limit', () => {
  const pool = makePool()
  pool.importLines('10.0.0.11:1080\n10.0.0.12:1080\n10.0.0.13:1080')
  const [a, b, c] = pool.snapshot().proxies.map((p) => p.id)
  for (const p of pool.state.proxies) p.status = 'ok'
  // Same provider gateway behind two ports: one observed address.
  pool.state.proxies.find((p) => p.id === a).geo_ip = '203.0.113.7'
  pool.state.proxies.find((p) => p.id === b).geo_ip = '203.0.113.7'
  pool.state.proxies.find((p) => p.id === c).geo_ip = '198.51.100.9'

  assert.equal(pool.bind(a, 'vm-01').ok, true)
  assert.equal(pool.bind(c, 'vm-02').ok, true)
  const shared = pool.bind(b, 'vm-02')
  assert.equal(shared.ok, false)
  assert.equal(shared.error, 'proxy_exit_ip_shared')
  assert.equal(shared.exit_ip, '203.0.113.7')
  assert.deepEqual(shared.bound_vm_ids, ['vm-01'])
  // A refused move leaves the slot where it was.
  assert.equal(pool.getProxyForVm('vm-02')?.id, c)

  // Auto-assignment skips the row whose address is already taken.
  assert.equal(pool.allocateForVm('vm-03'), null)

  // Rebinding the same slot onto a sibling row of its own address is not "sharing".
  assert.equal(pool.bind(b, 'vm-01').ok, true)
  assert.equal(pool.getProxyForVm('vm-01')?.id, b)

  assert.equal(pool.updateConfig({ bind_limit: 2 }).ok, true)
  pool.stopScheduler()
  assert.equal(pool.bind(a, 'vm-04').ok, true)
})

test('remove deletes a proxy and updateConfig rejects bad bind_limit', () => {
  const pool = makePool()
  pool.importLines('10.0.0.2:1080')
  const id = pool.snapshot().proxies[0].id
  const removed = pool.remove(id)
  assert.equal(removed.ok, true)
  assert.equal(pool.snapshot().proxies.length, 0)
  assert.equal(pool.updateConfig({ bind_limit: 0 }).ok, false)
  assert.equal(pool.updateConfig({ bind_limit: 33 }).ok, false)
  pool.stopScheduler()
})

async function listenSocks() {
  const server = net.createServer((socket) => {
    socket.on('data', () => {
      socket.write(Buffer.from([0x05, 0x00]))
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  return { server, host: addr.address, port: addr.port }
}

test('probeOne marks egress_down after SOCKS greeting if helper is dead', async () => {
  const socks = await listenSocks()
  const pool = new ProxyPool({
    dataDir: tmpDir(),
    egressCheck: () => ({ ok: false, reason: 'not_running' }),
  })
  pool.stopScheduler()
  try {
    pool.importLines(`${socks.host}:${socks.port}`)
    const result = await pool.probeOne(pool.state.proxies[0])
    assert.equal(result.ok, false)
    assert.equal(result.error, 'not_running')
  } finally {
    pool.stopScheduler()
    socks.server.close()
  }
})

test('probeOne repairs egress then passes', async () => {
  const socks = await listenSocks()
  let healthy = false
  const pool = new ProxyPool({
    dataDir: tmpDir(),
    egressCheck: () => ({ ok: healthy }),
    repairEgress: () => {
      healthy = true
    },
  })
  pool.stopScheduler()
  try {
    pool.importLines(`${socks.host}:${socks.port}`)
    const result = await pool.probeOne(pool.state.proxies[0])
    assert.equal(result.ok, true)
    assert.equal(healthy, true)
  } finally {
    pool.stopScheduler()
    socks.server.close()
  }
})

test('startScheduler immediately repairs enabled egress', async () => {
  const socks = await listenSocks()
  let healthy = false
  let repairs = 0
  const pool = new ProxyPool({
    dataDir: tmpDir(),
    egressCheck: () => ({ ok: healthy, reason: healthy ? null : 'not_running' }),
    repairEgress: () => {
      repairs += 1
      healthy = true
    },
  })
  try {
    pool.importLines(`${socks.host}:${socks.port}`)
    pool.startScheduler()
    const deadline = Date.now() + 1000
    while (!healthy && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10))
    assert.equal(healthy, true)
    assert.equal(repairs, 1)
  } finally {
    pool.stopScheduler()
    socks.server.close()
  }
})

test('egress_down does not mark a live SOCKS proxy dead', async () => {
  const socks = await listenSocks()
  const pool = new ProxyPool({
    dataDir: tmpDir(),
    egressCheck: () => ({ ok: false, reason: 'not_running' }),
  })
  pool.stopScheduler()
  try {
    pool.importLines(`${socks.host}:${socks.port}`)
    const id = pool.snapshot().proxies[0].id
    await pool.probeById(id)
    await pool.probeById(id)
    const p = pool.snapshot().proxies[0]
    assert.equal(p.enabled, true)
    assert.equal(p.status, 'ok')
    assert.match(String(p.last_error), /egress_down/)
  } finally {
    pool.stopScheduler()
    socks.server.close()
  }
})

test('TCP connect without a SOCKS5 reply is not healthy', async () => {
  const server = net.createServer((socket) => socket.destroy())
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  const pool = new ProxyPool({ dataDir: tmpDir() })
  pool.stopScheduler()
  try {
    pool.importLines(`${addr.address}:${addr.port}`)
    const row = pool.state.proxies[0]
    const result = await pool._probeSocks(row)
    assert.equal(result.ok, false)
    assert.equal(result.error, 'not_socks5：请填写 SOCKS5 端口')
    pool._applyProbeResult(row, { ...result, scope: 'socks' })
    assert.equal(row.status, 'fail')
    assert.equal(row.last_error, 'not_socks5：请填写 SOCKS5 端口')
  } finally {
    pool.stopScheduler()
    server.close()
  }
})

test('silent TCP accept is not_socks5 instead of a healthy timeout', async () => {
  const server = net.createServer(() => {})
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  const pool = new ProxyPool({ dataDir: tmpDir() })
  pool.stopScheduler()
  pool.state.config.probe_timeout_ms = 200
  try {
    pool.importLines(`${addr.address}:${addr.port}`)
    const started = Date.now()
    const result = await pool.probeOne(pool.state.proxies[0])
    assert.equal(result.ok, false)
    assert.equal(result.scope, 'socks')
    assert.equal(result.error, 'not_socks5：请填写 SOCKS5 端口')
    assert.ok(Date.now() - started < 1500)
  } finally {
    pool.stopScheduler()
    server.close()
  }
})

test('HTTP banner is not_socks5', async () => {
  const server = net.createServer((socket) => {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  const pool = new ProxyPool({ dataDir: tmpDir() })
  pool.stopScheduler()
  try {
    pool.importLines(`${addr.address}:${addr.port}`)
    const result = await pool._probeSocks(pool.state.proxies[0])
    assert.equal(result.ok, false)
    assert.equal(result.error, 'not_socks5：请填写 SOCKS5 端口')
  } finally {
    pool.stopScheduler()
    server.close()
  }
})

test('split SOCKS5 method reply still counts as healthy', async () => {
  let client
  let releaseSecond
  const firstHandled = new Promise((resolve) => {
    releaseSecond = resolve
  })
  const server = net.createServer((socket) => {
    client = socket
    socket.write(Buffer.from([0x05]))
    firstHandled.then(() => {
      if (!socket.destroyed) socket.write(Buffer.from([0x00]))
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  const chunks = []
  const pool = new ProxyPool({ dataDir: tmpDir() })
  const connect = net.connect
  net.connect = (...args) => {
    const socket = connect.apply(net, args)
    const on = socket.on.bind(socket)
    socket.on = (event, listener) => {
      if (event !== 'data') return on(event, listener)
      return on(event, (data) => {
        chunks.push(data.length)
        const result = listener(data)
        if (chunks.length === 1) releaseSecond()
        return result
      })
    }
    return socket
  }
  pool.stopScheduler()
  try {
    pool.importLines(`${addr.address}:${addr.port}`)
    const result = await pool._probeSocks(pool.state.proxies[0])
    assert.equal(client.bytesWritten, 2)
    assert.deepEqual(chunks, [1, 1])
    assert.equal(result.ok, true)
    assert.equal(result.error, null)
  } finally {
    net.connect = connect
    pool.stopScheduler()
    server.close()
  }
})

test('probeAll resurrects a probe-killed proxy', async () => {
  const socks = await listenSocks()
  const pool = new ProxyPool({ dataDir: tmpDir() })
  pool.stopScheduler()
  try {
    pool.importLines(`${socks.host}:${socks.port}`)
    const p = pool.state.proxies[0]
    p.enabled = false
    p.status = 'dead'
    p.last_error = 'connection_closed'
    p.consecutive_failures = 2
    const report = await pool.probeAll()
    assert.equal(report.ok, true)
    assert.equal(pool.state.proxies[0].enabled, true)
    assert.equal(pool.state.proxies[0].status, 'ok')
  } finally {
    pool.stopScheduler()
    socks.server.close()
  }
})

test('ensureLocal adds a single local egress row', () => {
  const pool = makePool()
  const first = pool.ensureLocal()
  const second = pool.ensureLocal()
  assert.equal(first.ok, true)
  assert.equal(first.created, true)
  assert.equal(first.proxy.kind, 'local')
  assert.equal(first.proxy.id, 'px-local')
  assert.equal(second.created, false)
  assert.equal(pool.snapshot().proxies.filter((p) => p.kind === 'local').length, 1)
  const bound = pool.bind('px-local', 'vm-01')
  assert.equal(bound.ok, true)
  const auth = pool.getProxyForVm('vm-01')
  assert.equal(auth.scheme, 'local')
  assert.equal(auth.url, '')
})

test('local egress probe stays direct when kin-egress is down', async () => {
  const disabled = []
  const pool = new ProxyPool({
    dataDir: tmpDir(),
    egressCheck: () => ({ ok: false, reason: 'local_network_missing' }),
    onDisableVm: (vmId) => disabled.push(vmId),
  })
  pool.stopScheduler()
  pool.ensureLocal()
  pool.bind('px-local', 'vm-01')
  const row = pool.state.proxies.find((p) => p.id === 'px-local')
  const result = await pool.probeOne(row)
  assert.equal(result.ok, true)
  assert.equal(result.scope, 'local')
  assert.equal(result.mode, 'direct')
  pool._applyProbeResult(row, result)
  assert.equal(row.status, 'ok')
  assert.equal(row.enabled, true)
  assert.equal(disabled.length, 0)
})

test('a same-ASN exit is reported as a warning, never refused', () => {
  const pool = makePool()
  pool.importLines('10.0.0.21:1080\n10.0.0.22:1080\n10.0.0.23:1080')
  const [a, b, c] = pool.snapshot().proxies.map((p) => p.id)
  for (const p of pool.state.proxies) p.status = 'ok'
  const rowA = pool.state.proxies.find((p) => p.id === a)
  const rowB = pool.state.proxies.find((p) => p.id === b)
  const rowC = pool.state.proxies.find((p) => p.id === c)
  // One provider, two addresses in different /24s: the exit-IP check cannot see it.
  Object.assign(rowA, { geo_ip: '216.151.254.119', geo_asn: 'AS2914' })
  Object.assign(rowB, { geo_ip: '128.241.18.56', geo_asn: 'AS2914' })
  Object.assign(rowC, { geo_ip: '198.51.100.9', geo_asn: 'AS7029' })

  const first = pool.bind(a, 'vm-01')
  assert.equal(first.ok, true)
  assert.equal(first.same_asn_vm_ids, undefined)

  const second = pool.bind(b, 'vm-02')
  assert.equal(second.ok, true, 'the bind still succeeds')
  assert.deepEqual(second.same_asn_vm_ids, ['vm-01'])
  assert.equal(second.asn, 'AS2914')
  assert.equal(pool.getProxyForVm('vm-02')?.id, b)

  const third = pool.bind(c, 'vm-03')
  assert.equal(third.ok, true)
  assert.equal(third.same_asn_vm_ids, undefined)

  // No ASN yet: nothing to compare, and no false warning.
  rowC.geo_asn = null
  pool.stopScheduler()
  assert.equal(pool.vmsOnSameAsn(rowC).length, 0)
})

test('geo_asn survives a reopen of the pool', (t) => {
  const dir = tmpDir()
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const pool = new ProxyPool({ dataDir: dir })
  pool.stopScheduler()
  pool.importLines('10.0.0.31:1080')
  const row = pool.state.proxies[0]
  pool._applyGeoResult(row, {
    ok: true,
    geo: { ip: '212.111.221.6', isp: 'URAN', asn: 'AS7029', timezone: 'America/New_York' },
  })
  pool.save()
  const reopened = new ProxyPool({ dataDir: dir })
  reopened.stopScheduler()
  const back = reopened.state.proxies[0]
  assert.equal(back.geo_asn, 'AS7029')
  // ISP text is mirrored into native telemetry; it keeps its own plain value.
  assert.equal(back.geo_isp, 'URAN')
})
