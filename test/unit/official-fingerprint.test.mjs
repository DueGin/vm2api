import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  reconcileFingerprint,
  applyOfficialFingerprintToVm,
  discardLeftoverClaudeJson,
  readOfficialCcIdentity,
  OFFICIAL_IDENTITY_SOURCE,
} from '../../src/lib/identity/official-fingerprint.mjs'

test('official userID becomes the slot device_id; a legacy machineID is only recorded', () => {
  const machine = 'aa'.repeat(32)
  const user = 'bb'.repeat(32)
  const next = reconcileFingerprint(
    { device_id: 'slot-uuid', machine_id: 'guest-os', session_id: 'sess' },
    { machine_id: machine, user_id: user },
  )
  // The CLI sends userID as device_id on its requests and 1P events.
  assert.equal(next.device_id, user)
  assert.equal(next.official_machine_id, machine)
  assert.equal(next.official_user_id, user)
  assert.equal(next.identity_source, OFFICIAL_IDENTITY_SOURCE)
  assert.equal(next.guest_machine_id, 'guest-os')
  assert.equal(next.machine_id, undefined)
  assert.equal(next.session_id, 'sess')
})

test('legacy machineID stands in only when there is no userID', () => {
  const machine = 'ab'.repeat(32)
  const next = reconcileFingerprint({ device_id: 'slot-uuid' }, { machine_id: machine })
  assert.equal(next.device_id, machine)
})

test('applyOfficialFingerprintToVm keeps both Claude identity files', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-fp-'))
  const home = path.join(root, 'cli-home')
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true })
  const machine = 'cc'.repeat(32)
  const user = 'dd'.repeat(32)
  // CLAUDE_CONFIG_DIR=~/.claude: the nested file is the CLI's own.
  fs.writeFileSync(
    path.join(home, '.claude', '.claude.json'),
    JSON.stringify({
      userID: user,
      oauthAccount: { accountUuid: 'acc-1' },
    }),
  )
  // Home-level copy from an older init, carrying a legacy machineID.
  fs.writeFileSync(
    path.join(home, '.claude.json'),
    JSON.stringify({
      machineID: machine,
      userID: 'ee'.repeat(32),
    }),
  )
  const vmPath = path.join(root, 'vm-30.json')
  fs.writeFileSync(
    vmPath,
    JSON.stringify({
      id: 'vm-30',
      fingerprint: { device_id: 'slot-uuid', official_machine_id: 'old-mid' },
    }),
  )
  fs.writeFileSync(
    path.join(home, '.claude', 'kin-identity.json'),
    JSON.stringify({
      device_id: 'slot-uuid',
      account_uuid: 'acc-1',
    }),
  )
  const result = applyOfficialFingerprintToVm(vmPath, home)
  assert.equal(result.wrote, true)
  assert.equal(result.replaced_device, true)
  assert.equal(result.leftover.removed, false)
  assert.equal(result.leftover.conflict, true)
  const vm = JSON.parse(fs.readFileSync(vmPath, 'utf8'))
  assert.equal(vm.fingerprint.device_id, user)
  assert.equal(vm.fingerprint.official_user_id, user)
  assert.equal(vm.fingerprint.identity_source, OFFICIAL_IDENTITY_SOURCE)
  assert.equal(fs.existsSync(path.join(home, '.claude', '.claude.json')), true)
  assert.equal(fs.existsSync(path.join(home, '.claude.json')), true)
  const ident = JSON.parse(fs.readFileSync(path.join(home, '.claude', 'kin-identity.json'), 'utf8'))
  assert.equal(ident.device_id, user)
  fs.rmSync(root, { recursive: true, force: true })
})

test('init reads CLAUDE_CONFIG_DIR identity without deleting its source', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-fp-nested-'))
  const home = path.join(root, 'cli-home')
  const nested = path.join(home, '.claude', '.claude.json')
  const vmPath = path.join(root, 'vm-01.json')
  try {
    fs.mkdirSync(path.dirname(nested), { recursive: true })
    fs.writeFileSync(nested, JSON.stringify({ machineID: 'official-machine', userID: 'official-user' }))
    fs.writeFileSync(vmPath, JSON.stringify({ id: 'vm-01', fingerprint: { device_id: 'slot-machine' } }))
    const applied = applyOfficialFingerprintToVm(vmPath, home)
    assert.equal(applied.official, true)
    assert.equal(readOfficialCcIdentity(home).machine_id, 'official-machine')
    assert.equal(JSON.parse(fs.readFileSync(vmPath, 'utf8')).fingerprint.device_id, 'official-machine')
    assert.equal(JSON.parse(fs.readFileSync(nested, 'utf8')).userID, 'official-user')
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('discardLeftoverClaudeJson is a no-op when missing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-fp-miss-'))
  assert.deepEqual(discardLeftoverClaudeJson(root), { removed: false, conflict: false })
  fs.rmSync(root, { recursive: true, force: true })
})
