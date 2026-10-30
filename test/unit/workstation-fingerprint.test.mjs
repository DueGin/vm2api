import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { normalizeTimezone } from '../../src/lib/core/timezone.mjs'
import {
  applyGeneratedFingerprint,
  DEVICE_ID_RE,
  ensureGuestMachineIdFile,
  generateWorkstationFingerprint,
  HOSTNAME_RE,
  isGeneratedHostname,
  isHexDeviceId,
  isPlaceholderHostname,
  MACHINE_ID_RE,
  takenFingerprintKeys,
  writeGuestMachineIdFile,
} from '../../src/lib/identity/workstation-fingerprint.mjs'

test('generateWorkstationFingerprint emits a coherent linux pack', () => {
  const pack = generateWorkstationFingerprint({ id: 'vm-05', kernel: 'ubuntu-24.04' })
  assert.match(pack.hostname, HOSTNAME_RE)
  assert.equal(pack.hostname.startsWith('ubuntu-'), true)
  assert.match(pack.device_id, DEVICE_ID_RE)
  assert.match(pack.guest_machine_id, MACHINE_ID_RE)
  assert.equal(pack.sku, '4c8g')
  assert.equal(pack.linux_kernel, '6.8.0-51-generic')
  assert.equal(pack.locale, 'en_US.UTF-8')
  assert.equal(pack.timezone, '')
  assert.equal(pack.source, 'generated')
  assert.equal(isGeneratedHostname(pack.hostname), true)
  assert.equal(isHexDeviceId(pack.device_id), true)
})

test('computer names fit the hostname rule and stay at most 63 characters', () => {
  assert.equal(isGeneratedHostname('macbookpro11-4-20bd08'), true)
  assert.equal(HOSTNAME_RE.test('a'.repeat(63)), true)
  assert.equal(HOSTNAME_RE.test('a'.repeat(64)), false)
  assert.equal(HOSTNAME_RE.test('-macbook'), false)
  assert.equal(HOSTNAME_RE.test('macbook-'), false)
  assert.equal(HOSTNAME_RE.test('MacBook'), false)
})

test('debian family hostname and catalog kernel', () => {
  const pack = generateWorkstationFingerprint({ id: 'vm-10', kernel: 'debian-12' })
  assert.equal(pack.hostname.startsWith('debian-'), true)
  assert.equal(pack.sku, '2c4g')
  assert.match(pack.linux_kernel, /6\.1\.0-\d+-amd64/)
})

test('collision retries until unused hostname', () => {
  const first = generateWorkstationFingerprint({ id: 'vm-01', kernel: 'ubuntu-24.04' })
  const taken = takenFingerprintKeys([{ fingerprint: first }])
  const second = generateWorkstationFingerprint({ id: 'vm-02', kernel: 'ubuntu-24.04' }, { taken })
  assert.notEqual(second.hostname, first.hostname)
  assert.notEqual(second.device_id, first.device_id)
  assert.notEqual(second.guest_machine_id, first.guest_machine_id)
})

test('missing timezone stays unset instead of a random US zone', () => {
  const pack = generateWorkstationFingerprint({ id: 'vm-05', kernel: 'ubuntu-24.04' })
  assert.equal(pack.timezone, '')
})

test('explicit America timezone is kept', () => {
  const pack = generateWorkstationFingerprint({
    id: 'vm-03',
    kernel: 'ubuntu-24.04',
    timezone: 'America/Denver',
  })
  assert.equal(pack.timezone, 'America/Denver')
})

test('explicit Tokyo timezone survives fingerprint generation and slot normalization', () => {
  const pack = generateWorkstationFingerprint({ id: 'vm-01', timezone: ' asia/tokyo ' })
  const fingerprint = applyGeneratedFingerprint({}, pack)
  assert.equal(pack.timezone, 'Asia/Tokyo')
  assert.equal(fingerprint.timezone, 'Asia/Tokyo')
  assert.equal(normalizeTimezone(pack.timezone), 'Asia/Tokyo')
  assert.equal(pack.locale, 'en_US.UTF-8')
})

test('invalid fingerprint timezone stays unset', () => {
  for (const timezone of ['', 'Asia/Not_A_Zone', 'America/Not_A_Zone', '+09:00']) {
    const pack = generateWorkstationFingerprint({ id: 'vm-01', timezone })
    assert.equal(pack.timezone, '')
  }
})

test('applyGeneratedFingerprint drops official ids for reconcile to refill', () => {
  const pack = generateWorkstationFingerprint({ id: 'vm-05', kernel: 'ubuntu-24.04' })
  const next = applyGeneratedFingerprint(
    { official_machine_id: 'old', official_user_id: 'u', identity_source: 'official-cc-init', session_id: 'keep?' },
    pack,
  )
  assert.equal(next.device_id, pack.device_id)
  assert.equal(next.hostname, pack.hostname)
  assert.equal(next.official_machine_id, undefined)
  assert.equal(next.identity_source, undefined)
})

test('writeGuestMachineIdFile replaces a docker directory trap', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-mid-'))
  const destDir = path.join(root, 'vms', 'vm-05', 'machine-id')
  fs.mkdirSync(destDir, { recursive: true })
  const dest = writeGuestMachineIdFile(root, 'vm-05', 'ab'.repeat(16))
  assert.equal(fs.statSync(dest).isFile(), true)
  assert.equal(fs.readFileSync(dest, 'utf8').trim(), 'ab'.repeat(16))
  fs.rmSync(root, { recursive: true, force: true })
})

test('ensureGuestMachineIdFile keeps a matching file and rewrites a stale one', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-mid-sync-'))
  try {
    const vm = { id: 'vm-06', fingerprint: { guest_machine_id: 'cd'.repeat(16) } }
    const dest = writeGuestMachineIdFile(root, vm.id, 'cd'.repeat(16))
    const ino = fs.statSync(dest).ino
    assert.equal(ensureGuestMachineIdFile(root, vm), dest)
    assert.equal(fs.statSync(dest).ino, ino)
    // The slot record moved on (reset / rebuild); the mount source must follow it.
    vm.fingerprint.guest_machine_id = 'EF'.repeat(16)
    assert.equal(ensureGuestMachineIdFile(root, vm), dest)
    assert.equal(fs.readFileSync(dest, 'utf8'), `${'ef'.repeat(16)}\n`)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('isPlaceholderHostname catches DMI defaults raw, slugged and with a machine-id suffix', () => {
  for (const value of [
    'System Product Name',
    'system-product-name',
    'system-product-name-53a439',
    'System Version',
    'Default string',
    'default-string-0a1b2c',
    'To Be Filled By O.E.M.',
    'to-be-filled-by-o-e-m-abcdef',
    'Not Specified',
    'Unknown',
    'unknown-123abc',
    'System manufacturer',
    '',
  ]) {
    assert.equal(isPlaceholderHostname(value), true, value)
  }
  for (const value of [
    '10t8sj9900-d57eac',
    'rog-strix-b550-f-gaming-53a439',
    'thinkcentre-m720q',
    'ubuntu-1a2b',
    'unknownhost',
  ]) {
    assert.equal(isPlaceholderHostname(value), false, value)
  }
})
