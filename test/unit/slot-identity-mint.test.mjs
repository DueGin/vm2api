import '../fixtures/kin-computer-test-env.mjs'
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { RFC4122_UUID_RE } from '../../src/lib/identity/rfc4122-uuid.mjs'
import {
  HOSTNAME_RE,
  isPlaceholderHostname,
  MACHINE_ID_RE,
  takenFingerprintKeys,
} from '../../src/lib/identity/workstation-fingerprint.mjs'
import {
  assignComputerFingerprint,
  computerBin,
  ensureSlotComputer,
  fingerprintDir,
} from '../../src/lib/identity/slot-computer.mjs'

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/
const RUNTIMES = ['docker', 'kvm']

function withRoot(prefix, fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix))
  try {
    return fn(root)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
}

function withProfile(profile, fn) {
  const prev = process.env.KIN_COMPUTER_STUB_PROFILE
  if (profile) process.env.KIN_COMPUTER_STUB_PROFILE = profile
  else delete process.env.KIN_COMPUTER_STUB_PROFILE
  try {
    return fn()
  } finally {
    if (prev == null) delete process.env.KIN_COMPUTER_STUB_PROFILE
    else process.env.KIN_COMPUTER_STUB_PROFILE = prev
  }
}

function slotVm(id, runtime) {
  return { id, kernel: 'ubuntu-24.04', runtime: { type: runtime } }
}

function emptyTaken() {
  return takenFingerprintKeys([])
}

function read(file) {
  return fs.readFileSync(file, 'utf8')
}

function readJson(file) {
  return JSON.parse(read(file))
}

function walk(dir) {
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]))
}

function snapshot(dir) {
  return Object.fromEntries(
    walk(dir).map((file) => {
      const st = fs.statSync(file)
      return [file, `${st.mtimeMs}:${st.ino}:${read(file)}`]
    }),
  )
}

/** Every copy of hostname / machine-id / MAC / UUID the computer directory carries. */
function embedded(dir, runtime) {
  if (runtime === 'kvm') {
    const ident = readJson(path.join(dir, 'identity.json'))
    const args = read(path.join(dir, 'qemu-smbios.args'))
    return {
      hostname: [ident.hostname],
      machine_id: [ident.machine_id],
      mac: [],
      uuid: [
        ident.uuid,
        ident.hardware.hardware_uuid,
        readJson(path.join(dir, 'hardware.json')).hardware_uuid,
        /-uuid\n([^\n]*)/.exec(args)?.[1],
        /type=1,[^\n]*uuid=([^,\n]*)/.exec(args)?.[1],
        /uuid=([^,]*)/.exec(ident.smbios.find((line) => line.startsWith('type=1,')))?.[1],
      ],
    }
  }
  const etc = path.join(dir, 'system', 'etc')
  const pc = readJson(path.join(dir, 'pc_identity.json'))
  const kc = Object.fromEntries(
    read(path.join(etc, 'kin-computer'))
      .split('\n')
      .filter((line) => line.includes('='))
      .map((line) => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]),
  )
  const selfLine = read(path.join(etc, 'hosts'))
    .split('\n')
    .find((line) => line.startsWith('127.0.1.1 '))
  return {
    hostname: [read(path.join(etc, 'hostname')).trim(), pc.hostname, kc.hostname, selfLine?.split(/\s+/)[1]],
    machine_id: [
      read(path.join(etc, 'machine-id')).trim(),
      read(path.join(dir, 'system', 'var', 'lib', 'dbus', 'machine-id')).trim(),
      pc.machine_id,
      kc.machine_id,
    ],
    mac: [read(path.join(dir, 'system', 'hardware', 'mac')).trim(), pc.hardware.en0_mac, kc.mac],
    uuid: [
      pc.uuid,
      pc.hardware.hardware_uuid,
      read(path.join(dir, 'system', 'dmi', 'id', 'product_uuid')).trim(),
      kc['id/product_uuid'],
    ],
  }
}

function assertOne(values, label) {
  assert.equal(new Set(values).size, 1, `${label} copies disagree: ${JSON.stringify(values)}`)
  return values[0]
}

/** What the binary alone writes for this vm-id: the identity every install would share. */
function binaryComputer(runtime, vmId) {
  return withRoot('kin-computer-raw-', (root) => {
    execFileSync(computerBin(), ['create', '--runtime', runtime, '--vm-id', vmId, '--out', root])
    const doc = readJson(path.join(root, runtime === 'kvm' ? 'identity.json' : 'pc_identity.json'))
    return { hostname: doc.hostname, machine_id: doc.machine_id, mac: doc.hardware.en0_mac, uuid: doc.uuid }
  })
}

for (const runtime of RUNTIMES) {
  test(`${runtime}: the same vm-id built twice gets a new machine-id, hostname and MAC`, () => {
    const raw = binaryComputer(runtime, 'vm-02')
    const builds = [1, 2].map(() =>
      withRoot('kin-mint-twice-', (root) => {
        const pack = assignComputerFingerprint(root, slotVm('vm-02', runtime), { taken: emptyTaken() })
        const computer = ensureSlotComputer(root, slotVm('vm-02', runtime))
        assert.equal(computer.hostname, pack.hostname)
        assert.equal(computer.guest_machine_id, pack.guest_machine_id)
        return computer
      }),
    )
    for (const computer of builds) {
      assert.notEqual(computer.guest_machine_id, raw.machine_id)
      assert.notEqual(computer.hostname, raw.hostname)
      if (runtime === 'docker') assert.notEqual(computer.mac, raw.mac)
    }
    assert.notEqual(builds[0].guest_machine_id, builds[1].guest_machine_id)
    assert.notEqual(builds[0].hostname, builds[1].hostname)
    if (runtime === 'docker') assert.notEqual(builds[0].mac, builds[1].mac)
    // The model slug is the binary's: hardware is chosen by vm-id on purpose.
    assert.equal(builds[0].hostname.slice(0, -7), raw.hostname.slice(0, -7))
  })

  test(`${runtime}: deleting the computer and rebuilding the same vm-id mints again`, () =>
    withRoot('kin-mint-rebuild-', (root) => {
      const vm = slotVm('vm-04', runtime)
      const first = assignComputerFingerprint(root, vm, { taken: emptyTaken() })
      fs.rmSync(path.join(root, 'vms'), { recursive: true, force: true })
      const second = assignComputerFingerprint(root, vm, { taken: emptyTaken() })
      assert.notEqual(second.guest_machine_id, first.guest_machine_id)
      assert.notEqual(second.hostname, first.hostname)
    }))

  test(`${runtime}: hostname suffix is the first 6 of the machine-id and every copy agrees`, () =>
    withRoot('kin-mint-coherent-', (root) => {
      const vm = slotVm('vm-07', runtime)
      const raw = binaryComputer(runtime, 'vm-07')
      for (let round = 0; round < 2; round++) {
        const pack = assignComputerFingerprint(root, vm, { taken: emptyTaken(), fresh: true })
        const dir = fingerprintDir(root, vm.id)
        const copies = embedded(dir, runtime)
        const hostname = assertOne(copies.hostname, 'hostname')
        const machineId = assertOne(copies.machine_id, 'machine-id')
        assert.equal(hostname, pack.hostname)
        assert.equal(machineId, pack.guest_machine_id)
        assert.match(hostname, HOSTNAME_RE)
        assert.match(machineId, MACHINE_ID_RE)
        assert.equal(hostname.slice(-7), `-${machineId.slice(0, 6)}`)
        const uuid = assertOne(copies.uuid, 'uuid')
        assert.match(uuid, RFC4122_UUID_RE)
        assert.notEqual(uuid, raw.uuid)
        if (runtime === 'docker') {
          const mac = assertOne(copies.mac, 'mac')
          assert.match(mac, MAC_RE)
          const first = Number.parseInt(mac.slice(0, 2), 16)
          assert.equal(first & 0x01, 0, 'unicast')
          assert.equal(first & 0x02, 0x02, 'locally administered')
        }
        // No trace of the binary's shared values is left anywhere in the directory.
        for (const file of walk(dir)) {
          const text = read(file)
          for (const old of [raw.machine_id, raw.hostname, raw.mac, raw.uuid].filter(Boolean)) {
            assert.equal(text.includes(old), false, `${path.relative(dir, file)} still carries ${old}`)
          }
        }
      }
    }))

  test(`${runtime}: a placeholder DMI profile never yields a placeholder hostname`, () => {
    for (const [profile, base] of [
      ['placeholder', 'rog-strix-b550-f-gaming'],
      ['placeholder-all', 'ubuntu'],
    ]) {
      withProfile(profile, () => {
        assert.equal(isPlaceholderHostname(binaryComputer(runtime, 'vm-01').hostname), true)
        for (const id of ['vm-01', 'vm-03', 'vm-11']) {
          withRoot('kin-mint-placeholder-', (root) => {
            const pack = assignComputerFingerprint(root, slotVm(id, runtime), { taken: emptyTaken() })
            assert.equal(isPlaceholderHostname(pack.hostname), false, pack.hostname)
            assert.equal(pack.hostname, `${base}-${pack.guest_machine_id.slice(0, 6)}`)
          })
        }
      })
    }
  })

  test(`${runtime}: the read path neither reruns the binary nor rewrites an existing computer`, () =>
    withRoot('kin-mint-read-', (root) => {
      const vm = slotVm('vm-08', runtime)
      const pack = assignComputerFingerprint(root, vm, { taken: emptyTaken() })
      const dir = fingerprintDir(root, vm.id)
      const before = snapshot(dir)
      const prevBin = process.env.KIN_COMPUTER_BIN
      process.env.KIN_COMPUTER_BIN = path.join(root, 'no-binary-on-read')
      try {
        for (let i = 0; i < 3; i++) {
          const read = ensureSlotComputer(root, vm)
          assert.equal(read.created, false)
          assert.equal(read.hostname, pack.hostname)
          assert.equal(read.guest_machine_id, pack.guest_machine_id)
        }
      } finally {
        process.env.KIN_COMPUTER_BIN = prevBin
      }
      assert.deepEqual(snapshot(dir), before)
    }))

  test(`${runtime}: an old slot with a placeholder hostname stays as is on read`, () =>
    withRoot('kin-mint-legacy-', (root) => {
      const vm = slotVm('vm-01', runtime)
      const dir = fingerprintDir(root, vm.id)
      fs.mkdirSync(dir, { recursive: true })
      withProfile('placeholder', () =>
        execFileSync(computerBin(), ['create', '--runtime', runtime, '--vm-id', vm.id, '--out', dir]),
      )
      const legacy = ensureSlotComputer(root, vm)
      const before = snapshot(dir)
      const again = ensureSlotComputer(root, vm)
      assert.equal(again.created, false)
      assert.equal(again.hostname, legacy.hostname)
      assert.equal(isPlaceholderHostname(again.hostname), true)
      assert.deepEqual(snapshot(dir), before)
      // reset-fingerprint keeps it too; only a fresh rebuild (directory dropped) replaces it.
      const reset = assignComputerFingerprint(root, vm, { taken: emptyTaken() })
      assert.equal(reset.hostname, legacy.hostname)
      assert.deepEqual(snapshot(dir), before)
      const rebuilt = assignComputerFingerprint(root, vm, { taken: emptyTaken(), fresh: true })
      assert.equal(isPlaceholderHostname(rebuilt.hostname), false)
      assert.notEqual(rebuilt.guest_machine_id, legacy.guest_machine_id)
    }))

  test(`${runtime}: a taken hostname or machine-id is re-minted, not a hard failure`, () =>
    withRoot('kin-mint-taken-', (root) => {
      const vm = slotVm('vm-09', runtime)
      let refused = 0
      const busy = { has: () => refused++ < 3 }
      const pack = assignComputerFingerprint(root, vm, {
        taken: { hostname: busy, device_id: new Set(), guest_machine_id: new Set() },
      })
      assert.ok(refused >= 4)
      assert.match(pack.guest_machine_id, MACHINE_ID_RE)
      const full = { has: () => true }
      assert.throws(
        () =>
          assignComputerFingerprint(root, vm, {
            taken: { hostname: new Set(), device_id: new Set(), guest_machine_id: full },
            fresh: true,
          }),
        /workstation fingerprint collision/,
      )
    }))

  test(`${runtime}: reset on an existing computer keeps hostname, machine-id and MAC`, () =>
    withRoot('kin-mint-reset-', (root) => {
      const vm = slotVm('vm-10', runtime)
      const first = assignComputerFingerprint(root, vm, { taken: emptyTaken() })
      const dir = fingerprintDir(root, vm.id)
      const before = snapshot(dir)
      const mac = ensureSlotComputer(root, vm).mac
      const again = assignComputerFingerprint(root, vm, { taken: emptyTaken() })
      assert.equal(again.hostname, first.hostname)
      assert.equal(again.guest_machine_id, first.guest_machine_id)
      assert.notEqual(again.device_id, first.device_id)
      assert.equal(ensureSlotComputer(root, vm).mac, mac)
      assert.deepEqual(snapshot(dir), before)
    }))

  test(`${runtime}: a lost computer directory is rebuilt with the slot record's identity`, () =>
    withRoot('kin-mint-restore-', (root) => {
      const pack = assignComputerFingerprint(root, slotVm('vm-14', runtime), { taken: emptyTaken() })
      const mac = runtime === 'docker' ? '02:11:22:33:44:55' : ''
      const vm = {
        ...slotVm('vm-14', runtime),
        fingerprint: {
          hostname: pack.hostname,
          guest_machine_id: pack.guest_machine_id,
          ...(mac ? { hardware: { mac: mac.toUpperCase() } } : {}),
        },
      }
      fs.rmSync(fingerprintDir(root, vm.id), { recursive: true, force: true })
      const restored = ensureSlotComputer(root, vm)
      assert.equal(restored.created, true)
      assert.equal(restored.hostname, pack.hostname)
      assert.equal(restored.guest_machine_id, pack.guest_machine_id)
      if (mac) assert.equal(restored.mac, mac)
      const copies = embedded(fingerprintDir(root, vm.id), runtime)
      assert.equal(assertOne(copies.hostname, 'hostname'), pack.hostname)
      assert.equal(assertOne(copies.machine_id, 'machine-id'), pack.guest_machine_id)
      if (mac) assert.equal(assertOne(copies.mac, 'mac'), mac)
      // A recorded placeholder hostname is restored as is, not repaired on read.
      fs.rmSync(fingerprintDir(root, vm.id), { recursive: true, force: true })
      const legacy = { ...vm, fingerprint: { ...vm.fingerprint, hostname: 'system-product-name-53a439' } }
      assert.equal(ensureSlotComputer(root, legacy).hostname, 'system-product-name-53a439')
    }))

  test(`${runtime}: a lost computer directory with no record is minted, never the binary's`, () =>
    withRoot('kin-mint-norecord-', (root) => {
      const raw = binaryComputer(runtime, 'vm-15')
      const computer = ensureSlotComputer(root, slotVm('vm-15', runtime))
      assert.equal(computer.created, true)
      assert.notEqual(computer.guest_machine_id, raw.machine_id)
      assert.notEqual(computer.hostname, raw.hostname)
      assert.equal(computer.hostname.slice(-7), `-${computer.guest_machine_id.slice(0, 6)}`)
      if (runtime === 'docker') assert.notEqual(computer.mac, raw.mac)
    }))
}
