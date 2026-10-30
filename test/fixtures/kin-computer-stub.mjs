#!/usr/bin/env node
/**
 * CI/local stand-in for the closed kin-computer binary.
 * Implements: create --runtime kvm|docker --vm-id <id> --out <dir>
 *
 * Like the real binary it is a pure function of --vm-id and writes the same
 * files: hostname is `<slug(product_name)>-<machine_id[0:6]>`.
 * KIN_COMPUTER_STUB_PROFILE=placeholder     product_name is "System Product Name"
 * KIN_COMPUTER_STUB_PROFILE=placeholder-all every DMI name field is a placeholder
 * KIN_COMPUTER_STUB_EMPTY_UUID=1            publish no SMBIOS UUID (redacted profile)
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const PROFILES = {
  default: {
    sys_vendor: 'LENOVO',
    product_name: '10T8SJ9900',
    product_version: 'ThinkCentre M720q',
    product_family: 'ThinkCentre M720q',
    board_vendor: 'LENOVO',
    board_name: '3132',
  },
  placeholder: {
    sys_vendor: 'ASUS',
    product_name: 'System Product Name',
    product_version: 'System Version',
    product_family: '',
    board_vendor: 'ASUSTeK COMPUTER INC.',
    board_name: 'ROG STRIX B550-F GAMING',
  },
  'placeholder-all': {
    sys_vendor: 'System manufacturer',
    product_name: 'System Product Name',
    product_version: 'System Version',
    product_family: 'To Be Filled By O.E.M.',
    board_vendor: 'Default string',
    board_name: 'Default string',
  },
}

function usage() {
  process.stderr.write('usage: kin-computer-stub create --runtime kvm|docker --vm-id <id> --out <dir>\n')
  process.exit(2)
}

function parseCreate(argv) {
  if (argv[0] !== 'create') usage()
  let runtime = ''
  let vmId = ''
  let out = ''
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--runtime') runtime = String(argv[++i] || '')
    else if (arg === '--vm-id') vmId = String(argv[++i] || '')
    else if (arg === '--out') out = String(argv[++i] || '')
    else usage()
  }
  if (!runtime || !vmId || !out) usage()
  return { runtime, vmId, out }
}

function slug(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

function computerFor(vmId, runtime) {
  const seed = crypto.createHash('sha256').update(`kin-computer-stub:${vmId}`).digest('hex')
  const dmi = PROFILES[process.env.KIN_COMPUTER_STUB_PROFILE || 'default'] || PROFILES.default
  const machine_id = seed.slice(16, 48)
  const macBytes = Buffer.from(seed.slice(48, 60), 'hex')
  macBytes[0] = (macBytes[0] & 0xfe) | 0x02
  const raw = seed.slice(0, 32)
  const uuid =
    process.env.KIN_COMPUTER_STUB_EMPTY_UUID === '1'
      ? ''
      : `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20, 32)}`
  return {
    dmi,
    uuid,
    machine_id,
    hostname: `${slug(dmi.product_name)}-${machine_id.slice(0, 6)}`,
    mac: runtime === 'docker' ? [...macBytes].map((b) => b.toString(16).padStart(2, '0')).join(':') : '',
  }
}

function identityDoc(vmId, c) {
  const { dmi } = c
  return {
    vm_id: vmId,
    target_guest_os: 'linux',
    uuid: c.uuid,
    hostname: c.hostname,
    machine_id: c.machine_id,
    hardware: {
      model_identifier: dmi.product_name,
      hardware_uuid: c.uuid,
      board_vendor: dmi.board_vendor,
      board_id: dmi.board_name,
      sys_vendor: dmi.sys_vendor,
      en0_mac: c.mac,
    },
    smbios: [
      `type=1,manufacturer=${dmi.sys_vendor},product=${dmi.product_name},version=${dmi.product_version}${
        dmi.product_family ? `,family=${dmi.product_family}` : ''
      }${c.uuid ? `,uuid=${c.uuid}` : ''}`,
      `type=2,manufacturer=${dmi.board_vendor},product=${dmi.board_name}`,
    ],
  }
}

function writeJson(file, doc) {
  fs.writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`, 'utf8')
}

function writeKvm(out, vmId) {
  const c = computerFor(vmId, 'kvm')
  const doc = identityDoc(vmId, c)
  fs.mkdirSync(out, { recursive: true })
  writeJson(path.join(out, 'identity.json'), doc)
  writeJson(path.join(out, 'hardware.json'), doc.hardware)
  fs.writeFileSync(
    path.join(out, 'qemu-smbios.args'),
    ['-uuid', c.uuid, ...doc.smbios.flatMap((line) => ['-smbios', line]), ''].join('\n'),
    'utf8',
  )
}

function writeDocker(out, vmId) {
  const c = computerFor(vmId, 'docker')
  const etc = path.join(out, 'system', 'etc')
  const hw = path.join(out, 'system', 'hardware')
  const dmi = path.join(out, 'system', 'dmi', 'id')
  const dbus = path.join(out, 'system', 'var', 'lib', 'dbus')
  for (const dir of [etc, hw, dmi, dbus]) fs.mkdirSync(dir, { recursive: true })
  writeJson(path.join(out, 'pc_identity.json'), identityDoc(vmId, c))
  fs.writeFileSync(path.join(etc, 'hostname'), `${c.hostname}\n`, 'utf8')
  fs.writeFileSync(path.join(etc, 'hosts'), `127.0.0.1 localhost\n127.0.1.1 ${c.hostname}\n`, 'utf8')
  fs.writeFileSync(path.join(etc, 'machine-id'), `${c.machine_id}\n`, 'utf8')
  fs.writeFileSync(path.join(dbus, 'machine-id'), `${c.machine_id}\n`, 'utf8')
  fs.writeFileSync(path.join(hw, 'mac'), `${c.mac}\n`, 'utf8')
  const ids = { ...c.dmi, product_uuid: c.uuid }
  for (const [key, value] of Object.entries(ids)) fs.writeFileSync(path.join(dmi, key), `${value}\n`, 'utf8')
  fs.writeFileSync(
    path.join(etc, 'kin-computer'),
    [
      `hostname=${c.hostname}`,
      `machine_id=${c.machine_id}`,
      ...Object.entries(ids).map(([key, value]) => `id/${key}=${value}`),
      `mac=${c.mac}`,
      'source=linux-pc',
      '',
    ].join('\n'),
    'utf8',
  )
}

const { runtime, vmId, out } = parseCreate(process.argv.slice(2))
if (runtime === 'kvm') writeKvm(out, vmId)
else if (runtime === 'docker') writeDocker(out, vmId)
else usage()
