/**
 * One computer per slot, created by the closed kin-computer binary before the
 * guest starts. The hardware profile and device codes stay in that binary.
 * The binary is a pure function of --vm-id, so every install's vm-02 would share
 * one machine-id; the unique fields (machine-id, hostname suffix, MAC, SMBIOS
 * UUID) are minted here on every construction and written back into its files.
 * device_id stays a control-plane 64-bit value and is never the SMBIOS UUID.
 */
import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { isKvmRuntime } from '../vm/runtime-kind.mjs'
import { atomicWriteJson } from '../vm/vm-file.mjs'
import {
  generateWorkstationFingerprint,
  HOSTNAME_RE,
  hostnameSlug,
  isPlaceholderHostname,
  MACHINE_ID_RE,
} from './workstation-fingerprint.mjs'
import { workstationFamily } from './workstation-profile.mjs'
import { isRfc4122Uuid } from './rfc4122-uuid.mjs'
import { patchQemuSmbiosArgsUuid, repairKvmFingerprintUuid } from './kvm-fingerprint-uuid.mjs'

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/
const MINT_ATTEMPTS = 16
/** Hostname is `<base>-<first 6 of machine-id>`, like the binary writes it. */
const HOST_SUFFIX = 6
const HOST_BASE_MAX = 63 - HOST_SUFFIX - 1
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

export function computerBin() {
  const fromEnv = String(process.env.KIN_COMPUTER_BIN || '').trim()
  if (fromEnv) return fromEnv
  return path.join(REPO_ROOT, 'bin', 'kin-computer')
}

export function fingerprintDir(projectRoot, vmId) {
  return path.join(projectRoot, 'vms', vmId, 'kvm', 'fingerprint')
}

function readTrimmed(file) {
  return fs.readFileSync(file, 'utf8').replace(/\s+/g, '')
}

function linuxComputer(dir) {
  const identPath = path.join(dir, 'identity.json')
  const smbios = path.join(dir, 'qemu-smbios.args')
  if (!fs.existsSync(identPath) || !fs.existsSync(smbios)) return null
  let data
  try {
    data = JSON.parse(fs.readFileSync(identPath, 'utf8'))
  } catch {
    return null
  }
  const hostname = String(data.hostname || '').trim()
  const guest_machine_id = String(data.machine_id || '')
    .trim()
    .toLowerCase()
  const uuid = String(data.uuid || '').trim()
  if (!HOSTNAME_RE.test(hostname) || !MACHINE_ID_RE.test(guest_machine_id) || !isRfc4122Uuid(uuid)) return null
  try {
    if (!fs.statSync(smbios).size) return null
  } catch {
    return null
  }
  return { hostname, guest_machine_id, mac: '', dir, kvm: true }
}

function containerComputer(dir) {
  const hostFile = path.join(dir, 'system', 'etc', 'hostname')
  const midFile = path.join(dir, 'system', 'etc', 'machine-id')
  const macFile = path.join(dir, 'system', 'hardware', 'mac')
  const dmi = path.join(dir, 'system', 'dmi', 'id')
  for (const file of [hostFile, midFile, macFile]) {
    try {
      if (!fs.statSync(file).isFile()) return null
    } catch {
      return null
    }
  }
  try {
    if (!fs.statSync(dmi).isDirectory()) return null
  } catch {
    return null
  }
  const hostname = readTrimmed(hostFile)
  const guest_machine_id = readTrimmed(midFile).toLowerCase()
  const mac = readTrimmed(macFile).toLowerCase()
  if (!HOSTNAME_RE.test(hostname) || !MACHINE_ID_RE.test(guest_machine_id) || !MAC_RE.test(mac)) return null
  return { hostname, guest_machine_id, mac, dir, kvm: false }
}

function runChecked(argv, timeout) {
  try {
    execFileSync(argv[0], argv.slice(1), {
      encoding: 'utf8',
      timeout,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  } catch (e) {
    const detail = String(e.stderr || e.stdout || e.message || e).trim()
    throw new Error(detail || 'vm-os computer identity failed')
  }
}

/** The DMI profile the closed binary published for this directory, if any. */
export function readPublishedProfile(dir) {
  const pc = readJson(path.join(dir, 'pc_identity.json'))
  if (!pc || typeof pc !== 'object') return null
  return {
    source_profile: typeof pc.source_profile === 'string' ? pc.source_profile : null,
    identity_source: typeof pc.identity_source === 'string' ? pc.identity_source : null,
  }
}

/**
 * Other slots that the binary gave the same hardware profile. It is a pure
 * function of vm-id inside a closed binary, so Node cannot re-roll it; the
 * profiles can only be reported. Two slots with the same profile differ in
 * hostname / machine-id / MAC but present the same model, CPU and DIMMs.
 */
export function duplicateProfileSlots(projectRoot, vmId) {
  const own = readPublishedProfile(fingerprintDir(projectRoot, vmId))
  if (!own?.source_profile) return []
  const out = []
  let entries = []
  try {
    entries = fs.readdirSync(path.join(projectRoot, 'vms'), { withFileTypes: true })
  } catch {
    return []
  }
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name === vmId) continue
    const other = readPublishedProfile(fingerprintDir(projectRoot, entry.name))
    if (other?.source_profile === own.source_profile) out.push(entry.name)
  }
  return out.sort()
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

/** Rewrite in place so the file keeps the mode the binary chose. */
function rewrite(file, text) {
  fs.writeFileSync(file, text, 'utf8')
}

function rewriteJson(file, doc) {
  rewrite(file, `${JSON.stringify(doc, null, 2)}\n`)
}

function rewriteIfExists(file, text) {
  if (fs.existsSync(file)) rewrite(file, text)
}

function randomMac() {
  const b = crypto.randomBytes(6)
  b[0] = (b[0] & 0xfe) | 0x02 // unicast, locally administered
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join(':')
}

function clampBase(value) {
  return hostnameSlug(value).slice(0, HOST_BASE_MAX).replace(/-+$/, '')
}

/** Board name, family and vendor the binary published, in fallback order. */
function dmiNames(dir, kvm) {
  if (kvm) {
    const doc = readJson(path.join(dir, 'identity.json')) || {}
    const hw = doc.hardware && typeof doc.hardware === 'object' ? doc.hardware : {}
    const type1 = (Array.isArray(doc.smbios) ? doc.smbios : []).find((line) => String(line).startsWith('type=1,'))
    const family = /(?:^|,)family=([^,]*)/.exec(String(type1 || ''))?.[1] || ''
    return [hw.board_id, family, hw.sys_vendor]
  }
  const id = path.join(dir, 'system', 'dmi', 'id')
  const read = (name) => {
    try {
      return fs.readFileSync(path.join(id, name), 'utf8').trim()
    } catch {
      return ''
    }
  }
  return [read('board_name'), read('product_family'), read('sys_vendor')]
}

/**
 * The model slug the binary put in front of its machine-id suffix. A DMI
 * placeholder (`system-product-name`) falls back to board / family / vendor,
 * then to the workstation family.
 */
function hostnameBase(dir, kvm, vm, current) {
  const tail = `-${current.guest_machine_id.slice(0, HOST_SUFFIX)}`
  const own = current.hostname.endsWith(tail)
    ? current.hostname.slice(0, -tail.length)
    : current.hostname.replace(/-[0-9a-f]{6}$/, '')
  for (const value of [own, ...dmiNames(dir, kvm)]) {
    const base = clampBase(value)
    if (base && !isPlaceholderHostname(base)) return base
  }
  return workstationFamily(vm)
}

/** The published SMBIOS list may carry a type=1 uuid; keep it on the minted one. */
function setSmbiosType1Uuid(doc, uuid) {
  if (!Array.isArray(doc.smbios)) return
  doc.smbios = doc.smbios.map((line) =>
    String(line).startsWith('type=1,') ? String(line).replace(/(^|,)uuid=[^,]*/, `$1uuid=${uuid}`) : line,
  )
}

function writeContainerIdentity(dir, { hostname, machineId, mac }) {
  const etc = path.join(dir, 'system', 'etc')
  const dmiUuid = path.join(dir, 'system', 'dmi', 'id', 'product_uuid')
  const pcPath = path.join(dir, 'pc_identity.json')
  const pc = readJson(pcPath)
  const hw = pc?.hardware && typeof pc.hardware === 'object' ? pc.hardware : null
  const oldUuid = [pc?.uuid, hw?.hardware_uuid, fs.existsSync(dmiUuid) ? fs.readFileSync(dmiUuid, 'utf8') : '']
    .map((v) => String(v || '').trim())
    .find(Boolean)
  // Redacted profiles publish no UUID; one the binary did publish is per vm-id, so re-roll it.
  const uuid = oldUuid ? crypto.randomUUID() : ''
  rewrite(path.join(etc, 'hostname'), `${hostname}\n`)
  rewrite(path.join(etc, 'machine-id'), `${machineId}\n`)
  rewrite(path.join(dir, 'system', 'hardware', 'mac'), `${mac}\n`)
  rewriteIfExists(path.join(dir, 'system', 'var', 'lib', 'dbus', 'machine-id'), `${machineId}\n`)
  if (uuid) rewriteIfExists(dmiUuid, `${uuid}\n`)
  const hostsPath = path.join(etc, 'hosts')
  if (fs.existsSync(hostsPath)) {
    const lines = fs.readFileSync(hostsPath, 'utf8').replace(/\n$/, '').split('\n')
    const self = `127.0.1.1 ${hostname}`
    const at = lines.findIndex((line) => /^127\.0\.1\.1\s/.test(line.trim()))
    if (at >= 0) lines[at] = self
    else lines.push(self)
    rewrite(hostsPath, `${lines.join('\n')}\n`)
  }
  const kcPath = path.join(etc, 'kin-computer')
  if (fs.existsSync(kcPath)) {
    const set = { hostname, machine_id: machineId, mac, ...(uuid ? { 'id/product_uuid': uuid } : {}) }
    const text = fs
      .readFileSync(kcPath, 'utf8')
      .split('\n')
      .map((line) => {
        const eq = line.indexOf('=')
        const key = eq > 0 ? line.slice(0, eq) : ''
        return Object.hasOwn(set, key) ? `${key}=${set[key]}` : line
      })
      .join('\n')
    rewrite(kcPath, text)
  }
  if (pc) {
    pc.hostname = hostname
    pc.machine_id = machineId
    if (uuid && pc.uuid) pc.uuid = uuid
    if (uuid) setSmbiosType1Uuid(pc, uuid)
    if (hw) {
      hw.en0_mac = mac
      if (uuid && hw.hardware_uuid) hw.hardware_uuid = uuid
    }
    rewriteJson(pcPath, pc)
  }
}

function writeLinuxIdentity(dir, { hostname, machineId }) {
  // SMBIOS type=1 UUID: the binary leaves it empty or derives it from vm-id; always re-roll.
  const uuid = crypto.randomUUID()
  const identPath = path.join(dir, 'identity.json')
  const doc = readJson(identPath)
  doc.hostname = hostname
  doc.machine_id = machineId
  doc.uuid = uuid
  if (doc.hardware && typeof doc.hardware === 'object') doc.hardware.hardware_uuid = uuid
  setSmbiosType1Uuid(doc, uuid)
  atomicWriteJson(identPath, doc, { mode: 0o600 })
  const hwPath = path.join(dir, 'hardware.json')
  const hw = readJson(hwPath)
  if (hw && typeof hw === 'object' && Object.hasOwn(hw, 'hardware_uuid')) {
    hw.hardware_uuid = uuid
    rewriteJson(hwPath, hw)
  }
  const smbiosPath = path.join(dir, 'qemu-smbios.args')
  rewrite(smbiosPath, patchQemuSmbiosArgsUuid(fs.readFileSync(smbiosPath, 'utf8'), uuid))
}

function writeIdentity(dir, kvm, { hostname, machineId, mac }) {
  if (kvm) writeLinuxIdentity(dir, { hostname, machineId })
  else writeContainerIdentity(dir, { hostname, machineId, mac })
  return kvm ? linuxComputer(dir) : containerComputer(dir)
}

/**
 * Fresh random unique fields for a directory the binary just wrote: machine-id,
 * `<model>-<machine-id[0:6]>` hostname, Docker MAC, SMBIOS UUID. The hardware
 * profile stays. A taken hostname or machine-id is re-rolled a bounded number of times.
 */
function mintComputer(dir, kvm, vm, current, taken) {
  const base = hostnameBase(dir, kvm, vm, current)
  let hostname = ''
  let machineId = ''
  let free = false
  for (let i = 0; i < MINT_ATTEMPTS && !free; i++) {
    machineId = crypto.randomBytes(16).toString('hex')
    hostname = `${base}-${machineId.slice(0, HOST_SUFFIX)}`
    free = !taken?.hostname?.has(hostname) && !taken?.guest_machine_id?.has(machineId)
  }
  if (!free) throw new Error('workstation fingerprint collision')
  const minted = writeIdentity(dir, kvm, { hostname, machineId, mac: randomMac() })
  if (!minted || minted.hostname !== hostname || isPlaceholderHostname(minted.hostname)) {
    throw new Error('computer identity mint failed')
  }
  return minted
}

/** The hostname / machine-id (and MAC) the slot record already carries, if it has a complete pair. */
function recordedComputer(vm) {
  const fp = vm?.fingerprint && typeof vm.fingerprint === 'object' ? vm.fingerprint : {}
  const hostname = String(fp.hostname || '').trim()
  const machineId = String(fp.guest_machine_id || '')
    .trim()
    .toLowerCase()
  if (!HOSTNAME_RE.test(hostname) || !MACHINE_ID_RE.test(machineId)) return null
  const mac = String(fp.hardware?.mac || '')
    .trim()
    .toLowerCase()
  return { hostname, machineId, mac: MAC_RE.test(mac) ? mac : '' }
}

/**
 * Read an existing computer. Create it once when the directory has no identity.
 * A valid directory is returned as is: no second binary run, no re-mint, no
 * rewrite, so an account that already signed in never sees its computer change.
 * The binary's own unique fields are never handed out: a rebuilt directory takes
 * the slot record's hostname / machine-id back, and only `mint` (constructors) or
 * a slot with no record gets fresh random ones.
 */
export function ensureSlotComputer(projectRoot, vm, { mint = false, taken } = {}) {
  if (!projectRoot || !vm?.id) throw new Error('projectRoot and vm id required')
  const kvm = isKvmRuntime(vm)
  const dir = fingerprintDir(projectRoot, vm.id)
  const ready = kvm ? linuxComputer(dir) : containerComputer(dir)
  if (ready) return { ...ready, created: false }
  if (kvm && fs.existsSync(dir)) {
    repairKvmFingerprintUuid(dir)
    const repaired = linuxComputer(dir)
    if (repaired) return { ...repaired, created: false }
  }
  const bin = computerBin()
  if (!fs.existsSync(bin)) {
    const missing = new Error('计算机服务未安装。放好 kin-computer 后可再次创建，已完成的身份不会重抽。')
    missing.code = 'computer_service_missing'
    throw missing
  }
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true })
  fs.mkdirSync(dir, { recursive: true })
  try {
    runChecked(
      [bin, 'create', '--runtime', kvm ? 'kvm' : 'docker', '--vm-id', vm.id, '--out', dir],
      kvm ? 120_000 : 180_000,
    )
  } catch (e) {
    fs.rmSync(dir, { recursive: true, force: true })
    const failed = new Error(`计算机身份创建失败，目录已清掉，可再次创建：${String(e.message || e).slice(0, 240)}`)
    failed.code = 'computer_create_failed'
    throw failed
  }
  if (kvm) repairKvmFingerprintUuid(dir)
  try {
    const written = kvm ? linuxComputer(dir) : containerComputer(dir)
    if (!written) throw new Error('computer identity incomplete')
    const recorded = mint ? null : recordedComputer(vm)
    const computer = recorded
      ? writeIdentity(dir, kvm, { ...recorded, mac: recorded.mac || randomMac() })
      : mintComputer(dir, kvm, vm, written, taken)
    if (!computer) throw new Error('computer identity incomplete')
    return { ...computer, created: true }
  } catch (e) {
    fs.rmSync(dir, { recursive: true, force: true })
    const incomplete = new Error(
      e.message === 'computer identity incomplete'
        ? '计算机身份不完整，目录已清掉，可再次创建。'
        : `计算机身份铸造失败，目录已清掉，可再次创建：${e.message}`,
    )
    incomplete.code = 'computer_create_failed'
    throw incomplete
  }
}

/**
 * Control-plane device_id plus the computer hostname and machine-id.
 * A computer this call creates is minted. An existing directory keeps its
 * computer: the guest's container was built with that hostname / MAC, so a new
 * computer comes from a fresh rebuild (which drops the directory first) or
 * `fresh`, for a new slot id that may find a deleted slot's leftover directory.
 */
export function assignComputerFingerprint(projectRoot, vm, { taken, now, fresh = false } = {}) {
  if (fresh && projectRoot && vm?.id) fs.rmSync(fingerprintDir(projectRoot, vm.id), { recursive: true, force: true })
  const computer = ensureSlotComputer(projectRoot, vm, { mint: true, taken })
  if (
    !computer.created &&
    (taken?.hostname?.has(computer.hostname) || taken?.guest_machine_id?.has(computer.guest_machine_id))
  ) {
    throw new Error('workstation fingerprint collision')
  }
  const generated = generateWorkstationFingerprint(vm, { taken, now })
  return {
    ...generated,
    hostname: computer.hostname,
    guest_machine_id: computer.guest_machine_id,
  }
}

/** Point the slot record at the computer. Does not touch device_id. */
export function rememberComputer(projectRoot, vm, computer) {
  if (!computer?.hostname || !vm?.id) return false
  const fp = vm.fingerprint && typeof vm.fingerprint === 'object' ? vm.fingerprint : {}
  const same =
    fp.hostname === computer.hostname &&
    String(fp.guest_machine_id || '')
      .trim()
      .toLowerCase() === computer.guest_machine_id
  if (same) return false
  vm.fingerprint = {
    ...fp,
    hostname: computer.hostname,
    guest_machine_id: computer.guest_machine_id,
  }
  const vmPath = path.join(projectRoot, 'vms', `${vm.id}.json`)
  if (!fs.existsSync(vmPath)) return true
  const disk = JSON.parse(fs.readFileSync(vmPath, 'utf8'))
  disk.fingerprint = {
    ...(disk.fingerprint && typeof disk.fingerprint === 'object' ? disk.fingerprint : {}),
    hostname: computer.hostname,
    guest_machine_id: computer.guest_machine_id,
  }
  disk.updated_at = new Date().toISOString()
  atomicWriteJson(vmPath, disk, { mode: 0o600 })
  return true
}
