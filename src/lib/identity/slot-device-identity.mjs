/**
 * One device id per slot account.
 *
 * Every first-party request and 1P event the official CLI sends carries the
 * install `userID` from its `.claude.json` as the device id. The control
 * plane's `fingerprint.device_id` is only right when it is that same value,
 * so a slot keeps exactly one: seed the CLI with the slot's id before it mints
 * its own, and follow the CLI's id once it exists.
 *
 * A different account on the same slot is a different user of the computer.
 * It gets a new device id and a fresh `.claude.json`, never the previous
 * account's userID / oauthAccount / project history.
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { listVmRecordFiles, readJsonCached } from '../vm/vm-file.mjs'
import { isCodexVm } from '../vm/vm-kind.mjs'
import { readOfficialCcIdentity } from './official-fingerprint.mjs'

const HEX64 = /^[0-9a-f]{64}$/

/** Kept when an account leaves: onboarding / UI state only, nothing that names a user or a project. */
export const CLAUDE_JSON_KEEP_ON_ACCOUNT_CHANGE = Object.freeze([
  'hasCompletedOnboarding',
  'lastOnboardingVersion',
  'theme',
  'autoUpdates',
  'installMethod',
])

/**
 * Every slot runtime (Docker, KVM, node, the init run) starts the CLI with
 * CLAUDE_CONFIG_DIR=/home/kincli/.claude, so the CLI's own file is the nested
 * one. A home-level ~/.claude.json is a leftover from older inits: kept in
 * step when present, never created.
 */
export function claudeJsonPaths(homeDir) {
  return [path.join(homeDir, '.claude', '.claude.json'), path.join(homeDir, '.claude.json')]
}

export function normalizeDeviceId(value) {
  const id = String(value || '')
    .trim()
    .toLowerCase()
  return HEX64.test(id) ? id : ''
}

export function newDeviceId() {
  return crypto.randomBytes(32).toString('hex')
}

function readDoc(file) {
  try {
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'))
    return doc && typeof doc === 'object' && !Array.isArray(doc) ? doc : null
  } catch {
    return null
  }
}

function isSymlink(p) {
  try {
    return fs.lstatSync(p).isSymbolicLink()
  } catch {
    return false
  }
}

/** The CLI's install id, or '' before the CLI (or the seed) has written one. */
export function readSlotUserId(homeDir) {
  if (!homeDir) return ''
  for (const file of claudeJsonPaths(homeDir)) {
    const id = normalizeDeviceId(readDoc(file)?.userID)
    if (id) return id
  }
  return ''
}

function writeDoc(file, doc, { uid, gid } = {}) {
  const dir = path.dirname(file)
  fs.mkdirSync(dir, { recursive: true })
  const tmp = path.join(dir, `.${path.basename(file)}.${crypto.randomBytes(6).toString('hex')}.tmp`)
  try {
    fs.writeFileSync(tmp, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600 })
    if (uid != null && gid != null) {
      try {
        fs.chownSync(tmp, uid, gid)
      } catch {}
    }
    // rename replaces a planted symlink instead of writing through it.
    fs.renameSync(tmp, file)
  } catch (error) {
    try {
      fs.rmSync(tmp, { force: true })
    } catch {}
    throw error
  }
}

/**
 * Make `id` the CLI's install id in its config file (and in a leftover
 * home-level copy, so no reader finds a stale id). `reset` drops everything
 * that belongs to the previous user (oauthAccount, legacy machineID, projects,
 * caches); otherwise only userID changes.
 */
export function writeSlotUserId(homeDir, id, { reset = false, uid, gid } = {}) {
  const userId = normalizeDeviceId(id)
  if (!homeDir || !userId) return { wrote: false, files: [] }
  if (isSymlink(homeDir)) return { wrote: false, files: [], reason: 'home_symlink' }
  const files = []
  const [authoritative] = claudeJsonPaths(homeDir)
  for (const file of claudeJsonPaths(homeDir)) {
    if (isSymlink(path.dirname(file))) continue
    const prev = readDoc(file)
    if (!prev && file !== authoritative) continue
    let next
    if (reset) {
      next = {}
      for (const key of CLAUDE_JSON_KEEP_ON_ACCOUNT_CHANGE) {
        if (prev && Object.hasOwn(prev, key)) next[key] = prev[key]
      }
    } else {
      next = { ...(prev || {}) }
    }
    next.userID = userId
    if (prev && JSON.stringify(prev) === JSON.stringify(next)) continue
    writeDoc(file, next, { uid, gid })
    files.push(file)
  }
  return { wrote: files.length > 0, files }
}

/**
 * Before the CLI has minted an install id, give it the slot's, so the first
 * request already carries the same device id as the slot record. Never
 * replaces an id the CLI already has.
 */
export function seedSlotUserId(homeDir, deviceId, ids = {}) {
  if (!homeDir) return { seeded: false, reason: 'no_home' }
  if (readSlotUserId(homeDir)) return { seeded: false, reason: 'cli_has_user_id' }
  const id = normalizeDeviceId(deviceId)
  if (!id) return { seeded: false, reason: 'no_slot_device_id' }
  return { seeded: writeSlotUserId(homeDir, id, ids).wrote }
}

/** Comparable account identity. */
export function accountIdentity(src = {}) {
  const s = src && typeof src === 'object' ? src : {}
  return {
    account_uuid: String(s.account_uuid || s.accountUuid || '')
      .trim()
      .toLowerCase(),
    email: String(s.email || s.email_address || s.emailAddress || '')
      .trim()
      .toLowerCase(),
  }
}

export function hasAccountIdentity(src = {}) {
  const id = accountIdentity(src)
  return !!(id.account_uuid || id.email)
}

/** true / false when both sides name an account; null when either side is unknown. */
export function sameAccount(a, b) {
  const x = accountIdentity(a)
  const y = accountIdentity(b)
  if (x.account_uuid && y.account_uuid) return x.account_uuid === y.account_uuid
  if (x.email && y.email) return x.email === y.email
  return null
}

/**
 * The account this slot's device id was last used with: the slot record, then
 * the account a credential clear recorded, then the CLI's own oauthAccount.
 */
export function previousSlotAccount(vm = {}, homeDir = '') {
  const claude = vm?.claude && typeof vm.claude === 'object' ? vm.claude : {}
  if (hasAccountIdentity(claude)) return accountIdentity(claude)
  const departed = vm?.fingerprint?.departed_account
  if (hasAccountIdentity(departed)) return accountIdentity(departed)
  if (homeDir) {
    const official = readOfficialCcIdentity(homeDir)
    if (hasAccountIdentity(official)) return accountIdentity(official)
  }
  const fp = vm?.fingerprint || {}
  if (fp.official_account_uuid) return accountIdentity({ account_uuid: fp.official_account_uuid })
  return accountIdentity({})
}

/**
 * Another Claude slot that already holds this account. One account on two
 * slots shows up as two computers (and usually two exits) at the same time.
 */
export function findSlotHoldingAccount(projectRoot, identity, { exceptId = null } = {}) {
  if (!projectRoot || !hasAccountIdentity(identity)) return null
  const dir = path.join(projectRoot, 'vms')
  for (const name of listVmRecordFiles(dir)) {
    let vm
    try {
      vm = readJsonCached(path.join(dir, name))
    } catch {
      continue
    }
    if (!vm?.id || vm.id === exceptId || isCodexVm(vm)) continue
    const claude = vm.claude && typeof vm.claude === 'object' ? vm.claude : {}
    if (sameAccount(identity, claude) !== true) continue
    const want = accountIdentity(identity)
    const have = accountIdentity(claude)
    return {
      vm_id: vm.id,
      by: want.account_uuid && have.account_uuid ? 'account_uuid' : 'email',
    }
  }
  return null
}

export function accountBoundElsewhereError(holder) {
  return {
    type: 'conflict',
    code: 'account_bound_elsewhere',
    message: `该账号已在槽位 ${holder.vm_id} 上（按 ${holder.by} 判断）。同一账号挂两个槽会以两台电脑同时出现；请先清除原槽凭证再导入，确需共享时传 allow_shared_account: true。`,
    vm_id: holder.vm_id,
  }
}

/** Fingerprint fields that describe the previous user's install, not the computer. */
const ACCOUNT_SCOPED_FP_KEYS = Object.freeze([
  'official_machine_id',
  'official_user_id',
  'official_account_uuid',
  'identity_source',
  'reconciled_at',
  'departed_account',
])

/** New device id + session for a new user of the same computer. Hostname / machine-id / MAC stay. */
export function rotatedFingerprint(prev = {}, { deviceId = newDeviceId(), now = new Date().toISOString() } = {}) {
  const next = { ...(prev && typeof prev === 'object' ? prev : {}) }
  for (const key of ACCOUNT_SCOPED_FP_KEYS) delete next[key]
  next.device_id = deviceId
  next.session_id = crypto.randomUUID()
  next.reset_at = now
  next.updated_at = now
  return next
}
