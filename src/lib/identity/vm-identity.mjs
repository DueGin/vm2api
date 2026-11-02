/**
 * VM slot identity for official Messages hop.
 * Client settings/metadata are discarded; the scheduled VM is the only source.
 */
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { atomicWriteJson, writeJsonIfChanged } from '../vm/vm-file.mjs'
import { readSlotCredentialIdentity } from '../oauth/oauth-credentials.mjs'
import { buildSlotSettingsEnv } from '../protocol/seed-policy.mjs'
import { buildKinSeedJson } from './workstation-profile.mjs'
import { isHexDeviceId } from './workstation-fingerprint.mjs'

export function readJsonSafe(p, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'))
  } catch {
    return fallback
  }
}

/** Official Claude Code version shared by Node identity and the slot CLI wire. */
export const OFFICIAL_CLI_VERSION = '2.1.303'
/** Shipped cc_entrypoint is `cli` (see ccEntrypointFromRouting); the default UA matches it. */
export const OFFICIAL_CLAUDE_CLI_UA = `claude-cli/${OFFICIAL_CLI_VERSION} (external, cli)`
export const OFFICIAL_STAINLESS = Object.freeze({
  stainless_lang: 'js',
  stainless_os: 'Linux',
  stainless_arch: 'x64',
  stainless_runtime: 'node',
  stainless_runtime_version: 'v26.3.0',
  stainless_package_version: '0.128.0',
})

export function officialClaudeCliUa(version = OFFICIAL_CLI_VERSION, entrypoint = 'cli') {
  const m = String(version || '').match(/(\d+\.\d+\.\d+)/)
  return `claude-cli/${m ? m[1] : OFFICIAL_CLI_VERSION} (external, ${entrypoint === 'cli' ? 'cli' : 'sdk-cli'})`
}

/** Panel cc_entrypoint switch. Only an explicit `sdk-cli` leaves the shipped `cli` default. */
export function slotEntrypoint(routing) {
  return routing?.compatibility?.cc_entrypoint === 'sdk-cli' ? 'sdk-cli' : 'cli'
}

/**
 * Non-auth headers of a first-party API call made by the slot's CLI. Anything
 * the control plane sends for a slot account uses these, so the account never
 * shows a UA / client the CLI itself would not send.
 */
export function officialCliApiHeaders({ entrypoint = 'cli', version = OFFICIAL_CLI_VERSION } = {}) {
  return {
    'user-agent': officialClaudeCliUa(version, entrypoint),
    'x-app': 'cli',
    'x-stainless-lang': OFFICIAL_STAINLESS.stainless_lang,
    'x-stainless-os': OFFICIAL_STAINLESS.stainless_os,
    'x-stainless-arch': OFFICIAL_STAINLESS.stainless_arch,
    'x-stainless-runtime': OFFICIAL_STAINLESS.stainless_runtime,
    'x-stainless-runtime-version': OFFICIAL_STAINLESS.stainless_runtime_version,
    'x-stainless-package-version': OFFICIAL_STAINLESS.stainless_package_version,
    'x-stainless-retry-count': '0',
    'x-stainless-timeout': '600',
  }
}

export function formatMetadataUserId({ deviceId, accountUuid, sessionId }) {
  // Official Messages user_id is device/account/session only.
  // A literal email (@) makes Anthropic 400 (has_at). Slot email belongs
  // on the telemetry sidecar, not this JSON.
  return JSON.stringify({
    device_id: deviceId || '',
    account_uuid: accountUuid || '',
    session_id: sessionId || '',
  })
}

function sha256Hex(s) {
  return crypto
    .createHash('sha256')
    .update(String(s || ''))
    .digest('hex')
}

/** 64-hex (generated or official machineID) goes out as-is. Legacy UUID stays hashed. */
export function outboundDeviceId(raw, fallback = 'kin-vm') {
  const s = String(raw || '').trim()
  if (isHexDeviceId(s)) return s
  return sha256Hex(s || fallback)
}

export function loadVmIdentity(exec = {}) {
  const home = exec.homeDir || ''
  const claudeDir = path.join(home, '.claude')
  const settings = readJsonSafe(path.join(claudeDir, 'settings.json'), {}) || {}
  const homeClaude = readJsonSafe(path.join(home, '.claude.json'), {}) || {}
  const dirClaude = readJsonSafe(path.join(claudeDir, '.claude.json'), {}) || {}
  const claudeJson = { ...dirClaude, ...homeClaude }
  const fp = exec.vm?.fingerprint || {}
  const oauth = exec.oauth || {}
  const seed = exec.seedPolicy || {}

  const timezone = fp.timezone || exec.timezone || 'UTC'
  const locale = fp.locale || exec.locale || 'en_US.UTF-8'
  // The CLI's install userID is what it sends as device_id on its own
  // requests and 1P events, so metadata.user_id carries the same value.
  // A new account gets a new userID (import rotates it), so this is never a
  // previous account's id. Before the CLI has one, the slot fingerprint
  // (seeded into .claude.json at start) stands in. A legacy machineID is never used.
  // Slots run the CLI with CLAUDE_CONFIG_DIR=~/.claude: the nested file is its own.
  const cliUserId = isHexDeviceId(dirClaude.userID)
    ? String(dirClaude.userID).toLowerCase()
    : isHexDeviceId(homeClaude.userID)
      ? String(homeClaude.userID).toLowerCase()
      : ''
  const deviceId = cliUserId || outboundDeviceId(fp.device_id, exec.vmId || 'kin-vm')
  const sessionId = fp.session_id || crypto.randomUUID()
  const slotCred = readSlotCredentialIdentity(home)
  // Slot worker credentials.json is the only credential location.
  // Do not take account identity from leftover .claude.json / client inbound.
  const accountUuid = slotCred?.account_uuid || oauth.account_uuid || ''
  const orgUuid = slotCred?.org_uuid || oauth.org_uuid || ''
  // Credential email only — never leftover ~/.claude.json or inbound caller.
  const email = slotCred?.email || oauth.email || null
  // Slot leftover (2.1.233 / 2.1.234) must not leak into outbound UA or billing.
  const cliVersion = OFFICIAL_CLI_VERSION
  const userAgent = OFFICIAL_CLAUDE_CLI_UA

  // Do not merge leftover settings.env — old scripts (kill-switch /
  // ANTHROPIC_BASE_URL) would win over the current seed contract.
  const env = buildSlotSettingsEnv(seed, {
    timezone,
    locale,
    extra: seed.settings_json_override?.env,
  })

  const settingsOut = {
    ...(seed.settings_json_override && typeof seed.settings_json_override === 'object'
      ? seed.settings_json_override
      : {}),
    env,
    theme: seed.theme || settings.theme || 'dark',
    autoUpdates: false,
    grove_enabled: false,
  }

  return {
    vmId: exec.vmId || null,
    cliVersion,
    timezone,
    locale,
    kernel: fp.kernel_release || exec.kernel || null,
    email,
    accountUuid,
    orgUuid,
    deviceId,
    sessionId,
    machineId: deviceId,
    userId: claudeJson.userID || null,
    displayName: claudeJson.oauthAccount?.displayName || null,
    settings: settingsOut,
    metadataUserId: formatMetadataUserId({ deviceId, accountUuid, sessionId }),
    userAgent,
    fingerprint: {
      device_id: cliUserId || fp.device_id || deviceId,
      session_id: sessionId,
      user_agent: userAgent,
      ...OFFICIAL_STAINLESS,
      x_app: 'cli',
      locale,
      timezone,
      os_pretty: fp.os_pretty || exec.osPretty || null,
      kernel_release: fp.kernel_release || exec.kernel || null,
    },
  }
}

export function persistVmSettings(exec, identity) {
  if (!exec?.homeDir || !identity) return { wrote: false }
  const claudeDir = path.join(exec.homeDir, '.claude')
  fs.mkdirSync(claudeDir, { recursive: true })
  // Only settings.json affects CLI behavior — skip rewrite when unchanged (T7).
  const wrote = writeJsonIfChanged(path.join(claudeDir, 'settings.json'), identity.settings)
  // Descriptive sidecars carry timestamps; write atomically only when settings changed
  // to avoid per-request churn.
  if (wrote) {
    atomicWriteJson(path.join(claudeDir, 'kin-identity.json'), {
      vm_id: identity.vmId,
      cli_version: identity.cliVersion,
      timezone: identity.timezone,
      locale: identity.locale,
      kernel: identity.kernel,
      account_uuid: identity.accountUuid,
      org_uuid: identity.orgUuid,
      device_id: identity.deviceId,
      session_id: identity.sessionId,
      written_at: new Date().toISOString(),
    })
    atomicWriteJson(
      path.join(claudeDir, 'kin-seed.json'),
      buildKinSeedJson(
        {
          id: identity.vmId,
          kernel: exec.vm?.kernel || null,
          timezone: identity.timezone,
          locale: identity.locale,
          fingerprint: exec.vm?.fingerprint || identity.fingerprint,
        },
        exec.seedPolicy || {},
        {
          cli_version: identity.cliVersion,
          timezone: identity.timezone,
          locale: identity.locale,
        },
      ),
    )
  }
  return { wrote }
}

/** Persist fingerprint onto vm.json only. Never touches oauth tokens. */
export function persistVmFingerprint(exec, identity) {
  if (!exec?.vmPath || !identity?.fingerprint) return { wrote: false }
  let vm
  try {
    vm = JSON.parse(fs.readFileSync(exec.vmPath, 'utf8'))
  } catch {
    return { wrote: false }
  }
  const prev = vm.fingerprint && typeof vm.fingerprint === 'object' ? vm.fingerprint : {}
  const merged = {
    ...prev,
    ...identity.fingerprint,
    device_id: prev.device_id || identity.fingerprint.device_id,
    session_id: prev.session_id || identity.fingerprint.session_id,
    reset_at: prev.reset_at || new Date().toISOString(),
  }
  // Write-only-on-change (T7): compare ignoring the volatile updated_at stamp so
  // steady-state requests don't rewrite vm.json every call.
  const { updated_at: _prevStamp, ...prevCmp } = prev
  const versionChanged = identity.cliVersion && vm.claude_code_version !== identity.cliVersion
  const changed = JSON.stringify(prevCmp) !== JSON.stringify(merged)
  if (!changed && !versionChanged) {
    if (exec.vm) exec.vm.fingerprint = prev
    return { wrote: false }
  }
  merged.updated_at = new Date().toISOString()
  vm.fingerprint = merged
  if (identity.cliVersion) vm.claude_code_version = identity.cliVersion
  atomicWriteJson(exec.vmPath, vm)
  if (exec.vm) {
    exec.vm.fingerprint = vm.fingerprint
    if (identity.cliVersion) exec.vm.claude_code_version = identity.cliVersion
  }
  return { wrote: true }
}
