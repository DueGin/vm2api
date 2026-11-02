import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  claudeJsonPaths,
  findSlotHoldingAccount,
  previousSlotAccount,
  readSlotUserId,
  rotatedFingerprint,
  sameAccount,
  seedSlotUserId,
  writeSlotUserId,
} from '../../src/lib/identity/slot-device-identity.mjs'
import { createImportCommit } from '../../src/lib/oauth/import-commit.mjs'
import { loadVmIdentity } from '../../src/lib/identity/vm-identity.mjs'

const A = 'aa'.repeat(32)
const B = 'bb'.repeat(32)

function tmpRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-devid-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return root
}

function home(root, id = 'vm-01') {
  const dir = path.join(root, 'vms', id, 'cli-home')
  fs.mkdirSync(path.join(dir, '.claude'), { recursive: true })
  return dir
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

function writeVm(root, rec) {
  const file = path.join(root, 'vms', `${rec.id}.json`)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, JSON.stringify(rec, null, 2))
  return file
}

test('the CLI config file is the CLAUDE_CONFIG_DIR one; home-level is only a leftover', (t) => {
  const dir = home(tmpRoot(t))
  const [own, leftover] = claudeJsonPaths(dir)
  assert.equal(own, path.join(dir, '.claude', '.claude.json'))
  assert.equal(leftover, path.join(dir, '.claude.json'))

  writeSlotUserId(dir, A)
  assert.equal(readJson(own).userID, A)
  // Never created: no reader should find a second copy that could go stale.
  assert.equal(fs.existsSync(leftover), false)

  fs.writeFileSync(leftover, JSON.stringify({ userID: B, theme: 'light' }))
  writeSlotUserId(dir, A)
  assert.equal(readJson(leftover).userID, A, 'an existing leftover is kept in step')
  assert.equal(readJson(leftover).theme, 'light')
  assert.equal(readSlotUserId(dir), A)
})

test('reset drops the previous user and keeps onboarding state', (t) => {
  const dir = home(tmpRoot(t))
  const [own] = claudeJsonPaths(dir)
  fs.writeFileSync(
    own,
    JSON.stringify({
      userID: A,
      machineID: 'legacy',
      oauthAccount: { accountUuid: 'acc-old', emailAddress: 'old@example.com' },
      projects: { '/home/kincli': { history: ['secret'] } },
      hasCompletedOnboarding: true,
      theme: 'dark',
    }),
  )
  writeSlotUserId(dir, B, { reset: true })
  assert.deepEqual(readJson(own), { hasCompletedOnboarding: true, theme: 'dark', userID: B })
})

test('seed only fills an empty slot and never replaces the CLI id', (t) => {
  const dir = home(tmpRoot(t))
  assert.equal(seedSlotUserId(dir, 'not-hex').seeded, false)
  assert.equal(seedSlotUserId(dir, A).seeded, true)
  assert.equal(readSlotUserId(dir), A)
  assert.equal(seedSlotUserId(dir, B).seeded, false)
  assert.equal(readSlotUserId(dir), A)
})

test('outbound identity follows the seeded id before and after the CLI runs', (t) => {
  const dir = home(tmpRoot(t))
  seedSlotUserId(dir, A)
  const id = loadVmIdentity({ vmId: 'vm-01', homeDir: dir, vm: { fingerprint: { device_id: A } } })
  assert.equal(id.deviceId, A)
  assert.equal(JSON.parse(id.metadataUserId).device_id, A)
})

test('symlinked config dir is not written through', (t) => {
  const root = tmpRoot(t)
  const dir = path.join(root, 'cli-home')
  const elsewhere = path.join(root, 'elsewhere')
  fs.mkdirSync(dir, { recursive: true })
  fs.mkdirSync(elsewhere)
  fs.symlinkSync(elsewhere, path.join(dir, '.claude'))
  writeSlotUserId(dir, A)
  assert.equal(fs.existsSync(path.join(elsewhere, '.claude.json')), false)
})

test('accounts compare by uuid, then email; unknown is not "different"', () => {
  assert.equal(sameAccount({ account_uuid: 'X' }, { account_uuid: 'x' }), true)
  assert.equal(sameAccount({ account_uuid: 'x' }, { account_uuid: 'y' }), false)
  assert.equal(sameAccount({ email: 'A@b.c' }, { email: 'a@b.c' }), true)
  assert.equal(sameAccount({ email: 'a@b.c' }, {}), null)
  assert.equal(sameAccount({}, {}), null)
})

test('previous account survives a credential clear and falls back to the CLI record', (t) => {
  const dir = home(tmpRoot(t))
  assert.deepEqual(previousSlotAccount({ claude: { email: 'live@x.io' } }, dir), {
    account_uuid: '',
    email: 'live@x.io',
  })
  assert.equal(
    previousSlotAccount({ claude: {}, fingerprint: { departed_account: { account_uuid: 'gone' } } }, dir).account_uuid,
    'gone',
  )
  fs.writeFileSync(
    path.join(dir, '.claude', '.claude.json'),
    JSON.stringify({ userID: A, oauthAccount: { accountUuid: 'cli-acc' } }),
  )
  assert.equal(previousSlotAccount({ claude: {} }, dir).account_uuid, 'cli-acc')
})

test('findSlotHoldingAccount skips the slot itself and Codex slots', (t) => {
  const root = tmpRoot(t)
  writeVm(root, { id: 'vm-01', claude: { account_uuid: 'acc-1', email: 'one@x.io' } })
  writeVm(root, { id: 'vm-02', platform: 'openai', family: 'codex', claude: { email: 'two@x.io' } })
  assert.deepEqual(findSlotHoldingAccount(root, { email: 'ONE@x.io' }), { vm_id: 'vm-01', by: 'email' })
  assert.deepEqual(findSlotHoldingAccount(root, { account_uuid: 'acc-1' }), { vm_id: 'vm-01', by: 'account_uuid' })
  assert.equal(findSlotHoldingAccount(root, { account_uuid: 'acc-1' }, { exceptId: 'vm-01' }), null)
  assert.equal(findSlotHoldingAccount(root, { email: 'two@x.io' }), null)
  assert.equal(findSlotHoldingAccount(root, {}), null)
})

test('rotation keeps the computer and drops the previous user identity', () => {
  const next = rotatedFingerprint(
    {
      device_id: A,
      session_id: 's-old',
      hostname: 'box-1',
      guest_machine_id: 'f'.repeat(32),
      official_user_id: A,
      official_account_uuid: 'acc-old',
      identity_source: 'official-cc-init',
      departed_account: { email: 'old@x.io' },
    },
    { deviceId: B },
  )
  assert.equal(next.device_id, B)
  assert.notEqual(next.session_id, 's-old')
  assert.equal(next.hostname, 'box-1')
  assert.equal(next.guest_machine_id, 'f'.repeat(32))
  for (const key of ['official_user_id', 'official_account_uuid', 'identity_source', 'departed_account']) {
    assert.equal(next[key], undefined, key)
  }
})

function importCommit(root) {
  return createImportCommit({
    cfg: { paths: { project: root } },
    proxyPool: { getProxyForVm: () => null },
    accountQuota: { rebindToVm() {}, clearGrantRevokeLeftover() {} },
    importWorkerCredential: async () => ({ ok: true }),
  })
}

async function withMock(fn) {
  const prev = process.env.KIN_CRS_MOCK
  process.env.KIN_CRS_MOCK = '1'
  try {
    return await fn()
  } finally {
    if (prev === undefined) delete process.env.KIN_CRS_MOCK
    else process.env.KIN_CRS_MOCK = prev
  }
}

const GRANT = (extra = {}) => ({
  access_token: 'sk-ant-oat01-T',
  refresh_token: 'sk-ant-ort01-T',
  expires_at: Math.floor(Date.now() / 1000) + 3600,
  ...extra,
})

test('import refuses an account another slot holds unless sharing is explicit', async (t) => {
  const root = tmpRoot(t)
  writeVm(root, { id: 'vm-01', claude: { account_uuid: 'acc-1', email: 'one@x.io' } })
  const vmPath = writeVm(root, { id: 'vm-02', fingerprint: { device_id: B } })
  home(root, 'vm-02')
  const { commitImportedOauth } = importCommit(root)
  const refused = await withMock(() =>
    commitImportedOauth({
      vmId: 'vm-02',
      vmPath,
      existing: readJson(vmPath),
      oauth: GRANT({ email: 'one@x.io', account_uuid: 'acc-1' }),
      skipOfficialCc: true,
    }),
  )
  assert.equal(refused.ok, false)
  assert.equal(refused.status, 409)
  assert.equal(refused.error.code, 'account_bound_elsewhere')
  assert.equal(refused.error.vm_id, 'vm-01')
  assert.equal(fs.existsSync(path.join(root, 'vms', 'vm-02', 'cli-home', '.claude', 'credentials.json')), false)

  const shared = await withMock(() =>
    commitImportedOauth({
      vmId: 'vm-02',
      vmPath,
      existing: readJson(vmPath),
      oauth: GRANT({ email: 'one@x.io', account_uuid: 'acc-1' }),
      skipOfficialCc: true,
      allowSharedAccount: true,
    }),
  )
  assert.equal(shared.ok, true, shared.error?.message)
})

test('a different account on a used slot gets a new device id and a fresh CLI config', async (t) => {
  const root = tmpRoot(t)
  const dir = home(root, 'vm-01')
  const own = path.join(dir, '.claude', '.claude.json')
  fs.writeFileSync(
    own,
    JSON.stringify({ userID: A, oauthAccount: { accountUuid: 'acc-old' }, hasCompletedOnboarding: true }),
  )
  fs.mkdirSync(path.join(dir, '.claude', 'projects', 'p'), { recursive: true })
  const vmPath = writeVm(root, {
    id: 'vm-01',
    claude: {},
    fingerprint: {
      device_id: A,
      hostname: 'box-1',
      official_user_id: A,
      departed_account: { account_uuid: 'acc-old' },
    },
  })
  const { commitImportedOauth } = importCommit(root)
  const result = await withMock(() =>
    commitImportedOauth({
      vmId: 'vm-01',
      vmPath,
      existing: readJson(vmPath),
      oauth: GRANT({ email: 'new@x.io', account_uuid: 'acc-new' }),
      skipOfficialCc: true,
    }),
  )
  assert.equal(result.ok, true, result.error?.message)
  assert.equal(result.device_identity.rotated, true)
  const fp = readJson(vmPath).fingerprint
  assert.notEqual(fp.device_id, A)
  assert.match(fp.device_id, /^[0-9a-f]{64}$/)
  assert.equal(fp.hostname, 'box-1')
  assert.equal(fp.departed_account, undefined)
  const cli = readJson(own)
  assert.equal(cli.userID, fp.device_id, 'the CLI and the slot record carry one device id')
  assert.equal(cli.oauthAccount, undefined)
  assert.equal(cli.hasCompletedOnboarding, true)
  assert.equal(fs.existsSync(path.join(dir, '.claude', 'projects')), false)
  const saved = readJson(vmPath)
  // The stub worker writes no credentials.json; the slot record carries the account.
  const identity = loadVmIdentity({ vmId: 'vm-01', homeDir: dir, vm: saved, oauth: saved.claude })
  assert.equal(identity.deviceId, fp.device_id)
  assert.equal(identity.accountUuid, 'acc-new')
})

test('the same account re-imported keeps its device id', async (t) => {
  const root = tmpRoot(t)
  const dir = home(root, 'vm-01')
  fs.writeFileSync(path.join(dir, '.claude', '.claude.json'), JSON.stringify({ userID: A }))
  const vmPath = writeVm(root, {
    id: 'vm-01',
    claude: { account_uuid: 'acc-1', email: 'one@x.io' },
    fingerprint: { device_id: A },
  })
  const { commitImportedOauth } = importCommit(root)
  const result = await withMock(() =>
    commitImportedOauth({
      vmId: 'vm-01',
      vmPath,
      existing: readJson(vmPath),
      oauth: GRANT({ email: 'ONE@x.io' }),
      skipOfficialCc: true,
    }),
  )
  assert.equal(result.ok, true, result.error?.message)
  assert.equal(result.device_identity.rotated, false)
  assert.equal(readJson(vmPath).fingerprint.device_id, A)
  // Same account proven by email: its uuid carries over.
  assert.equal(readJson(vmPath).claude.account_uuid, 'acc-1')
})

test('an unidentified grant never inherits the previous account uuid', async (t) => {
  const root = tmpRoot(t)
  home(root, 'vm-01')
  const vmPath = writeVm(root, {
    id: 'vm-01',
    claude: { account_uuid: 'acc-old', email: 'old@x.io' },
    fingerprint: { device_id: A },
  })
  const { importedCredentialFromOauth } = importCommit(root)
  const cred = importedCredentialFromOauth(GRANT(), readJson(vmPath))
  assert.equal(cred.account_uuid, null)
  assert.equal(cred.email, null)
})
