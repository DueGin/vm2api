import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { prepareSlotOAuth, runGuestOAuthAuthService } from '../../src/lib/oauth/guest-oauth-helper.mjs'

const SOCKS = {
  id: 'px-socks',
  scheme: 'socks5',
  host: '203.0.113.20',
  port: 443,
  username: 'u',
  password: 'p',
  url: 'socks5://u:p@203.0.113.20:443',
}

function seed(t, kernel) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-oauth-egress-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  fs.mkdirSync(path.join(root, 'vms', 'vm-04', 'run'), { recursive: true })
  fs.writeFileSync(
    path.join(root, 'vms', 'vm-04.json'),
    JSON.stringify({ id: 'vm-04', runtime: { type: 'docker' }, proxy: SOCKS }),
  )
  fs.writeFileSync(
    path.join(root, 'vms', 'vm-04', 'run', 'kernel.json'),
    JSON.stringify({ credential_path: '/home/kincli/.claude/credentials.json', ...kernel }),
  )
  return { vmId: 'vm-04', projectRoot: root }
}

const ready = async () => ({
  ok: true,
  rust_ok: true,
  rust: { ok: true, engine: 'rust', rust: { ok: true, health: { vm_telemetry: true, telemetry_ready: true } } },
})

async function guestPayload(exec) {
  let stdin = ''
  await runGuestOAuthAuthService(
    { operation: 'exchange_code', code: 'c', code_verifier: 'v', proxy_url: 'socks5h://controller-loopback:1' },
    {
      exec,
      projectRoot: exec.projectRoot,
      prepare: (options) => prepareSlotOAuth({ ...options, startReady: ready }),
      postTelemetry: async () => ({ ok: true }),
      runDocker: async (_argv, opts) => {
        stdin = opts.stdin
        return {
          code: 0,
          stdout: `${JSON.stringify({ ok: true, credential: { access_token: 'sk-ant-oat01-x' } })}\n`,
        }
      },
    },
  )
  return JSON.parse(stdin)
}

// On the transparent egress network the guest must not dial the SOCKS itself:
// that dial is forwarded through the same proxy and dropped ("Socket closed").
test('a slot on transparent egress gives the guest helper no proxy, like its kernel', async (t) => {
  const exec = seed(t, { proxy_url: '', proxy_required: false })
  const prepared = await prepareSlotOAuth({ exec: { ...exec }, startReady: ready })
  assert.equal(prepared.guestProxyUrl, '')
  const payload = await guestPayload(exec)
  assert.equal(payload.proxy_url, '')
})

test('the controller proxy URL never reaches the guest; an old kernel.json keeps the bound exit', async (t) => {
  const payload = await guestPayload(seed(t, {}))
  assert.notEqual(payload.proxy_url, 'socks5h://controller-loopback:1')
  assert.match(payload.proxy_url, /203\.0\.113\.20:443/)
})
