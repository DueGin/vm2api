/**
 * Exchange-time OAuth account identity.
 * Flatten helper/token shapes, then fill gaps from claude_cli/bootstrap.
 * This is part of ticket exchange, not official Claude Code first-run.
 */
import https from 'node:https'
import { makeProxyFetch } from '../protocol/codex-models.mjs'
import { OFFICIAL_CLI_VERSION, OFFICIAL_STAINLESS, officialClaudeCliUa } from '../identity/vm-identity.mjs'
import { BETA_OAUTH, BOOTSTRAP_URL } from './oauth-contract.mjs'

const IPV4_AGENT = new https.Agent({ family: 4, keepAlive: false })

export const CLAUDE_CLI_BOOTSTRAP_URL = BOOTSTRAP_URL

function firstText(...values) {
  for (const value of values) {
    const text = String(value || '').trim()
    if (text) return text
  }
  return null
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

const SUBSCRIPTION_TYPES = new Set(['pro', 'max', 'team', 'enterprise'])

export function normalizeSubscriptionType(value) {
  const key = String(value || '')
    .trim()
    .toLowerCase()
  return SUBSCRIPTION_TYPES.has(key) ? key : null
}

function subscriptionTypeFromText(text) {
  const blob = String(text || '').toLowerCase()
  if (!blob) return null
  if (/\b(claude[_\s-]*max|max\s*20x)\b/.test(blob)) return 'max'
  if (/\bclaude[_\s-]*enterprise\b/.test(blob)) return 'enterprise'
  if (/\bclaude[_\s-]*team\b/.test(blob)) return 'team'
  if (/\bclaude[_\s-]*pro\b/.test(blob)) return 'pro'
  return null
}

function planFromProfile(profile) {
  const account = profile?.account || {}
  const org = profile?.organization || {}
  if (account.has_claude_max === true) return 'max'
  const orgType = String(org.organization_type || profile.organization_type || '').toLowerCase()
  const rateTier = String(org.rate_limit_tier || '').toLowerCase()
  if (orgType === 'claude_max' || rateTier.includes('max')) return 'max'
  if (account.has_claude_pro === true || orgType === 'claude_pro' || rateTier.includes('pro')) return 'pro'
  if (orgType === 'claude_enterprise') return 'enterprise'
  if (orgType === 'claude_team') return 'team'
  return null
}

/** Plan from the exchange/bootstrap body. Explicit field, profile, then text. */
export function subscriptionTypeFromOauthRaw(raw) {
  if (raw == null) return null
  if (typeof raw === 'string') return subscriptionTypeFromText(raw)
  if (typeof raw !== 'object') return null
  const explicit = normalizeSubscriptionType(
    raw.subscriptionType || raw.subscription_type || raw.claudeAiOauth?.subscriptionType,
  )
  if (explicit) return explicit
  const profiles = [raw, raw.profile, raw.oauth_profile].filter((item) => item && typeof item === 'object')
  for (const profile of profiles) {
    const tier = planFromProfile(profile)
    if (tier) return tier
  }
  return subscriptionTypeFromText(JSON.stringify(raw))
}

export function flattenOauthIdentity(raw = {}) {
  const account = asObject(raw.account)
  const organization = asObject(raw.organization)
  const oauthAccount = asObject(raw.oauth_account)
  const profile = asObject(raw.profile)
  return {
    email: firstText(
      raw.email,
      raw.email_address,
      raw.emailAddress,
      account.email_address,
      account.email,
      oauthAccount.account_email,
      oauthAccount.email,
      profile.email,
    ),
    account_uuid: firstText(
      raw.account_uuid,
      raw.accountUuid,
      account.uuid,
      account.account_uuid,
      oauthAccount.account_uuid,
      profile.account_uuid,
    ),
    org_uuid: firstText(
      raw.org_uuid,
      raw.orgUuid,
      raw.organization_uuid,
      organization.uuid,
      organization.org_uuid,
      organization.organization_uuid,
      oauthAccount.organization_uuid,
      profile.organization_uuid,
    ),
    subscription_type: subscriptionTypeFromOauthRaw(raw),
  }
}

export function oauthIdentityComplete(identity = {}) {
  return !!(identity.email && identity.account_uuid && identity.org_uuid)
}

export function applyOauthIdentity(cred = {}, identity = {}) {
  const next = { ...cred }
  if (identity.email) {
    next.email = identity.email
    next.email_address = identity.email
  }
  if (identity.account_uuid) next.account_uuid = identity.account_uuid
  if (identity.org_uuid) next.org_uuid = identity.org_uuid
  if (identity.subscription_type) next.subscription_type = identity.subscription_type
  return next
}

/** The slot's CLI makes this call with its own UA; the entrypoint follows the panel switch. */
export function bootstrapRequestHeaders(accessToken, { entrypoint = 'cli' } = {}) {
  return {
    accept: 'application/json',
    authorization: `Bearer ${String(accessToken || '').trim()}`,
    'user-agent': officialClaudeCliUa(OFFICIAL_CLI_VERSION, entrypoint),
    'anthropic-beta': BETA_OAUTH,
    'anthropic-version': '2023-06-01',
    'x-stainless-lang': OFFICIAL_STAINLESS.stainless_lang,
    'x-stainless-os': OFFICIAL_STAINLESS.stainless_os,
    'x-stainless-arch': OFFICIAL_STAINLESS.stainless_arch,
    'x-stainless-runtime': OFFICIAL_STAINLESS.stainless_runtime,
    'x-stainless-runtime-version': OFFICIAL_STAINLESS.stainless_runtime_version,
    'x-stainless-package-version': OFFICIAL_STAINLESS.stainless_package_version,
  }
}

export async function fetchOauthBootstrapAccount({
  accessToken,
  proxyUrl = null,
  fetchImpl = null,
  timeoutMs = 15000,
  entrypoint = 'cli',
} = {}) {
  const token = String(accessToken || '').trim()
  if (!token) return { ok: false, reason: 'no_access_token' }
  if (proxyUrl == null && !fetchImpl) return { ok: false, reason: 'proxy_required' }
  const direct = !String(proxyUrl || '').trim()
  const baseFetch = fetchImpl || makeProxyFetch(proxyUrl, timeoutMs)
  // A local exit has no proxy URL. Slot networks are IPv4-only, so a direct
  // call must not leave over the host's IPv6 address.
  const fetchFn = direct && !fetchImpl ? (url, init = {}) => baseFetch(url, { ...init, agent: IPV4_AGENT }) : baseFetch
  try {
    const res = await fetchFn(CLAUDE_CLI_BOOTSTRAP_URL, {
      method: 'GET',
      headers: bootstrapRequestHeaders(token, { entrypoint }),
    })
    if (!res || typeof res.ok !== 'boolean') return { ok: false, reason: 'bootstrap_no_response' }
    if (!res.ok) return { ok: false, reason: `http_${res.status || 0}` }
    const body = typeof res.json === 'function' ? await res.json() : null
    const identity = flattenOauthIdentity(body || {})
    if (!identity.email && !identity.account_uuid && !identity.org_uuid) {
      return { ok: false, reason: 'empty_identity' }
    }
    return { ok: true, identity }
  } catch (err) {
    return { ok: false, reason: String(err?.message || err).slice(0, 180) }
  }
}

/** Flatten first. Only fetch bootstrap when email / account / org is still missing. */
export async function enrichOauthIdentity(cred, { proxyUrl = null, fetchImpl = null, entrypoint = 'cli' } = {}) {
  const fromCred = flattenOauthIdentity(cred)
  let next = applyOauthIdentity(cred, fromCred)
  if (oauthIdentityComplete(fromCred)) return next
  const access = next.access_token || next.accessToken
  if (!access) return next
  const fetched = await fetchOauthBootstrapAccount({
    accessToken: access,
    proxyUrl,
    fetchImpl,
    entrypoint,
  })
  if (!fetched.ok) return next
  return applyOauthIdentity(next, fetched.identity)
}
