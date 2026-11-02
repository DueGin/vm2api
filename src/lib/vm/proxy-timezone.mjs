/**
 * "Slot follows its proxy" timezone default.
 *
 * Binding an exit node in Tokyo while the slot still claims America/Los_Angeles
 * is a fingerprint contradiction the upstream can see (`# Environment - Timezone`
 * vs the exit IP). After every bind the slot adopts the proxy's detected zone,
 * unless the operator pinned one by hand (`vm.timezone_source === 'manual'`).
 */
import { validTimezone } from '../core/timezone.mjs'
import { isLocalEgressProxy, localEgressIdForNode } from './egress.mjs'
import { slotHost } from './slot-host.mjs'
import { getVm, patchVmRecord, persistVmTimezone } from './vm-registry.mjs'

/**
 * `vm.exit_timezone` records whether the slot's zone matches its current exit:
 *   aligned   zone follows the exit's detected location
 *   unknown   the exit's location could not be read; the slot stays out of the
 *             pool (evaluateSlotGate) rather than answer with a zone the exit IP
 *             contradicts
 *   pinned    the operator set the zone by hand
 *   unmanaged follow_proxy_timezone is off
 */
export const EXIT_TIMEZONE_UNKNOWN = 'exit_timezone_unknown'

/** Not a failure to read the exit: the operator decided the zone. */
const OPERATOR_REASONS = Object.freeze({
  timezone_pinned: 'pinned',
  follow_proxy_timezone_disabled: 'unmanaged',
})

/** No slot to record on. */
const NO_SLOT_REASONS = new Set(['vm_id_required', 'vm_not_found'])

export function recordExitTimezone(projectRoot, vmId, record) {
  return patchVmRecord(projectRoot, vmId, (vm) => {
    vm.exit_timezone = { ...record, checked_at: new Date().toISOString() }
    return vm
  })
}

function recordSyncResult(projectRoot, vmId, proxyId, result) {
  if (NO_SLOT_REASONS.has(result.reason)) return
  if (result.ok) {
    recordExitTimezone(projectRoot, vmId, { status: 'aligned', timezone: result.timezone, proxy_id: proxyId || null })
    return
  }
  const operator = OPERATOR_REASONS[result.reason]
  if (operator) {
    recordExitTimezone(projectRoot, vmId, { status: operator, proxy_id: proxyId || null })
    return
  }
  recordExitTimezone(projectRoot, vmId, { status: 'unknown', reason: result.reason, proxy_id: proxyId || null })
}

/**
 * @param {object} opts
 * @param {boolean} opts.force  apply even over a manually pinned timezone
 * @param {boolean} opts.detect run a geo lookup when the proxy has no location yet
 * @returns {Promise<{ok: boolean, applied: boolean, timezone: string|null, reason: string|null}>}
 */
export async function syncVmTimezoneFromProxy(
  projectRoot,
  proxyPool,
  vmId,
  { force = false, detect = true, proxyId = null, persist = true } = {},
) {
  const result = await resolveVmTimezoneFromProxy(projectRoot, proxyPool, vmId, { force, detect, proxyId, persist })
  if (persist) {
    const bound = proxyId || getVm(projectRoot, String(vmId || '').trim())?.proxy?.id || null
    recordSyncResult(projectRoot, String(vmId || '').trim(), bound, result)
  }
  return result
}

async function resolveVmTimezoneFromProxy(projectRoot, proxyPool, vmId, { force, detect, proxyId, persist }) {
  const id = String(vmId || '').trim()
  if (!id || !proxyPool) return skip('vm_id_required')
  if (!force && !proxyPool.followProxyTimezoneEnabled()) return skip('follow_proxy_timezone_disabled')
  const vm = getVm(projectRoot, id)
  if (!vm) return skip('vm_not_found')
  if (!force && vm.timezone_source === 'manual') return skip('timezone_pinned')

  const bound = proxyId || vm.proxy?.id || null
  const boundRow = vm.proxy?.id === bound ? vm.proxy : { id: bound }
  const host = slotHost(vm)
  let timezone = ''
  const nodeRow = host.nodeId ? localEgressIdForNode(host.nodeId) : null
  if (bound && nodeRow && isLocalEgressProxy(boundRow) && proxyPool.getProxyByIdWithAuth?.(nodeRow)) {
    // The slot leaves from its own node: that VPS's local row carries its geo.
    timezone = proxyPool.proxyTimezone(nodeRow)
    if (!timezone && detect) {
      const detected = await proxyPool.detectGeo(nodeRow)
      if (!detected?.ok) return skip(detected?.error || 'geo_lookup_failed')
      timezone = validTimezone(detected.geo?.timezone)
    }
  } else if (bound && host.nodeId && isLocalEgressProxy(boundRow)) {
    // No node row (local egress never seeded): ask the node's route directly.
    let url
    try {
      url = host.localExitProxyUrl(vm)
    } catch (err) {
      return skip(err?.code || 'node_egress_unavailable')
    }
    const exit = await proxyPool.exitGeo(`node:${host.nodeId}`, url, { detect })
    if (!exit.ok) return skip(exit.error)
    timezone = validTimezone(exit.geo?.timezone)
  } else {
    timezone = bound ? proxyPool.proxyTimezone(bound) : proxyPool.timezoneForVm(id)
    if (!timezone && detect && bound) {
      const detected = await proxyPool.detectGeo(bound)
      if (!detected?.ok) return skip(detected?.error || 'geo_lookup_failed')
      timezone = validTimezone(detected.geo?.timezone)
    }
  }
  if (!timezone) return skip('proxy_timezone_unknown')
  if (vm.timezone === timezone) {
    // Already aligned, but re-stamp the source so the panel stops showing the
    // zone as hand-pinned once the operator opted back into following.
    if (persist && force && vm.timezone_source !== 'proxy_geo') {
      persistVmTimezone(projectRoot, id, timezone, { source: 'proxy_geo' })
    }
    return { ok: true, applied: false, timezone, reason: 'already_current' }
  }
  if (!persist) return { ok: true, applied: true, timezone, reason: null }
  const summary = persistVmTimezone(projectRoot, id, timezone, { source: 'proxy_geo' })
  if (!summary) return skip('persist_failed')
  return { ok: true, applied: true, timezone, reason: null }
}

/** A slot without a zone takes its exit's; a set zone (manual or already synced) stays. */
export async function fillVmTimezoneFromExit(projectRoot, proxyPool, vmId) {
  const vm = getVm(projectRoot, vmId)
  if (!vm?.proxy?.id || validTimezone(vm.timezone)) return null
  return syncVmTimezoneFromProxy(projectRoot, proxyPool, vmId, { force: true })
}

function skip(reason) {
  return { ok: false, applied: false, timezone: null, reason }
}
