/**
 * Bound slots follow a moved exit.
 *
 * ProxyPool re-reads the location of bound rows (`geo_refresh_min`) and emits
 * `geo-change` when the exit IP or zone moved. Each bound slot re-syncs its
 * zone from the fresh location (a pinned zone stays, see proxy-timezone.mjs)
 * and a changed zone goes straight into the slot's kernel config, the same hot
 * path the panel uses when the operator edits a zone.
 */
import { writeKernelConfig } from '../transport/rust-kernel-supervisor.mjs'
import { syncVmTimezoneFromProxy } from './proxy-timezone.mjs'
import { getVm } from './vm-registry.mjs'
import { isCodexVm } from './vm-kind.mjs'

export async function followExitGeoChange(
  change,
  { projectRoot, proxyPool, getRouting = () => ({}), writeKernel = writeKernelConfig, log = console } = {},
) {
  const from = change?.from || {}
  const to = change?.to || {}
  if (from.ip && to.ip && from.ip !== to.ip) {
    // The exit itself moved: the accounts on it now come from a new address.
    log.warn?.(
      JSON.stringify({
        event: 'proxy-exit-ip-changed',
        proxy_id: change.proxy_id,
        from_ip: from.ip,
        to_ip: to.ip,
        from_timezone: from.timezone || null,
        to_timezone: to.timezone || null,
        vm_ids: change.bound_vm_ids || [],
      }),
    )
  }
  const results = []
  for (const vmId of change?.bound_vm_ids || []) {
    const synced = await syncVmTimezoneFromProxy(projectRoot, proxyPool, vmId, {
      proxyId: change.proxy_id,
      detect: false,
    })
    let kernelHot = false
    if (synced.applied) {
      const vm = getVm(projectRoot, vmId)
      if (vm && !isCodexVm(vm)) {
        try {
          kernelHot = writeKernel(projectRoot, vm, { routing: getRouting(), timezone: vm.timezone })?.changed === true
        } catch {}
      }
    }
    results.push({ vm_id: vmId, ...synced, kernel_hot: kernelHot })
  }
  return results
}

export function followExitGeoChanges(deps) {
  const onChange = (change) => {
    followExitGeoChange(change, deps).catch((err) => {
      deps?.log?.warn?.(`[proxy-geo] follow failed for ${change?.proxy_id}: ${err?.message || err}`)
    })
  }
  deps.proxyPool.on('geo-change', onChange)
  return () => deps.proxyPool.off('geo-change', onChange)
}
