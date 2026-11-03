import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { duplicateProfileMap } from '../../src/lib/admin/panel-api.mjs'
import { duplicateProfileSlots, readPublishedProfile } from '../../src/lib/identity/slot-computer.mjs'

const LENOVO = 'Mini Pc/Lenovo/ThinkCentre/ThinkCentre M720q 10T8SJ9900/135DBB4F3AC1'
const ASUS = 'Windows_WMI/ASUS_ROG_Strix_B550_Ryzen5600X'

function project(t, profiles) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-hwprof-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  for (const [id, profile] of Object.entries(profiles)) {
    const dir = path.join(root, 'vms', id, 'kvm', 'fingerprint')
    fs.mkdirSync(dir, { recursive: true })
    if (profile != null) {
      fs.writeFileSync(
        path.join(dir, 'pc_identity.json'),
        JSON.stringify({ vm_id: id, identity_source: 'bsdhw-dmi-published', source_profile: profile }),
      )
    }
  }
  return root
}

test('slots the binary gave one DMI profile are reported to each other', (t) => {
  const root = project(t, { 'vm-04': LENOVO, 'vm-05': LENOVO, 'vm-06': LENOVO, 'vm-07': ASUS, 'vm-08': null })
  const vms = ['vm-04', 'vm-05', 'vm-06', 'vm-07', 'vm-08'].map((id) => ({ id }))
  const map = duplicateProfileMap(root, vms)
  assert.deepEqual(map['vm-04'], ['vm-05', 'vm-06'])
  assert.deepEqual(map['vm-05'], ['vm-04', 'vm-06'])
  assert.deepEqual(map['vm-06'], ['vm-04', 'vm-05'])
  // A unique profile, or a slot with no computer yet, is not in the map.
  assert.equal(map['vm-07'], undefined)
  assert.equal(map['vm-08'], undefined)

  assert.deepEqual(duplicateProfileSlots(root, 'vm-05'), ['vm-04', 'vm-06'])
  assert.deepEqual(duplicateProfileSlots(root, 'vm-07'), [])
  assert.deepEqual(duplicateProfileSlots(root, 'vm-08'), [])
  assert.equal(readPublishedProfile(path.join(root, 'vms', 'vm-07', 'kvm', 'fingerprint')).source_profile, ASUS)
})

test('a missing project or unreadable identity reports nothing instead of throwing', (t) => {
  const root = project(t, { 'vm-01': LENOVO })
  fs.writeFileSync(path.join(root, 'vms', 'vm-01', 'kvm', 'fingerprint', 'pc_identity.json'), '{not json')
  assert.deepEqual(duplicateProfileMap(root, [{ id: 'vm-01' }, { id: 'vm-02' }]), {})
  assert.deepEqual(duplicateProfileMap(path.join(root, 'nope'), [{ id: 'vm-01' }]), {})
  assert.deepEqual(duplicateProfileSlots(path.join(root, 'nope'), 'vm-01'), [])
})
