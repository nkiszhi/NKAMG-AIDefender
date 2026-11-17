import test from 'node:test'
import assert from 'node:assert/strict'
import { analyzeLocalPe, mergeLocalFileInfo } from '../src/localPeInfo.js'

function makePe(bits = 32, dll = false) {
  const data = new Uint8Array(1024)
  const v = new DataView(data.buffer)
  data.set([0x4d, 0x5a]); v.setUint32(0x3c, 0x80, true); data.set([0x50, 0x45, 0, 0], 0x80)
  const optional = bits === 64 ? 240 : 224
  v.setUint16(0x84, bits === 64 ? 0x8664 : 0x14c, true)
  v.setUint16(0x86, 1, true); v.setUint16(0x94, optional, true)
  v.setUint16(0x96, dll ? 0x2002 : 2, true); v.setUint16(0x98, bits === 64 ? 0x20b : 0x10b, true)
  v.setUint32(0x98 + (bits === 64 ? 108 : 92), 16, true)
  v.setUint32(0x98 + 16, 0x1010, true)
  if (bits === 64) v.setBigUint64(0x98 + 24, 0x123456789abcdef0n, true)
  else v.setUint32(0x98 + 28, 0x400000, true)
  const section = 0x98 + optional
  data.set(new TextEncoder().encode('.text'), section)
  v.setUint32(section + 8, 0x200, true); v.setUint32(section + 12, 0x1000, true)
  v.setUint32(section + 16, 0x200, true); v.setUint32(section + 20, 0x200, true)
  return data
}

test('reads EXE/DLL 32/64-bit headers and sections without depending on extension', async () => {
  for (const bits of [32, 64]) for (const dll of [false, true]) {
    const info = await analyzeLocalPe(new Blob([makePe(bits, dll)]))
    assert.equal(info.is_pe, true)
    assert.equal(info.pe_type, `${dll ? 'dll' : 'exe'}${bits}`)
    assert.equal(info.entry_point, '0x1010')
    assert.equal(info.sections[0].name, '.text')
    assert.equal(info.sections[0].raw_pointer, '0x200')
    assert.equal(info.sections[0].raw_size, 512)
    assert.equal(info.image_base, bits === 64 ? '0x123456789ABCDEF0' : '0x400000')
  }
})

test('rejects truncated, magic-only, out-of-range and inconsistent headers', async () => {
  const cases = [new Uint8Array(0), new TextEncoder().encode('MZ'), makePe().slice(0, 1023), makePe().slice(0, 350)]
  for (const [offset, value, width] of [[0x3c, 0x20, 4], [0x3c, 0xfffffff0, 4], [0x94, 1, 2],
    [0x94, 70, 2], [0x98, 0, 2], [0x98 + 92, 17, 4]]) {
    const data = makePe(); const v = new DataView(data.buffer)
    width === 4 ? v.setUint32(offset, value, true) : v.setUint16(offset, value, true)
    cases.push(data)
  }
  for (const bytes of cases) assert.equal((await analyzeLocalPe(new Blob([bytes]))).is_pe, false)
})

test('accepts BSS sections and overlays; identifies ARM64 correctly', async () => {
  const bss = makePe(); const v = new DataView(bss.buffer)
  v.setUint32(0x98 + 224 + 16, 0, true); v.setUint32(0x98 + 224 + 20, 0, true)
  assert.equal((await analyzeLocalPe(new Blob([bss.slice(0, 512)]))).is_pe, true)
  assert.equal((await analyzeLocalPe(new Blob([makePe(), 'overlay']))).is_pe, true)
  const arm = makePe(64, true); new DataView(arm.buffer).setUint16(0x84, 0xaa64, true)
  assert.equal((await analyzeLocalPe(new Blob([arm]))).architecture, 'ARM64')
})

test('large-file display uses bounded header reads, not whole-file loading', async () => {
  const blob = new Blob([makePe()]); const reads = []
  const file = { size: 1024 ** 3, slice: (start, end) => { reads.push(end - start); return blob.slice(start, end) } }
  assert.equal((await analyzeLocalPe(file)).is_pe, true)
  assert.ok(reads.reduce((a, b) => a + b, 0) < 1024)
})

test('local PE info is merged only for the same hash and preserves database fingerprints/labels', () => {
  const result = { sha256: 'a'.repeat(64), file_uploaded: false, pe_structure_checked: false,
    sample_record: { labels: { Packer: 'UPX' }, hashes: { SSDeep: 'db-ssdeep', TLSH: 'db-tlsh' } } }
  const local = { sha256: result.sha256, md5: 'local-md5', filename: 'sample.exe', file_size: 1024, pe_info: { is_pe: true, pe_type: 'exe32', format: 'PE32', architecture: 'x86' } }
  const merged = mergeLocalFileInfo(result, local)
  assert.equal(merged.pe_structure_checked, true)
  assert.equal(merged.pe_info_source, 'local')
  assert.equal(merged.sample_record, result.sample_record)
  assert.equal(mergeLocalFileInfo(result, { ...local, sha256: 'b'.repeat(64) }), result)
  assert.equal(merged.md5, 'local-md5')
  assert.equal(mergeLocalFileInfo({ ...result, file_uploaded: true }, local).pe_structure_checked, true)
})
