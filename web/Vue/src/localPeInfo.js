const hex = (value, width = 0) => `0x${value.toString(16).toUpperCase().padStart(width, '0')}`
const machines = { 0x14c: 'Intel 386 / x86', 0x8664: 'x64', 0x1c0: 'ARM', 0x1c4: 'ARMv7', 0xaa64: 'ARM64', 0x200: 'Intel Itanium' }
const subsystems = { 1: 'Native', 2: 'Windows GUI', 3: 'Windows Console', 5: 'OS/2 Console', 7: 'POSIX Console',
  9: 'Windows CE GUI', 10: 'EFI Application', 11: 'EFI Boot Service Driver', 12: 'EFI Runtime Driver',
  13: 'EFI ROM', 14: 'Xbox', 16: 'Windows Boot Application' }

// Read only bounded header ranges. Raw section bytes are never needed for display.
export async function analyzeLocalPe(file) {
  const read = async (start, size) => new Uint8Array(await file.slice(start, start + size).arrayBuffer())
  const invalid = reason => ({ is_pe: false, reason })
  const dos = await read(0, 64)
  if (dos[0] !== 0x4d || dos[1] !== 0x5a) return invalid('缺少MZ头')
  if (dos.length < 64) return invalid('DOS文件头不完整')
  const peOffset = new DataView(dos.buffer, dos.byteOffset, dos.byteLength).getUint32(0x3c, true)
  if (peOffset < 64 || peOffset + 24 > file.size) return invalid('PE头偏移无效')
  const coff = await read(peOffset, 24)
  if (coff[0] !== 0x50 || coff[1] !== 0x45 || coff[2] !== 0 || coff[3] !== 0) return invalid('缺少PE签名')
  const view = new DataView(coff.buffer, coff.byteOffset, coff.byteLength)
  const machine = view.getUint16(4, true)
  const count = view.getUint16(6, true)
  const timestamp = view.getUint32(8, true)
  const optionalSize = view.getUint16(20, true)
  const characteristics = view.getUint16(22, true)
  const optionalOffset = peOffset + 24
  if (optionalSize < 2) return invalid('可选头不完整')
  if (optionalOffset + optionalSize > file.size) return invalid('可选头超出文件范围')
  const optional = await read(optionalOffset, optionalSize)
  const opt = new DataView(optional.buffer, optional.byteOffset, optional.byteLength)
  const magic = opt.getUint16(0, true)
  if (magic !== 0x10b && magic !== 0x20b) return invalid('可选头Magic不是PE32/PE32+')
  const bits = magic === 0x20b ? 64 : 32
  const fixedSize = bits === 64 ? 112 : 96
  if (optionalSize < fixedSize) return invalid('可选头长度不足')
  if (fixedSize + opt.getUint32(fixedSize - 4, true) * 8 > optionalSize) return invalid('数据目录数量超出可选头范围')
  const sectionOffset = optionalOffset + optionalSize
  if (sectionOffset + count * 40 > file.size) return invalid('节表不完整或超出文件范围')
  const table = await read(sectionOffset, count * 40)
  const sections = []
  const decoder = new TextDecoder('utf-8')
  for (let i = 0; i < count; i++) {
    const offset = i * 40
    const sec = new DataView(table.buffer, table.byteOffset + offset, 40)
    const rawSize = sec.getUint32(16, true)
    const rawPointer = sec.getUint32(20, true)
    if (rawSize && rawPointer + rawSize > file.size) return invalid(`第${i + 1}节原始数据超出文件范围`)
    const rawName = table.subarray(offset, offset + 8)
    const zero = rawName.indexOf(0)
    sections.push({ name: decoder.decode(rawName.subarray(0, zero < 0 ? 8 : zero)),
      virtual_size: sec.getUint32(8, true), virtual_address: hex(sec.getUint32(12, true)),
      raw_size: rawSize, raw_pointer: hex(rawPointer), characteristics: hex(sec.getUint32(36, true), 8) })
  }
  const subsystem = opt.getUint16(68, true)
  const dll = Boolean(characteristics & 0x2000)
  return { is_pe: true, bits, is_dll: dll, pe_type: `${dll ? 'dll' : 'exe'}${bits}`,
    format: bits === 64 ? 'PE32+' : 'PE32', machine: hex(machine, 4),
    architecture: machines[machine] || `Unknown (${hex(machine, 4)})`,
    number_of_sections: count, compile_time: timestamp ? new Date(timestamp * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC') : '',
    characteristics: hex(characteristics, 4), entry_point: hex(opt.getUint32(16, true)),
    image_base: hex(bits === 64 ? opt.getBigUint64(24, true) : opt.getUint32(28, true)),
    subsystem: subsystems[subsystem] || `Unknown (${subsystem})`, size_of_image: opt.getUint32(56, true),
    size_of_headers: opt.getUint32(60, true), sections }
}

export function mergeLocalFileInfo(result, local) {
  if (!local || result.sha256?.toLowerCase() !== local.sha256) return result
  return { ...result, filename: local.filename, file_size: local.file_size, md5: local.md5,
    is_pe: result.file_uploaded === false ? local.pe_info.is_pe : result.is_pe,
    pe_info: local.pe_info, pe_structure_checked: true, pe_info_source: 'local',
    file_type: local.pe_info.is_pe ? `${local.pe_info.pe_type} (${local.pe_info.format}, ${local.pe_info.architecture})` : '非有效PE文件' }
}
