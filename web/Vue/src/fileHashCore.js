import { createSHA256, createMD5 } from 'hash-wasm'

// A bounded working buffer also permits files larger than browser ArrayBuffer limits.
export async function fileFingerprints(file, onProgress = () => {}) {
  const hasher = await createSHA256()
  const md5 = await createMD5()
  hasher.init()
  md5.init()
  const chunkSize = 2 * 1024 * 1024
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, file.size)
    const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer())
    hasher.update(chunk)
    md5.update(chunk)
    onProgress(Math.round(end / file.size * 100))
  }
  return { sha256: hasher.digest('hex'), md5: md5.digest('hex') }
}

export async function hashBlob(file, onProgress) {
  return (await fileFingerprints(file, onProgress)).sha256
}
