import { createSHA256 } from 'hash-wasm'

// A bounded working buffer also permits files larger than browser ArrayBuffer limits.
export async function hashBlob(file, onProgress = () => {}) {
  const hasher = await createSHA256()
  hasher.init()
  const chunkSize = 2 * 1024 * 1024
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, file.size)
    hasher.update(new Uint8Array(await file.slice(offset, end).arrayBuffer()))
    onProgress(Math.round(end / file.size * 100))
  }
  return hasher.digest('hex')
}
