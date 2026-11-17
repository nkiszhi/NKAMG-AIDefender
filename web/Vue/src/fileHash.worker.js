import { fileFingerprints } from './fileHashCore.js'
import { analyzeLocalPe } from './localPeInfo.js'

self.onmessage = async ({ data: file }) => {
  try {
    const fingerprints = await fileFingerprints(file, percent => self.postMessage({ percent }))
    const pe_info = await analyzeLocalPe(file)
    self.postMessage({ ...fingerprints, pe_info, filename: file.name, file_size: file.size })
  } catch {
    self.postMessage({ error: '文件读取失败，请重新选择文件' })
  }
}
