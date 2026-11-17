import { hashBlob } from './fileHashCore.js'

self.onmessage = async ({ data: file }) => {
  try {
    const sha256 = await hashBlob(file, percent => self.postMessage({ percent }))
    self.postMessage({ sha256 })
  } catch {
    self.postMessage({ error: '本机SHA256计算失败，原文件未上传，请重新选择文件' })
  }
}
