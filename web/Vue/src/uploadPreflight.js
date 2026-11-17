export async function submitWithPreflight({ file, api, baseUrl, requestId, hashFile, signal, onPhase }) {
  onPhase('preparing')
  const sha256 = await hashFile(file, { signal, onProgress: percent => onPhase('preparing', percent) })
  onPhase('preflight')
  const preflight = await api.post(`${baseUrl}/detect/preflight`, {
    sha256, filename: file.name, file_size: file.size
  }, { headers: { 'X-Detection-ID': requestId }, signal, timeout: 20000 })
  if (preflight.data?.upload_required === false) return preflight
  if (preflight.data?.upload_required !== true || preflight.data.sha256 !== sha256) {
    throw new Error('服务器预查响应无效，原文件未上传，请稍后重试')
  }
  onPhase('uploading')
  const formData = new FormData()
  formData.append('file', file)
  return api.post(`${baseUrl}/detect`, formData, {
    headers: { 'X-Detection-ID': requestId, 'X-Expected-SHA256': sha256 }, signal
  })
}
