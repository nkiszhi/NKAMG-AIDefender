export function hashFile(file, { signal, onProgress } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException('Aborted', 'AbortError'))
    const worker = new Worker(new URL('./fileHash.worker.js', import.meta.url), { type: 'module' })
    const close = () => {
      worker.terminate()
      signal?.removeEventListener('abort', abort)
    }
    const abort = () => {
      close()
      reject(new DOMException('Aborted', 'AbortError'))
    }
    signal?.addEventListener('abort', abort, { once: true })
    worker.onerror = () => {
      close()
      reject(new Error('无法启动本机哈希计算，原文件未上传，请换用新版浏览器重试'))
    }
    worker.onmessage = ({ data }) => {
      if (data.sha256) { close(); resolve(data.sha256) }
      else if (data.error) { close(); reject(new Error(data.error)) }
      else onProgress?.(data.percent)
    }
    worker.postMessage(file)
  })
}
