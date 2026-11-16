// Upload transport cleanup only. Never cancel accepted model tasks here.
function isUpload(req) {
  return req?.method === 'POST' && /^\/(?:api-backend\/)?(?:api\/v1\/detect|detect)(?:\?|$)/.test(req.url || '')
}

export function configureUploadProxy(proxy, { logger = console } = {}) {
  proxy.on('proxyReq', (upstream, req, res) => {
    if (!isUpload(req)) return
    const rawId = req.headers?.['x-detection-id']
    const taskId = typeof rawId === 'string' && /^[a-f0-9]{32}$/.test(rawId) ? rawId : '-'
    const started = Date.now()
    let aborted = false
    const log = (event, extra = {}) => logger.info('[upload-proxy]', JSON.stringify({
      event, task_id: taskId, expected_bytes: req.headers?.['content-length'] || null,
      body_complete: req.complete === true, elapsed_ms: Date.now() - started, ...extra
    }))
    const abortIncomplete = reason => {
      // IncomingMessage 'close' also fires for a normally completed request.
      if (req.complete || aborted) return
      aborted = true
      log('upstream_upload_aborted', { reason })
      if (!upstream.destroyed) upstream.destroy()
    }
    const onAbort = () => abortIncomplete('client_aborted')
    const onClose = () => abortIncomplete('client_request_closed')
    const onError = error => abortIncomplete(error.code || 'client_request_error')
    const onResponseClose = () => abortIncomplete('client_response_closed')
    const onEnd = () => log('upload_body_received')
    const cleanup = () => {
      req.removeListener('aborted', onAbort)
      req.removeListener('close', onClose)
      req.removeListener('error', onError)
      req.removeListener('end', onEnd)
      res.removeListener('close', onResponseClose)
    }
    req.once('aborted', onAbort)
    req.once('close', onClose)
    req.once('error', onError)
    req.once('end', onEnd)
    res.once('close', onResponseClose)
    upstream.once('close', cleanup)
    log('upload_forward_started')
    if (req.aborted || (req.destroyed && !req.complete)) onAbort()
  })
  proxy.on('error', (error, req) => {
    if (isUpload(req)) logger.warn('[upload-proxy] upload transport error', error.code || error.name)
  })
}
