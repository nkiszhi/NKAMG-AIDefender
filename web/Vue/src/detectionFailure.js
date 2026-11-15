// Retain valid partial observations without manufacturing a final verdict.
export function failedModelResults(models = []) {
  return Object.fromEntries(models.map(item => [item.model, {
    probability: item.status === 'ok' ? item.score : null,
    result: item.status === 'ok' ? (item.prediction === 1 ? 'Malicious' : 'Benign') : '未完成',
    reason: item.status === 'ok' ? (item.reason || '') : '分析已中止，未取得有效结果'
  }]))
}

export function serviceStatus(service) {
  if (service.dispatch_paused) return service.queue_message || '模型服务恢复中，暂停派发'
  if (!service.ready) return service.connected ? '模型服务未就绪' : '模型服务未连接'
  return `模型服务已连接 · ${service.model_count} 个模型 · 可用节点 ${service.ready_workers ?? 1}/${service.total_workers ?? 1}`
}
