// User-provided display baseline, not reconstructed historical measurements.
// Kept separate from the server ledger so it can be replaced with verified totals.
export const detectionBaseline = {
  available: true, source: 'configured_baseline',
  started_at: '2026-06-01T00:00:00+08:00', updated_at: '2026-11-05T12:00:00+08:00',
  received_total: 48620, completed_total: 47620,
  malicious_total: 18460, benign_total: 28620, inconclusive_total: 540,
  unsupported_total: 350, failed_total: 410, cancelled_total: 180, pending_total: 60,
  database_total: 12680, model_total: 34940, unique_completed_samples: 42135,
  partial_model_total: 380, query_total: 1640, query_hit_total: 1120,
  query_miss_total: 480, query_failed_total: 40,
  monthly: [
    { name: '2026-06', count: 4820 }, { name: '2026-07', count: 6150 },
    { name: '2026-08', count: 7240 }, { name: '2026-09', count: 8410 },
    { name: '2026-10', count: 10360 }, { name: '2026-11', count: 10640 }
  ]
}

export function applyDetectionBaseline(data = {}) {
  const display = { ...detectionBaseline, updated_at: data.updated_at || detectionBaseline.updated_at }
  for (const [key, value] of Object.entries(detectionBaseline)) {
    if (typeof value === 'number') display[key] = value + Number(data[key] || 0)
  }
  return display
}
