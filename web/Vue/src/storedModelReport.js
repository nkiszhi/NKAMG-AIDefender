export function hasStoredModelReport(result) {
  return Boolean(result?.database_hit && result?.stored_model_report?.available)
}

export function initialReportSection(result) {
  if (hasStoredModelReport(result)) return 'modelDetection'
  return result?.is_pe && !result.database_hit ? 'modelDetection' : 'fileInfo'
}
