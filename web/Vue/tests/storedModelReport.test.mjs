import test from 'node:test'
import assert from 'node:assert/strict'
import { hasStoredModelReport, initialReportSection } from '../src/storedModelReport.js'

test('hash-only membership keeps file information without inventing model report', () => {
  const result = { database_hit: true, hash_search: true, stored_model_report: { available: false } }
  assert.equal(hasStoredModelReport(result), false)
  assert.equal(initialReportSection(result), 'fileInfo')
})
test('saved results are visible for both SHA searches and browser preflight hits', () => {
  for (const hash_search of [true, false]) {
    const result = { database_hit: true, hash_search, stored_model_report: { available: true } }
    assert.equal(hasStoredModelReport(result), true)
    assert.equal(initialReportSection(result), 'modelDetection')
  }
})
test('ordinary PE model report and non-PE failure retain initial sections', () => {
  assert.equal(initialReportSection({ is_pe: true, database_hit: false }), 'modelDetection')
  assert.equal(initialReportSection({ is_pe: false, database_hit: false }), 'fileInfo')
  assert.equal(hasStoredModelReport({ database_hit: false, stored_model_report: { available: true } }), false)
})
