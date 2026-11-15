import test from 'node:test'
import assert from 'node:assert/strict'
import { failedModelResults, serviceStatus } from '../src/detectionFailure.js'

test('failed analysis retains observations without a final ensemble or false Benign', () => {
  const result = failedModelResults([
    { model: 'A', status: 'ok', score: 0.7, prediction: 1 },
    { model: 'B', status: 'ok', score: 0.2, prediction: 0 },
    { model: 'C', status: 'running' }, { model: 'D', status: 'waiting' }
  ])
  assert.equal(result.A.result, 'Malicious')
  assert.equal(result.B.result, 'Benign')
  assert.equal(result.C.result, '未完成')
  assert.equal(result.D.probability, null)
  assert.equal(result['集成结果'], undefined)
})

test('header exposes recovery, paused dispatch and reduced capacity', () => {
  assert.match(serviceStatus({ready: true, model_count:33, ready_workers:1, total_workers:2}), /1\/2/)
  assert.equal(serviceStatus({ready: true, dispatch_paused:true, queue_message:'内存不足'}), '内存不足')
})
