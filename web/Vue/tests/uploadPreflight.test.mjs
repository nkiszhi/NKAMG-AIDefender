import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { File } from 'node:buffer'
import { hashBlob, fileFingerprints } from '../src/fileHashCore.js'
import { submitWithPreflight } from '../src/uploadPreflight.js'

const sha256 = 'a'.repeat(64)
const file = new File(['test'], 'sample.exe')
const options = api => ({ file, api, baseUrl: '/api', requestId: 'b'.repeat(32),
  hashFile: async () => sha256, onPhase: () => {} })

test('hashes empty and multi-chunk binary blobs identically to Node crypto', async () => {
  for (const bytes of [Buffer.alloc(0), Buffer.from('abc'), Buffer.alloc(5*1024*1024+33, 0xa5)]) {
    const expected = createHash('sha256').update(bytes).digest('hex')
    assert.equal(await hashBlob(new Blob([bytes])), expected)
    const fingerprints = await fileFingerprints(new Blob([bytes]))
    assert.equal(fingerprints.sha256, expected)
    assert.equal(fingerprints.md5, createHash('md5').update(bytes).digest('hex'))
  }
})

test('hit sends JSON only, never the original file', async () => {
  const calls = []
  const api = { post: async (...args) => { calls.push(args); return { data: { upload_required: false, status: 'completed' } } } }
  await submitWithPreflight(options(api))
  assert.equal(calls.length, 1)
  assert.equal(calls[0][0], '/api/detect/preflight')
  assert.deepEqual(calls[0][1], { sha256, filename: file.name, file_size: file.size })
  assert.equal(calls[0][1] instanceof FormData, false)
})

test('miss uploads once with the same request ID and expected hash', async () => {
  const calls = []
  const api = { post: async (...args) => { calls.push(args); return { data: calls.length === 1
    ? { upload_required: true, sha256 } : { status: 'queued' } } } }
  await submitWithPreflight(options(api))
  assert.equal(calls.length, 2)
  assert.equal(calls[1][0], '/api/detect')
  assert.equal(calls[1][1] instanceof FormData, true)
  assert.equal(calls[0][2].headers['X-Detection-ID'], calls[1][2].headers['X-Detection-ID'])
  assert.equal(calls[1][2].headers['X-Expected-SHA256'], sha256)
})

test('lookup outage or invalid response never falls back to uploading', async () => {
  for (const fail of [true, false]) {
    let calls = 0
    const api = { post: async () => { calls++; if (fail) throw new Error('offline'); return { data: {} } } }
    await assert.rejects(submitWithPreflight(options(api)))
    assert.equal(calls, 1)
  }
})

test('local hashing failure makes no server request', async () => {
  let calls = 0
  const args = options({ post: async () => { calls++ } })
  args.hashFile = async () => { throw new Error('hash failure') }
  await assert.rejects(submitWithPreflight(args))
  assert.equal(calls, 0)
})
