import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import http from 'node:http'
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { configureUploadProxy } from '../uploadProxy.js'

const logger = { info() {}, warn() {} }

function fixture(complete = false) {
  const proxy = new EventEmitter()
  const req = Object.assign(new EventEmitter(), {
    method: 'POST', url: '/api/v1/detect?wait_seconds=0',
    headers: { 'x-detection-id': 'a'.repeat(32), 'content-length': '100' }, complete
  })
  const res = new EventEmitter()
  const upstream = new EventEmitter()
  let destroys = 0
  upstream.destroy = () => { destroys++; upstream.destroyed = true }
  configureUploadProxy(proxy, { logger })
  proxy.emit('proxyReq', upstream, req, res)
  return { req, res, upstream, destroys: () => destroys }
}

test('incomplete client close destroys its upstream once', () => {
  const f = fixture()
  f.req.emit('close')
  f.res.emit('close')
  f.req.emit('aborted')
  assert.equal(f.destroys(), 1)
})

test('normal complete request and response close never cancel upstream', () => {
  const f = fixture(true)
  f.req.emit('end')
  f.req.emit('close')
  f.res.emit('close')
  assert.equal(f.destroys(), 0)
})

test('upstream close removes per-request listeners', () => {
  const f = fixture()
  f.upstream.emit('close')
  for (const name of ['end', 'aborted', 'close', 'error']) assert.equal(f.req.listenerCount(name), 0)
  assert.equal(f.res.listenerCount('close'), 0)
})

test('request errors and a pre-aborted request cancel incomplete upstream', () => {
  const f = fixture()
  f.req.emit('error', Object.assign(new Error('reset'), { code: 'ECONNRESET' }))
  assert.equal(f.destroys(), 1)
  const proxy = new EventEmitter()
  configureUploadProxy(proxy, { logger })
  const req = Object.assign(new EventEmitter(), { method: 'POST', url: '/detect', headers: {}, aborted: true })
  let cancelled = false
  proxy.emit('proxyReq', Object.assign(new EventEmitter(), { destroy() { cancelled = true } }), req, new EventEmitter())
  assert.equal(cancelled, true)
})

test('non-upload requests are unaffected', () => {
  const proxy = new EventEmitter()
  configureUploadProxy(proxy, { logger })
  const req = Object.assign(new EventEmitter(), { method: 'GET', url: '/api/v1/detect/tasks/a' })
  proxy.emit('proxyReq', {}, req, new EventEmitter())
  assert.equal(req.listenerCount('close'), 0)
})

for (const mode of ['dev', 'preview']) test(`real Vite ${mode} proxy releases two aborted uploads and accepts a third`, { timeout: 10000 }, async () => {
  const { createServer, preview } = await import('vite')
  const active = new Set()
  const sockets = new Set()
  const backend = http.createServer((req, res) => {
    active.add(req)
    req.on('error', () => {})
    req.on('close', () => active.delete(req))
    req.on('data', () => {})
    req.on('end', () => {
      active.delete(req)
      res.writeHead(202, { 'Content-Type': 'application/json' })
      res.end('{"status":"queued"}')
    })
  })
  backend.on('connection', socket => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })
  await new Promise(resolve => backend.listen(0, '127.0.0.1', resolve))
  let vite
  const cacheDir = await mkdtemp(join(tmpdir(), 'codefender-proxy-test-'))
  const clients = []
  async function until(predicate) {
    for (let i = 0; i < 100; i++) {
      if (predicate()) return
      await delay(10)
    }
    assert.ok(predicate(), 'proxy cleanup did not complete within one second')
  }
  try {
    const proxy = {
      '/api-backend': { target: `http://127.0.0.1:${backend.address().port}`,
        rewrite: path => path.replace(/^\/api-backend/, ''),
        configure: proxy => configureUploadProxy(proxy, { logger }) }
    }
    const options = { configFile: false, logLevel: 'silent', cacheDir,
      optimizeDeps: { noDiscovery: true, include: [] },
      server: { host: '127.0.0.1', port: 0, proxy },
      preview: { host: '127.0.0.1', port: 0, proxy } }
    if (mode === 'preview') {
      const outDir = join(cacheDir, 'dist')
      await mkdir(outDir)
      await writeFile(join(outDir, 'index.html'), '<html></html>')
      vite = await preview({ ...options, build: { outDir } })
    } else {
      vite = await createServer(options)
      await vite.listen()
    }
    const port = vite.httpServer.address().port
    for (let i = 0; i < 2; i++) {
      const req = http.request({ host: '127.0.0.1', port, method: 'POST',
        path: '/api-backend/api/v1/detect?wait_seconds=0', headers: { 'Content-Length': '100000' } })
      req.on('error', () => {})
      req.write('partial')
      clients.push(req)
    }
    await until(() => active.size === 2)
    clients.forEach(req => req.destroy())
    await until(() => active.size === 0)
    const status = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method: 'POST',
        path: '/api-backend/api/v1/detect?wait_seconds=0', headers: { 'Content-Length': '5' } }, res => {
        res.resume()
        res.on('end', () => resolve(res.statusCode))
      })
      req.on('error', reject)
      req.end('hello')
    })
    assert.equal(status, 202)
  } finally {
    clients.forEach(req => req.destroy())
    if (vite) {
      if (mode === 'dev') await vite.close()
      else {
        vite.httpServer.closeAllConnections()
        await new Promise(resolve => vite.httpServer.close(resolve))
      }
    }
    sockets.forEach(socket => socket.destroy())
    await new Promise(resolve => backend.close(resolve))
    await rm(cacheDir, { recursive: true, force: true })
  }
})
