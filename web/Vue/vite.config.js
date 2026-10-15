import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const proxy = {
  '/api-backend': {
    target: 'http://127.0.0.1:5006',
    changeOrigin: true,
    timeout: 660000,
    proxyTimeout: 660000,
    rewrite: path => path.replace(/^\/api-backend/, '')
  }
}

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 9528,
    strictPort: true,
    proxy
  },
  preview: { port: 9528, strictPort: true, proxy }
})
