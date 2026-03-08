import { defineConfig } from 'vite'
import { devApiPlugin } from './scripts/dev-api.js'
import fs from 'fs'
import path from 'path'
import { homedir } from 'os'

// 读取 package.json 版本号，构建时注入前端
const pkg = JSON.parse(fs.readFileSync(new URL('./package.json', import.meta.url), 'utf8'))

// 读取 Gateway 端口（启动时读取一次）
let gatewayPort = 18789
try {
  const cfg = JSON.parse(fs.readFileSync(path.join(homedir(), '.openclaw', 'openclaw.json'), 'utf8'))
  gatewayPort = cfg?.gateway?.port || 18789
} catch {}

export default defineConfig({
  plugins: [devApiPlugin()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    proxy: {
      '/ws': {
        target: `ws://127.0.0.1:${gatewayPort}`,
        ws: true,
        configure: (proxy) => {
          proxy.on('error', () => {})
        },
      },
    },
  },
  envPrefix: ['VITE_', 'TAURI_'],
  build: {
    target: ['es2021', 'chrome100', 'safari13'],
    minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
    sourcemap: !!process.env.TAURI_DEBUG,
  },
})
