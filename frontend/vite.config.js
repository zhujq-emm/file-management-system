import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173
  },
  base: '/file-management-system/', // 你的仓库名
  build: {
    outDir: 'dist'
  }
})