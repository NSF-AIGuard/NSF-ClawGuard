import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['index.ts'],
  format: ['esm'],
  dts: true,
  outDir: 'dist',
  clean: true,
  sourcemap: false,
  splitting: false,
  target: 'node18',
  minify: false,
  bundle: true,
  external: [],
  noExternal: [/^(?!bcrypt$).*/],
  loader: {
    '.wasm': 'base64'   // 将 .wasm 文件转为 base64 字符串
  },
  outExtension({ format }) {
    return {
      js: format === 'esm' ? '.mjs' : '.cjs'
    }
  }
})
