import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
    // 设置基础路径为/web
    base: '/web/',
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
    css: {
        preprocessorOptions: {
            less: {
                javascriptEnabled: true,
                modifyVars: {
                    // 可以在这里覆盖 Ant Design 的主题变量
                    '@primary-color': '#55A722',
                },
            },
        },
        modules: {
            localsConvention: 'camelCase',
        },
    },
    build: {
        // 指定输出目录为web
        emptyOutDir: true, 
        outDir: '../web',
        // 代码分割和分包配置
        rollupOptions: {
            output: {
                // 手动分包策略
                manualChunks: {
                    // React 核心库
                    'react-vendor': ['react', 'react-dom', 'react-router-dom'],
                    // Redux 状态管理
                    'redux-vendor': ['@reduxjs/toolkit', 'react-redux'],
                    // UI 框架
                    'antd-vendor': ['antd'],
                    // HTTP 请求库
                    'axios-vendor': ['axios'],
                },
                // 分块文件命名
                chunkFileNames: 'static/js/[name]-[hash].js',
                entryFileNames: 'static/js/[name]-[hash].js',
                assetFileNames: 'static/[ext]/[name]-[hash].[ext]',
            },
        },
        // 分块大小警告阈值
        chunkSizeWarningLimit: 1000,
        // 压缩配置
        minify: 'terser',
        terserOptions: {
            compress: {
                drop_console: true,
                drop_debugger: true,
            },
        },
    },
    // 开发服务器配置
    server: {
        port: 3000,
        open: true,
        host: '0.0.0.0',
        proxy: {
            // API 代理配置
            '/lm-securty': {
                target: 'http://localhost:19001',
                changeOrigin: true,
            },
        },
    },
})
