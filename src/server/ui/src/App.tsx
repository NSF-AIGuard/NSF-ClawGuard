import React from 'react'
import { RouterProvider } from 'react-router-dom'
import { ConfigProvider, theme } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import dayjs from 'dayjs'
import 'dayjs/locale/zh-cn'
import router from '@/router'
import styles from './App.module.less'

// 设置 dayjs 为中文
dayjs.locale('zh-cn')

const App: React.FC = () => {
  return (
    <div className={styles.app}>
      <ConfigProvider
        locale={zhCN}
        theme={{
          algorithm: theme.darkAlgorithm,
          token: {
            colorPrimary: '#55A722',
            borderRadius: 6,
            colorBgContainer: '#1c2333',
            colorBgElevated: '#1e2d3d',
            colorBgLayout: '#0d1117',
            colorBorder: '#30363d',
            colorBorderSecondary: '#21262d',
            colorText: 'rgba(230, 237, 243, 0.85)',
            colorTextSecondary: 'rgba(230, 237, 243, 0.65)',
            colorTextTertiary: 'rgba(230, 237, 243, 0.45)',
            colorFillSecondary: 'rgba(255, 255, 255, 0.08)',
            colorFillQuaternary: 'rgba(255, 255, 255, 0.04)',
          },
          components: {
            Button: {
              borderRadius: 6,
            },
            Input: {
              borderRadius: 6,
            },
            Card: {
              borderRadius: 8,
              colorBgContainer: '#1c2333',
              colorBorderSecondary: '#30363d',
            },
            Table: {
              colorBgContainer: '#1c2333',
              headerBg: '#161b22',
              rowHoverBg: 'rgba(85, 167, 34, 0.08)',
              colorText: 'rgba(230, 237, 243, 0.85)',
            },
            Tabs: {
              colorBgContainer: '#1c2333',
              inkBarColor: '#55a722',
            },
            Menu: {
              colorBgContainer: '#26303a',
              colorItemBg: '#26303a',
            },
            Tag: {
              colorBgContainer: 'rgba(85, 167, 34, 0.1)',
            },
            Select: {
              colorBgContainer: '#1c2333',
              colorBgElevated: '#1e2d3d',
            },
            Spin: {
              colorPrimary: '#55a722',
            },
          },
        }}
      >
        <RouterProvider router={router} />
      </ConfigProvider>
    </div>
  )
}

export default App