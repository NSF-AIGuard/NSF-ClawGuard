import { lazy, Suspense } from 'react'
import { createBrowserRouter, Navigate } from 'react-router-dom'
import { Spin } from 'antd'
import MainLayout from '@/layouts/MainLayout'

// 加载组件（深色主题风格）
const LoadingFallback = () => (
  <div style={{
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    alignItems: 'center',
    height: '100vh',
    background: '#0d1117',
    gap: '16px',
  }}>
    <style>{`
      .route-loading-spin .ant-spin-dot-item {
        background: #55a722 !important;
      }
    `}</style>
    <Spin size="large" className="route-loading-spin" />
    <span style={{
      color: 'rgba(230, 237, 243, 0.65)',
      fontSize: '15px',
      letterSpacing: '0.5px',
    }}>
      正在加载页面...
    </span>
  </div>
)

// 使用 React.lazy 进行代码分割
const Dashboard = lazy(() => import('@/pages/Dashboard'))
const NotFound = lazy(() => import('@/pages/NotFound'))
const AuditLog = lazy(() => import('@/pages/AuditLog'))

const router = createBrowserRouter([
  {
    path: '/',
    element: <MainLayout />,
    children: [
      {
        index: true,
        element: <Navigate to="/dashboard" replace />,
      },
      {
        path: 'dashboard',
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <Dashboard />
          </Suspense>
        ),
      },
      {
        path: 'audit-log',
        element: (
          <Suspense fallback={<LoadingFallback />}>
            <AuditLog />
          </Suspense>
        ),
      }
    ],
  },
  {
    path: '*',
    element: (
      <Suspense fallback={<LoadingFallback />}>
        <NotFound />
      </Suspense>
    ),
  },
], {
  basename: '/web'
})

export default router