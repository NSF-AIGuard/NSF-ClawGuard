import React from 'react'
import { Button } from 'antd'
import { useNavigate } from 'react-router-dom'
import {
  HomeOutlined,
  ArrowLeftOutlined,
} from '@ant-design/icons'
import styles from './index.module.less'

const NotFound: React.FC = () => {
  const navigate = useNavigate()

  const handleGoHome = () => {
    navigate('/dashboard')
  }

  const handleGoBack = () => {
    navigate(-1)
  }

  return (
    <div className={styles.notFound}>
      {/* 背景装饰 */}
      <div className={styles.bgDecoration}>
        <div className={styles.gridOverlay} />
        <div className={styles.glowCircle} />
        <div className={styles.scanLine} />
      </div>

      {/* 主内容 */}
      <div className={styles.content}>
        <div className={styles.errorCode}>
          <span className={styles.codeDigit}>4</span>
          <span className={styles.codeDigitMiddle}>
            <svg viewBox="0 0 100 120" className={styles.shieldIcon}>
              <defs>
                <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#55a722" />
                  <stop offset="100%" stopColor="#3d8a10" />
                </linearGradient>
              </defs>
              <path
                d="M50 5 L90 25 L90 65 Q90 95 50 115 Q10 95 10 65 L10 25 Z"
                fill="none"
                stroke="url(#shieldGrad)"
                strokeWidth="3"
                className={styles.shieldPath}
              />
              <path
                d="M35 60 L47 72 L67 48"
                fill="none"
                stroke="#55a722"
                strokeWidth="4"
                strokeLinecap="round"
                strokeLinejoin="round"
                className={styles.checkPath}
              />
            </svg>
          </span>
          <span className={styles.codeDigit}>4</span>
        </div>

        <h2 className={styles.subtitle}>页面未找到</h2>
        <p className={styles.description}>
          抱歉，您访问的页面不存在或已被移除。请检查地址是否正确，或返回首页。
        </p>

        <div className={styles.actions}>
          <Button
            type="primary"
            size="large"
            icon={<HomeOutlined />}
            onClick={handleGoHome}
            className={styles.btnPrimary}
          >
            返回首页
          </Button>
          <Button
            size="large"
            icon={<ArrowLeftOutlined />}
            onClick={handleGoBack}
            className={styles.btnDefault}
          >
            返回上一页
          </Button>
        </div>

        <div className={styles.footer}>
          <div className={styles.footerDot} />
          <span>LM Security · 智能安全检测系统</span>
        </div>
      </div>
    </div>
  )
}

export default NotFound