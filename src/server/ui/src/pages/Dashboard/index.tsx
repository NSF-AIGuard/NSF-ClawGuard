import { useState, useEffect, useCallback } from 'react'
import { Spin, Button } from 'antd'
import { ReloadOutlined, CloseCircleOutlined } from '@ant-design/icons'
import StatisticsCards from './components/StatisticsCards'
import ThreatDistribution from './components/ThreatDistribution'
import SecurityEventTable from './components/SecurityEventTable'
import Charts from './components/Charts'
import { getEventStats, getRiskDistribution } from '@/api/threat'
import type { Statistics, RiskDistribution } from '@/types/dashboard'
import styles from './index.module.less'

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState('all')
  const [selectedThreatLevel, setSelectedThreatLevel] = useState<string | null>(null)
  const [statistics, setStatistics] = useState<Statistics>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  })
  const [riskDistribution, setRiskDistribution] = useState<RiskDistribution>({
    config_security: 0,
    skill_security: 0,
    command_violation: 0,
    component_change: 0,
    content_check: 0,
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // 获取统计数据（通过 eventStats 接口）
  const fetchStatsData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      // 并行请求统计数据和风险分布数据
      const [statsRes, riskRes] = await Promise.all([
        getEventStats(),
        getRiskDistribution(),
      ])

      setStatistics(statsRes)
      setRiskDistribution(riskRes)
    } catch (err) {
      setError('Failed to load threat data')
      console.error('Error fetching threat data:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStatsData()
  }, [fetchStatsData])

  if (loading) {
    return (
      <div className={styles.loadingContainer}>
        <div className={styles.loadingSpinner}>
          <Spin size="large" />
        </div>
        <div className={styles.loadingText}>正在加载安全数据...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className={styles.loadingContainer}>
        <CloseCircleOutlined className={styles.errorIcon} />
        <div className={styles.errorTitle}>数据加载失败</div>
        <div className={styles.errorText}>{error}</div>
        <Button
          className={styles.retryButton}
          icon={<ReloadOutlined />}
          onClick={fetchStatsData}
        >
          重新加载
        </Button>
      </div>
    )
  }

  return (
    <div style={{ padding: '0' }}>
      <div className={styles.headerSection}>
        <h2 className={styles.pageTitle}>
          端侧安全告警监控中心
        </h2>
        <p className={styles.pageSubtitle}>
          绿盟清风卫|Openclaw 单端侧实时风险监测，自动化安全处置
        </p>
      </div>

      {/* 统计卡片 */}
      <div className={styles.sectionGap}>
         <StatisticsCards statistics={statistics} />
      </div>

      {/* 图表展示 */}
      <div className={styles.sectionGap}>
        <Charts statistics={statistics} riskDistribution={riskDistribution} />
      </div>

      {/* 威胁分布统计 */}
      <div className={styles.sectionGap}>
        <ThreatDistribution statistics={statistics} />
      </div>

      {/* 安全事件表格 */}
      <SecurityEventTable
        activeTab={activeTab}
        onTabChange={setActiveTab}
        selectedThreatLevel={selectedThreatLevel}
        onThreatLevelChange={setSelectedThreatLevel}
      />
    </div>
  )
}

export default Dashboard