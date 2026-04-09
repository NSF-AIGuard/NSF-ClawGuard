import { useState, useEffect, useMemo } from 'react'
import StatisticsCards from './components/StatisticsCards'
import ThreatDistribution from './components/ThreatDistribution'
import SecurityEventTable from './components/SecurityEventTable'
import Charts from './components/Charts'
import { getThreatList } from '@/api/threat'
import type { SecurityEvent, Statistics } from '@/types/dashboard'
import styles from './index.module.less'

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState('all')
  const [selectedThreatLevel, setSelectedThreatLevel] = useState<string | null>(null)
  const [securityData, setSecurityData] = useState<SecurityEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchThreatData = async () => {
      try {
        setLoading(true)
        setError(null)
        const threatEvents = await getThreatList()
        
        // Transform ThreatEvent[] to SecurityEvent[]
        const transformedData: SecurityEvent[] = threatEvents.map((event, index) => ({
          key: `${index}-${event.event_time}`,
          category: event.category,
          subCategory: event.sub_category,
          threatLevel:event.threat_level,
          recommendation: event.recommendation,
          eventTime: event.event_time,
          subCategoryDescription:event.sub_category_description,
          eventInfo: event.event_info
        })) 
        
        setSecurityData(transformedData)
      } catch (err) {
        setError('Failed to load threat data')
        console.error('Error fetching threat data:', err)
      } finally {
        setLoading(false)
      }
    }

    fetchThreatData()
  }, [])

  // 计算统计数据
  const statistics: Statistics = useMemo(() => {
    const total = securityData.length
    const critical = securityData.filter(item => item.threatLevel === 'critical').length
    const high = securityData.filter(item => item.threatLevel === 'high').length
    const medium = securityData.filter(item => item.threatLevel === 'medium').length
    const low = securityData.filter(item => item.threatLevel === 'low').length
    const info = securityData.filter(item => item.threatLevel === 'info').length
    
    return { total, critical, high, medium, low, info }
  }, [securityData])

  // 筛选数据
  const filteredData: SecurityEvent[] = useMemo(() => {
    let data = securityData
    
    if (activeTab !== 'all') {
      data = data.filter(item => item.category === activeTab)
    }
    
    if (selectedThreatLevel) {
      data = data.filter(item => item.threatLevel === selectedThreatLevel)
    }
    
    return data
  }, [securityData, activeTab, selectedThreatLevel])

  if (loading) {
    return (
      <div className={styles.loadingContainer}>
        <div className={styles.loadingText}>加载中...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className={styles.loadingContainer}>
        <div className={styles.errorText}>{error}</div>
      </div>
    )
  }

  return (
    <div style={{ padding: '0' }}>
      <div className={styles.headerSection}>
        <h2 className={styles.pageTitle}>
          端侧安全事件监控中心
        </h2>
        <p className={styles.pageSubtitle}>
          实时监测端侧安全状态，智能识别风险并提供处置方案
        </p>
      </div>

      {/* 统计卡片 */}
      <div className={styles.sectionGap}>
         <StatisticsCards statistics={statistics} />
      </div>

      {/* 图表展示 */}
      <div className={styles.sectionGap}>
        <Charts statistics={statistics} securityData={securityData} />
      </div>

      {/* 威胁分布统计 */}
      <div className={styles.sectionGap}>
        <ThreatDistribution statistics={statistics} />
      </div>

      {/* 安全事件表格 */}
      <SecurityEventTable
        data={filteredData}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        selectedThreatLevel={selectedThreatLevel}
        onThreatLevelClear={() => setSelectedThreatLevel(null)}
      />
    </div>
  )
}

export default Dashboard