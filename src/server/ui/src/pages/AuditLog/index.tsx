import React, { useState, useEffect } from 'react'
import { Tabs, Card, Spin, Button, Space } from 'antd'
import {
  DollarOutlined,
  ToolOutlined,
  ReloadOutlined,
  DownloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import OverviewStats from './components/OverviewStats'
import TokenConsumption from './components/TokenConsumption'
import ToolCallTable from './components/ToolCallTable'
import GatewayAuthLogTable from './components/GatewayAuthLogTable'
import type { TokenConsumptionRecord, ToolCallRecord, OverviewStatistics, GatewayAuthLogRecord } from '@/types/auditLog'
import { getTokenConsumptionList, getOverviewStatistics, getToolCallList, getGatewayAuthLogList } from '@/api/auditLog'
import styles from './index.module.less'

const AuditLog: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('token')

  // 数据状态
  // const [authData, setAuthData] = useState<AuthLogRecord[]>([])
  const [tokenData, setTokenData] = useState<TokenConsumptionRecord[]>([])
  const [toolCallData, setToolCallData] = useState<ToolCallRecord[]>([])
  const [gatewayAuthData, setGatewayAuthData] = useState<GatewayAuthLogRecord[]>([])
  const [statistics, setStatistics] = useState<OverviewStatistics>({
    totalSessions: 0,
    todayTokenConsumption: 0,
    todayToolCalls: 0,
    todayAuthEvents: 0,
    authFailureRate: 0,
    toolSuccessRate: 0,
    tokenDiffPercent: '0'
  })

  /** 加载所有数据 */
  const fetchAllData = async () => {
    setLoading(true)
    try {
      // Token 消耗使用真实 API，其余仍使用 Mock 数据
      const tokenRes = await getTokenConsumptionList()
      const statisticsRes = await getOverviewStatistics()
      const toolCallRes = await getToolCallList()
      const gatewayAuthRes = await getGatewayAuthLogList()

      // setAuthData(mockAuthLogData())
      setTokenData(tokenRes)
      setStatistics(statisticsRes)
      setToolCallData(toolCallRes)
      setGatewayAuthData(gatewayAuthRes)
      // setStatistics(mockOverviewStatistics())
    } catch (error) {
      console.error('加载审计日志数据失败:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAllData()
  }, [])

  // Tab 配置
  const tabItems = [
    {
      key: 'token',
      label: (
        <span>
          <DollarOutlined  className={styles.tabIcon} />
          Token 消耗
        </span>
      ),
      children: <TokenConsumption data={tokenData} />,
    },
    {
      key: 'tool',
      label: (
        <span>
          <ToolOutlined className={styles.tabIcon} />
          工具调用
        </span>
      ),
      children: <ToolCallTable data={toolCallData} />,
    },
    {
      key: 'gatewayAuth',
      label: (
        <span>
          <SafetyCertificateOutlined className={styles.tabIcon} />
          网关认证日志
        </span>
      ),
      children: <GatewayAuthLogTable data={gatewayAuthData} />,
    },
  ]

  return (
    <Spin spinning={loading} tip="正在加载审计数据...">
      <div className={styles.auditLog}>
        {/* 页面头部 */}
        <div className={styles.auditLogHeader}>
          <div>
            <div className={styles.auditLogHeaderTitle}>
              <h2>
                安全审计日志
              </h2>
              <span className={styles.auditLogHeaderBadge}>
                <span className={styles.pulseDot} />
                实时监控中
              </span>
            </div>
            <p className={styles.auditLogHeaderSubtitle}>
              集中展示Token 消耗分析及安全工具调用记录，助力安全态势感知与审计追溯
            </p>
          </div>
          <Space>
            <Button
              icon={<ReloadOutlined spin={loading} />}
              onClick={fetchAllData}
              loading={loading}
            >
              刷新数据
            </Button>
            <Button
              icon={<DownloadOutlined />}
              type="primary"
              className={styles.exportButton}
            >
              导出报告
            </Button>
          </Space>
        </div>

        {/* 统计概览 */}
        <OverviewStats statistics={statistics} />

        {/* 日志内容 Tab */}
        <div className={styles.auditLogContent}>
          <Card className={styles.tabCard} bodyStyle={{ padding: 0 }}>
            <Tabs
              activeKey={activeTab}
              onChange={setActiveTab}
              items={tabItems}
              size="large"
            />
          </Card>
        </div>
      </div>
    </Spin>
  )
}

export default AuditLog