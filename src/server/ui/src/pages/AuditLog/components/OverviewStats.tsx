import React from 'react'
import { Row, Col, Card } from 'antd'
import {
  TeamOutlined,
  DollarOutlined,
  ToolOutlined,
  SafetyCertificateOutlined,
  ArrowUpOutlined,
  ArrowDownOutlined,
} from '@ant-design/icons'
import type { OverviewStatistics } from '@/types/auditLog'
import { formatTokens } from '../constants'
import styles from '../index.module.less'

interface OverviewStatsProps {
  statistics: OverviewStatistics
}

const OverviewStats: React.FC<OverviewStatsProps> = ({ statistics }) => {
  const cards = [
    {
      key: 'session',
      className: `statCard ${styles.statCard} card-session`,
      icon: <TeamOutlined />,
      iconClass: 'session',
      label: '今日会话数',
      value: statistics.totalSessions,
      extra: (
        <span className={styles.rateUp}>
          <ArrowUpOutlined /> 活跃中
        </span>
      ),
    },
    {
      key: 'token',
      className: `statCard ${styles.statCard} card-token`,
      icon: <DollarOutlined />,
      iconClass: 'token',
      label: '今日Token消耗',
      value: formatTokens(statistics.todayTokenConsumption),
      extra:parseFloat(statistics.tokenDiffPercent)  < 0 ? (
        <span className={styles.rateDown}>
          <ArrowDownOutlined /> 较昨日 {statistics.tokenDiffPercent}%
        </span>
      ) : (
        <span className={styles.rateUp}>
          较昨日 {statistics.tokenDiffPercent}%
        </span>
      ),
    },
    {
      key: 'tool',
      className: `statCard ${styles.statCard} card-tool`,
      icon: <ToolOutlined />,
      iconClass: 'tool',
      label: '今日工具调用',
      value: statistics.todayToolCalls,
      extra: `成功率 ${statistics.toolSuccessRate}%`,
    },
    {
      key: 'auth',
      className: `statCard ${styles.statCard} card-auth`,
      icon: <SafetyCertificateOutlined />,
      iconClass: 'auth',
      label: '今日认证事件',
      value: statistics.todayAuthEvents,
      extra: statistics.authFailureRate > 10 ? (
        <span className={styles.rateDown}>
          <ArrowDownOutlined /> 失败率 {statistics.authFailureRate}%
        </span>
      ) : (
        <span className={styles.rateUp}>
          失败率 {statistics.authFailureRate}%
        </span>
      ),
    },
  ]

  return (
    <Row gutter={16} className={styles.auditLogStats}>
      {cards.map((card) => (
        <Col span={6} key={card.key}>
          <Card className={card.className} bodyStyle={{ padding: 0 }}>
            <div className={styles.statCardInner}>
              <div className={`${styles.statIcon} ${card.iconClass}`}>
                {card.icon}
              </div>
              <div className={styles.statContent}>
                <div className={styles.statLabel}>{card.label}</div>
                <div className={styles.statValue}>{card.value}</div>
                <div className={styles.statExtra}>{card.extra}</div>
              </div>
            </div>
          </Card>
        </Col>
      ))}
    </Row>
  )
}

export default OverviewStats