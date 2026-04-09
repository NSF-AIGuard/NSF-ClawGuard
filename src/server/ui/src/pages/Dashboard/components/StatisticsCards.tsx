import { Card, Row, Col, Statistic } from 'antd'
import { 
  SafetyOutlined, 
  FireOutlined,
  AlertOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  InfoCircleOutlined
} from '@ant-design/icons'
import type { Statistics } from '@/types/dashboard'
import styles from './StatisticsCards.module.less'

interface StatisticsCardsProps {
  statistics: Statistics
}

const StatisticsCards: React.FC<StatisticsCardsProps> = ({ statistics }) => {
  return (
    <Row gutter={16}>
      <Col span={4}>
        <Card>
          <Statistic
            title={
              <span className={`${styles.statTitle} ${styles.colorTotal}`}>
                <span>总事件数</span>
                <SafetyOutlined className={styles.statIcon} />
              </span>
            }
            value={statistics.total}
            valueStyle={{ color: '#fff', fontSize: 28, fontWeight: 600 }}
          />
        </Card>
      </Col>
      <Col span={4}>
        <Card>
          <Statistic
            title={
              <span className={`${styles.statTitle} ${styles.colorCritical}`}>
                <span>严重威胁</span>
                <FireOutlined className={styles.statIcon} />
              </span>
            }
            value={statistics.critical}
            valueStyle={{ color: '#ff4d4f', fontSize: 28, fontWeight: 600 }}
          />
        </Card>
      </Col>
      <Col span={4}>
        <Card>
          <Statistic
            title={
              <span className={`${styles.statTitle} ${styles.colorHigh}`}>
                <span>高危风险</span>
                <AlertOutlined className={styles.statIcon} />
              </span>
            }
            value={statistics.high}
            valueStyle={{ color: '#ff7a45', fontSize: 28, fontWeight: 600 }}
          />
        </Card>
      </Col>
      <Col span={4}>
        <Card>
          <Statistic
            title={
              <span className={`${styles.statTitle} ${styles.colorMedium}`}>
                <span>中危风险</span>
                <WarningOutlined className={styles.statIcon} />
              </span>
            }
            value={statistics.medium}
            valueStyle={{ color: '#faad14', fontSize: 28, fontWeight: 600 }}
          />
        </Card>
      </Col>
      <Col span={4}>
        <Card>
          <Statistic
            title={
              <span className={`${styles.statTitle} ${styles.colorLow}`}>
                <span>低危风险</span>
                <CheckCircleOutlined className={styles.statIcon} />
              </span>
            }
            value={statistics.low}
            valueStyle={{ color: '#52c41a', fontSize: 28, fontWeight: 600 }}
          />
        </Card>
      </Col>
      <Col span={4}>
        <Card>
          <Statistic
            title={
              <span className={`${styles.statTitle} ${styles.colorInfo}`}>
                <span>日志记录</span>
                <InfoCircleOutlined className={styles.statIcon} />
              </span>
            }
            value={statistics.info}
            valueStyle={{ color: '#1690ff', fontSize: 28, fontWeight: 600 }}
          />
        </Card>
      </Col>
    </Row>
  )
}

export default StatisticsCards