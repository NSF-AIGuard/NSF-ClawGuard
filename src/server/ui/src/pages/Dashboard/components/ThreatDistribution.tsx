import { Card, Row, Col, Tag } from "antd";
import dayjs from "dayjs";
import type { Statistics } from "@/types/dashboard";
import styles from "./ThreatDistribution.module.less";

interface ThreatDistributionProps {
  statistics: Statistics;
}

const ThreatDistribution: React.FC<ThreatDistributionProps> = ({
  statistics,
}) => {
  const threatLevels = [
    { key: "critical", label: "严重", color: "#ff4d4f", value: statistics.critical },
    { key: "high", label: "高危", color: "#ff7a45", value: statistics.high },
    { key: "medium", label: "中危", color: "#faad14", value: statistics.medium },
    { key: "low", label: "低危", color: "#52c41a", value: statistics.low },
    { key: "info", label: "日志", color: "#1890ff", value: statistics.info },
  ] as const;

  return (
    <Row gutter={16}>
      <Col span={8}>
        <Card
          headStyle={{
            minHeight: "48px",
          }}
          title={
            <span className={styles.cardTitle}>
              端侧安全通过率
            </span>
          }
          bodyStyle={{
            padding: "12px 24px",
            height: "240px",
          }}
        >
          <div className={styles.rateCenter}>
            <div className={styles.rateCircle}>
              <div className={styles.rateValue}>
                {(
                  ((statistics.low + statistics.info) / statistics.total) *
                  100
                ).toFixed(1)}
                %
              </div>
              <div className={styles.rateLabel}>
                安全通过率
              </div>
            </div>
            <div className={styles.rateInfo}>
              <div>扫描时间: {dayjs().format("YYYY-MM-DD")}</div>
              <div>
                共检测: {statistics.total}　通过:{" "}
                {statistics.low + statistics.info}
              </div>
            </div>
          </div>
        </Card>
      </Col>
      <Col span={16}>
        <Card
          headStyle={{
            minHeight: "48px",
          }}
          title={
            <span className={styles.cardTitle}>
              威胁等级占比
            </span>
          }
          bodyStyle={{
            padding: "12px 24px",
            height: "240px",
          }}
          extra={
            <>
              <Tag color="#ff4d4f" className={styles.tagMargin}>
                严重: {statistics.critical}
              </Tag>
              <Tag color="#ff7a45" className={styles.tagMargin}>
                高危: {statistics.high}
              </Tag>
              <Tag color="#faad14" className={styles.tagMargin}>
                中危: {statistics.medium}
              </Tag>
              <Tag color="#52c41a" className={styles.tagMargin}>
                低危: {statistics.low}
              </Tag>
              <Tag color="#1890ff">日志: {statistics.info}</Tag>
            </>
          }
        >
          <div className={styles.threatList}>
            {threatLevels.map(({ key, label, value }) => (
              <div key={key}>
                <div className={styles.threatRowHeader}>
                  <span className={`${styles.threatLabel} ${styles[`color-${key}`]}`}>{label}</span>
                  <span className={`${styles.threatValue} ${styles[`color-${key}`]}`}>
                    {value} ({((value / statistics.total) * 100).toFixed(1)}%)
                  </span>
                </div>
                <div className={styles.progressBarBg}>
                  <div
                    className={`${styles.progressBarFill} ${styles[`bg-${key}`]}`}
                    style={{ width: `${(value / statistics.total) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </Col>
    </Row>
  );
};

export default ThreatDistribution;