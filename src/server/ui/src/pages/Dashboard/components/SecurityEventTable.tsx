import { Card, Table } from "antd";
import type { ColumnsType } from "antd/es/table";
import type { SecurityEvent } from "@/types/dashboard";
import { categoryMap, threatLevelMap } from "../constants.tsx";
import styles from "./SecurityEventTable.module.less";

// 将 hex 颜色转为 rgba，opacity 控制透明度
const hexToRgba = (hex: string, opacity: number) => {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${opacity})`;
};

interface SecurityEventTableProps {
  data: SecurityEvent[];
  activeTab: string;
  onTabChange: (key: string) => void;
  selectedThreatLevel: string | null;
  onThreatLevelClear: () => void;
}

const SecurityEventTable: React.FC<SecurityEventTableProps> = ({
  data,
  activeTab,
  onTabChange,
}) => {
  // 表格列定义
  const columns: ColumnsType<SecurityEvent> = [
    {
      title: "分类",
      dataIndex: "category",
      key: "category",
      width: 120,
      render: (category) => {
        const config = categoryMap[category as keyof typeof categoryMap];
        const color = config?.color || '#d9d9d9';
        return (
          <span
            className={styles.tagBadge}
            style={{
              color: color,
              background: hexToRgba(color, 0.3),
            }}
          >
            {config?.text || category}
          </span>
        );
      },
    },
    {
      title: "二级分类",
      dataIndex: "subCategoryDescription",
      key: "subCategoryDescription",
      width: 200,
      render: (subCategoryDescription) => {
        return (
          subCategoryDescription || (
            <span className={styles.subCategoryPlaceholder}>-</span>
          )
        );
      },
    },
    {
      title: "威胁级别",
      dataIndex: "threatLevel",
      key: "threatLevel",
      width: 200,
      filters: [
        { text: "严重", value: "critical" },
        { text: "高危", value: "high" },
        { text: "中危", value: "medium" },
        { text: "低危", value: "low" },
        { text: "日志", value: "info" },
      ],
      onFilter: (value, record) => record.threatLevel === value,
      render: (level) => {
        const config = threatLevelMap[level as keyof typeof threatLevelMap];
        const color = config?.color || '#d9d9d9';
        return (
          <span
            className={styles.tagBadge}
            style={{
              color: color,
              background: hexToRgba(color, 0.3),
            }}
          >
            {config?.text || level}
          </span>
        );
      },
    },
    {
      title: "处置建议",
      dataIndex: "recommendation",
      key: "recommendation",
      ellipsis: true,
      render: (recommendation) => (
        <span
          className={`${styles.recommendationText} ${!recommendation ? styles.empty : ''}`}
        >
          {recommendation || "-"}
        </span>
      ),
    },
    {
      title: "事件时间",
      dataIndex: "eventTime",
      key: "eventTime",
      width: 180,
      render: (time) => {
        const date = new Date(time);
        return date.toLocaleString("zh-CN", {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });
      },
    },
  ];

  // 分页配置
  const paginationConfig = {
    pageSize: 10,
    showSizeChanger: true,
    showTotal: (total: number) => `共 ${total} 条记录`,
    showQuickJumper: true,
  };

  return (
    <Card
      headStyle={{
        minHeight: "48px",
      }}
      title={
        <span className={styles.cardTitle}>
          安全事件详情
        </span>
      }
    >
      <div className={styles.tabContainer}>
        {[
          { key: "all", label: "全部事件" },
          { key: "config_security", label: "配置安全" },
          { key: "skill_security", label: "Skill安全" },
          { key: "command_violation", label: "危险命令" },
          { key: "content_check", label: "上下文检查" },
        ].map((item) => (
          <button
            key={item.key}
            onClick={() => onTabChange(item.key)}
            className={`${styles.tabButton} ${activeTab === item.key ? styles.active : ''}`}
          >
            {item.label}
          </button>
        ))}
      </div>

      <Table
        columns={columns}
        dataSource={data}
        pagination={paginationConfig}
        size="middle"
        scroll={{ x: 800 }}
        rowClassName={(record) => {
          if (record.threatLevel === "critical") return "critical-row";
          if (record.threatLevel === "high") return "high-row";
          return "";
        }}
        expandable={{
          expandedRowRender: (record) => (
            <div className={styles.expandedRow}>
              <div className={styles.expandedRowTitle}>
                事件信息
              </div>
              <div className={styles.expandedRowContent}>
                {record.eventInfo || "暂无事件信息"}
              </div>
            </div>
          ),
          rowExpandable: (record) => !!record.eventInfo,
          defaultExpandAllRows: false,
        }}
      />

    </Card>
  );
};

export default SecurityEventTable;
