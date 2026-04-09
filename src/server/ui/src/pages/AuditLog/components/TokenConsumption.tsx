import React, { useMemo } from "react";
import { Table, Tag, Tooltip, Space } from "antd";
import type { ColumnsType } from "antd/es/table";
import type { TokenConsumptionRecord } from "@/types/auditLog";
import { formatTokens, formatTime } from "../constants";
import parentStyles from "../index.module.less";
import styles from "./TokenConsumption.module.less";

interface TokenConsumptionProps {
  data: TokenConsumptionRecord[];
}

const TokenConsumption: React.FC<TokenConsumptionProps> = ({ data }) => {
  const totalInput = useMemo(
    () => data.reduce((sum, d) => sum + d.inputTokens, 0),
    [data],
  );
  const totalOutput = useMemo(
    () => data.reduce((sum, d) => sum + d.outputTokens, 0),
    [data],
  );
  const totalAll = totalInput + totalOutput;

  const columns: ColumnsType<TokenConsumptionRecord> = [
    {
      title: "会话ID",
      dataIndex: "sessionId",
      key: "sessionId",
      width: 140,
      render: (sid) => (
        <span className={styles.sessionId}>
          {sid}
        </span>
      ),
    },
    {
      title: "开始时间",
      dataIndex: "startTime",
      key: "startTime",
      width: 170,
      render: (time) => (
        <span className={styles.timeCell}>{formatTime(time)}</span>
      ),
    },
    {
      title: "模型",
      dataIndex: "model",
      key: "model",
      width: 130,
      render: (model) => (
        <Tag className={styles.modelTag}>
          {model || "N/A"}
        </Tag>
      ),
    },
    {
      title: "Input Tokens",
      dataIndex: "inputTokens",
      key: "inputTokens",
      width: 130,
      sorter: (a, b) => a.inputTokens - b.inputTokens,
      render: (val) => (
        <span className={styles.inputTokens}>
          {formatTokens(val)}
        </span>
      ),
    },
    {
      title: "Output Tokens",
      dataIndex: "outputTokens",
      key: "outputTokens",
      width: 130,
      sorter: (a, b) => a.outputTokens - b.outputTokens,
      render: (val) => (
        <span className={styles.outputTokens}>
          {formatTokens(val)}
        </span>
      ),
    },
    {
      title: "Total Tokens",
      dataIndex: "totalTokens",
      key: "totalTokens",
      width: 130,
      sorter: (a, b) => a.totalTokens - b.totalTokens,
      render: (val) => (
        <span className={styles.totalTokens}>
          {formatTokens(val)}
        </span>
      ),
    },
    {
      title: "Cache Read",
      dataIndex: "cacheReadTokens",
      key: "cacheReadTokens",
      width: 130,
      sorter: (a, b) => a.cacheReadTokens - b.cacheReadTokens,
      render: (val) => (
        <span className={styles.cacheReadTokens}>
          {formatTokens(val)}
        </span>
      ),
    },
    {
      title: "Cache Write",
      dataIndex: "cacheWriteTokens",
      key: "cacheWriteTokens",
      width: 130,
      sorter: (a, b) => a.cacheWriteTokens - b.cacheWriteTokens,
      render: (val) => (
        <span className={styles.cacheWriteTokens}>
          {formatTokens(val)}
        </span>
      ),
    },
    {
      title: "Token消耗分布",
      key: "bar",
      render: (_, record) => {
        const inputPercent = (record.inputTokens / record.totalTokens) * 100;
        const outputPercent = (record.outputTokens / record.totalTokens) * 100;
        return (
          <div className={parentStyles.auditLogTokenBar}>
            <div className={parentStyles.barTrack}>
              <div
                className={parentStyles.barInput}
                style={{ width: `${inputPercent}%` }}
              />
              <div
                className={parentStyles.barOutput}
                style={{ width: `${outputPercent}%` }}
              />
            </div>
            <Tooltip
              title={`输入: ${record.inputTokens.toLocaleString()} | 输出: ${record.outputTokens.toLocaleString()}`}
            >
              <span className={parentStyles.barValue}>
                {formatTokens(record.totalTokens)}
              </span>
            </Tooltip>
          </div>
        );
      },
    },
  ];

  return (
    <div>
      {/* 汇总信息 */}
      <div className={styles.summaryBar}>
        <Space>
          <span className={styles.summaryLabel}>总会话数</span>
          <span className={styles.summaryValue}>
            {data.length}
          </span>
        </Space>
        <Space>
          <span className={styles.summaryLabel}>总消耗</span>
          <span className={styles.summaryValueGreen}>
            {formatTokens(totalAll)}
          </span>
        </Space>
        <Space>
          <span className={styles.summaryLabelBlue}>Input</span>
          <span className={styles.summaryValueBlue}>
            {formatTokens(totalInput)}
          </span>
          <span className={styles.summaryPercent}>
            ({totalAll>0?((totalInput / totalAll) * 100).toFixed(1):'0'}%)
          </span>
        </Space>
        <Space>
          <span className={styles.summaryLabelGreen}>Output</span>
          <span className={styles.summaryValueGreen}>
            {formatTokens(totalOutput)}
          </span>
          <span className={styles.summaryPercent}>
            ({totalAll>0?((totalOutput / totalAll) * 100).toFixed(1):'0'}%)
          </span>
        </Space>
        <div className={styles.legendContainer}>
          <span className={styles.legendDotBlue} />
          <span className={styles.legendText}>输入</span>
          <span className={styles.legendDotGreen} />
          <span className={styles.legendText}>输出</span>
        </div>
      </div>

      {/* 表格 */}
      <div className={styles.tableWrapper}>
        <Table
          columns={columns}
          dataSource={data}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条记录`,
          }}
          size="middle"
          scroll={{ x: 1000 }}
          rowClassName={(_, index) => (index % 2 === 1 ? "alt-row" : "")}
        />
      </div>
    </div>
  );
};

export default TokenConsumption;
