import React, { useState, useEffect, useCallback } from "react";
import { Table, Tag, Input, Tooltip, Badge, Progress, Button } from "antd";
import {
  SearchOutlined,
  ReloadOutlined,
  ThunderboltOutlined
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { ToolCallRecord } from "@/types/auditLog";
import { getToolCallList } from "@/api/auditLog";
import { formatTime } from "../constants";
import parentStyles from "../index.module.less";
import styles from "./ToolCallTable.module.less";

const ToolCallTable: React.FC = () => {
  const [data, setData] = useState<ToolCallRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [loading, setLoading] = useState(false);
  const [filteredStatus, setFilteredStatus] = useState<boolean | null>(null);
  const [filteredAction, setFilteredAction] = useState<string | null>(null);
  const [searchText, setSearchText] = useState("");

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, unknown> = { page, pageSize };
      if (searchText) params.search = searchText;
      if (filteredStatus !== null) params.isSuccess = filteredStatus;
      if (filteredAction !== null) params.action = filteredAction;

      const res = await getToolCallList(params as any);
      setData(res.items || []);
      setTotal(res.total || 0);
    } catch (error) {
      console.error("加载工具调用数据失败:", error);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, searchText, filteredStatus, filteredAction]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // 统计数据（基于当前页）
  const stats = {
    success: data.filter((d) => d.isSuccess).length,
    failure: data.filter((d) => !d.isSuccess).length,
    avgDuration:
      data.length > 0
        ? Math.round(data.reduce((sum, d) => sum + d.callTime, 0) / data.length)
        : 0,
    total: data.length,
  };

  const columns: ColumnsType<ToolCallRecord> = [
    {
      title: "ID",
      dataIndex: "id",
      key: "id",
      width: 180,
      ellipsis: true,
      render: (id) => (
        <span className={styles.idCell}>
          {id}
        </span>
      ),
    },
    {
      title: "工具名称",
      dataIndex: "toolName",
      key: "toolName",
      width: 200,
      render: (name) => (
        <span className={styles.toolNameCell}>
          <ThunderboltOutlined className={styles.toolIcon} />
          {name}
        </span>
      ),
    },
    {
      title: "调用时间",
      dataIndex: "startTime",
      key: "startTime",
      width: 170,
      render: (time) => (
        <span className={styles.timeCell}>{formatTime(time)}</span>
      ),
    },
    {
      title: "状态",
      dataIndex: "isSuccess",
      key: "isSuccess",
      width: 90,
      filters: [
        { text: "成功", value: true },
        { text: "失败", value: false },
      ],
      filterMultiple: false,
      onFilter: (value, record) => record.isSuccess === value,
      render: (isSuccess: boolean) => (
        <Tag
          className={`${styles.statusTag} ${isSuccess ? styles.statusSuccess : styles.statusFailure}`}
        >
          {isSuccess ? "成功" : "失败"}
        </Tag>
      ),
    },
    {
      title: "是否阻断",
      dataIndex: "action",
      key: "action",
      width: 90,
      filters: [
        { text: "是", value: "block" },
        { text: "否", value: "allow" },
      ],
      filterMultiple: false,
      onFilter: (value, record) => record.action === value,
      render: (action: string) => {
        if (action === "block") {
          return <Tag color="red">是</Tag>;
        }
        return <Tag color="green">否</Tag>;
      },
    },
    {
      title: "耗时",
      dataIndex: "callTime",
      key: "callTime",
      width: 100,
      sorter: (a, b) => a.callTime - b.callTime,
      render: (dur) => {
        const durationClass =
          dur > 3000 ? styles.durationSlow : dur > 1500 ? styles.durationMedium : styles.durationFast;
        return (
          <span className={`${styles.durationCell} ${durationClass}`}>
            {dur}ms
          </span>
        );
      },
    },
    {
      title: "会话ID",
      dataIndex: "sessionId",
      key: "sessionId",
      width: 130,
      render: (sid) => (
        <span className={styles.sessionIdCell}>
          {sid}
        </span>
      ),
    },
    {
      title: "错误信息",
      dataIndex: "errorMessage",
      key: "errorMessage",
      ellipsis: true,
      render: (msg) => (
        <Tooltip title={msg}>
          <span className={`${styles.errorCell} ${msg ? styles.hasError : styles.noError}`}>
            {msg || "-"}
          </span>
        </Tooltip>
      ),
    },
  ];

  const successRate =
    stats.total > 0 ? ((stats.success / stats.total) * 100).toFixed(1) : "0";

  return (
    <div>
      {/* 统计概览 + 筛选栏（同一行：左统计，右筛选） */}
      <div className={styles.statsBar}>
        {/* 左侧：统计概览 */}
        <div className={styles.statsLeft}>
          <div className={styles.statItem}>
            <Badge status="success" />
            <span className={styles.statLabel}>成功</span>
            <span className={styles.statValueSuccess}>
              {stats.success}
            </span>
          </div>
          <div className={styles.statItem}>
            <Badge status="error" />
            <span className={styles.statLabel}>失败</span>
            <span className={styles.statValueDanger}>
              {stats.failure}
            </span>
          </div>
          <div className={styles.statItem}>
            <span className={styles.statLabel}>成功率</span>
            <Progress
              percent={parseFloat(successRate)}
              size="small"
              strokeColor="#55a722"
              style={{ width: 120, marginBottom: 0 }}
              format={(percent) => (
                <span className={styles.progressPercent}>
                  {percent}%
                </span>
              )}
            />
          </div>
          <div className={styles.statItem}>
            <span className={styles.statLabel}>平均耗时</span>
            <span className={styles.statValueDefault}>
              {stats.avgDuration}ms
            </span>
          </div>
        </div>

        {/* 右侧：筛选栏 */}
        <div className={styles.filterRight}>
          <Input
            placeholder="搜索工具名称、调用ID"
            suffix={<SearchOutlined />}
            value={searchText}
            onChange={(e) => {
              setSearchText(e.target.value);
              setPage(1);
            }}
            className={styles.searchInput}
            allowClear
            size="middle"
          />
          <Tooltip title="刷新">
            <Button
              icon={<ReloadOutlined spin={loading} />}
              onClick={fetchData}
              loading={loading}
            />
          </Tooltip>
        </div>
      </div>

      {/* 表格 */}
      <div className={styles.tableWrapper}>
        <Table
          columns={columns}
          dataSource={data}
          loading={loading}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条记录`,
            showQuickJumper: true,
          }}
          onChange={(pagination, filters) => {
            setPage(pagination.current || 1);
            setPageSize(pagination.pageSize || 10);
            const statusVal = filters.isSuccess as boolean[] | undefined;
            if (statusVal && statusVal.length === 1) {
              setFilteredStatus(statusVal[0]);
            } else {
              setFilteredStatus(null);
            }
            const actionVal = filters.action as string[] | undefined;
            if (actionVal && actionVal.length === 1) {
              setFilteredAction(actionVal[0]);
            } else {
              setFilteredAction(null);
            }
          }}
          size="middle"
          scroll={{ x: 1100 }}
          rowClassName={(record) => (record.isSuccess ? "" : "failure-row")}
          expandable={{
            expandedRowRender: (record) => (
              <div className={styles.expandedRow}>
                <div className={styles.expandedContent}>
                  {record.inputParams && (
                    <div className={styles.expandedSection}>
                      <div className={styles.expandedTitle}>
                        📥 输入参数
                      </div>
                      <div className={parentStyles.auditLogTerminal}>
                        <div className={parentStyles.terminalContent}>
                          {record.inputParams.split("\n").map((line, i) => (
                            <div key={i} className={parentStyles.terminalLine}>
                              <span className={parentStyles.lineNumber}>{i + 1}</span>
                              <span className={parentStyles.lineContent}>
                                {highlightJson(line)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                  {record.outputResult && (
                    <div className={styles.expandedSection}>
                      <div className={styles.expandedTitle}>
                        📤 执行结果
                      </div>
                      <div className={parentStyles.auditLogTerminal}>
                        <div className={parentStyles.terminalContent}>
                          {record.outputResult.split("\n").map((line, i) => (
                            <div key={i} className={parentStyles.terminalLine}>
                              <span className={parentStyles.lineNumber}>{i + 1}</span>
                              <span className={parentStyles.lineContent}>
                                {highlightJson(line)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                  {record.errorMessage && (
                    <div className={styles.expandedSection}>
                      <div className={styles.expandedTitleError}>
                        ⚠️ 错误信息
                      </div>
                      <div className={parentStyles.auditLogTerminal}>
                        <div className={parentStyles.terminalContent}>
                          <span className={styles.errorMessageText}>
                            {record.errorMessage}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ),
            rowExpandable: (record) =>
              !!(
                record.inputParams ||
                record.outputResult ||
                record.errorMessage
              ),
          }}
        />
      </div>
    </div>
  );
};

/** JSON 语法高亮 */
function highlightJson(line: string): React.ReactNode {
  const parts: React.ReactNode[] = [];
  const regex =
    /("(?:[^"\\]|\\.)*")\s*:|("(?:[^"\\]|\\.)*")|(\b(?:true|false|null)\b)|(\b\d+\.?\d*\b)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(line)) !== null) {
    // 添加匹配前的文本
    if (match.index > lastIndex) {
      parts.push(line.slice(lastIndex, match.index));
    }
    if (match[1]) {
      // key
      parts.push(
        <span key={match.index} className={parentStyles.key}>
          {match[1]}
        </span>,
      );
      parts.push(":");
    } else if (match[2]) {
      // string value
      parts.push(
        <span key={match.index} className={parentStyles.string}>
          {match[2]}
        </span>,
      );
    } else if (match[3]) {
      // boolean/null
      parts.push(
        <span key={match.index} className={parentStyles.bool}>
          {match[3]}
        </span>,
      );
    } else if (match[4]) {
      // number
      parts.push(
        <span key={match.index} className={parentStyles.number}>
          {match[4]}
        </span>,
      );
    }
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < line.length) {
    parts.push(line.slice(lastIndex));
  }

  return parts.length > 0 ? parts : line;
}

export default ToolCallTable;