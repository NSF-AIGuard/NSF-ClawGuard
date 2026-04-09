import React, { useState, useMemo } from "react";
import { Table, Tag, Input, Tooltip, Badge, Button } from "antd";
import {
  SearchOutlined,
  ReloadOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  MinusCircleOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { GatewayAuthLogRecord, GatewayAuthEventType } from "@/types/auditLog";
import { formatTime } from "../constants";
import parentStyles from "../index.module.less";
import styles from "./GatewayAuthLogTable.module.less";

interface GatewayAuthLogTableProps {
  data: GatewayAuthLogRecord[];
}

/** 事件类型映射 */
const eventTypeMap: Record<
  GatewayAuthEventType,
  { text: string; color: string; icon: React.ReactNode }
> = {
  auth_success: {
    text: "认证成功",
    color: "#52c41a",
    icon: <CheckCircleOutlined />,
  },
  auth_failed: {
    text: "认证失败",
    color: "#ff4d4f",
    icon: <CloseCircleOutlined />,
  },
  disconnected: {
    text: "已断开",
    color: "#8c8c8c",
    icon: <MinusCircleOutlined />,
  },
};

/** JSON 语法高亮 */
function highlightJson(line: string): React.ReactNode {
  const parts: React.ReactNode[] = [];
  const regex =
    /("(?:[^"\\]|\\.)*")\s*:|("(?:[^"\\]|\\.)*")|(\b(?:true|false|null)\b)|(\b\d+\.?\d*\b)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(line)) !== null) {
    if (match.index > lastIndex) {
      parts.push(line.slice(lastIndex, match.index));
    }
    if (match[1]) {
      parts.push(
        <span key={match.index} className={parentStyles.key}>
          {match[1]}
        </span>
      );
      parts.push(":");
    } else if (match[2]) {
      parts.push(
        <span key={match.index} className={parentStyles.string}>
          {match[2]}
        </span>
      );
    } else if (match[3]) {
      parts.push(
        <span key={match.index} className={parentStyles.bool}>
          {match[3]}
        </span>
      );
    } else if (match[4]) {
      parts.push(
        <span key={match.index} className={parentStyles.number}>
          {match[4]}
        </span>
      );
    }
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < line.length) {
    parts.push(line.slice(lastIndex));
  }

  return parts.length > 0 ? parts : line;
}

const GatewayAuthLogTable: React.FC<GatewayAuthLogTableProps> = ({ data }) => {
  const [searchText, setSearchText] = useState("");
  const [eventTypeFilter, setEventTypeFilter] = useState<string>("all");
  const [logLevelFilter, setLogLevelFilter] = useState<string>("all");

  // 统计数据
  const stats = useMemo(() => {
    const success = data.filter((d) => d.eventType === "auth_success").length;
    const failed = data.filter((d) => d.eventType === "auth_failed").length;
    const disconnected = data.filter((d) => d.eventType === "disconnected").length;
    return { success, failed, disconnected, total: data.length };
  }, [data]);

  const filteredData = data.filter((item) => {
    // 事件类型筛选
    if (eventTypeFilter !== "all" && item.eventType !== eventTypeFilter) return false;
    // 日志级别筛选
    if (logLevelFilter !== "all" && item.logLevel !== logLevelFilter) return false;
    // 关键字搜索
    if (searchText) {
      const text = searchText.toLowerCase();
      return (
        item.eventId.toLowerCase().includes(text) ||
        item.connId.toLowerCase().includes(text) ||
        item.remoteIp.toLowerCase().includes(text) ||
        item.client.toLowerCase().includes(text) ||
        item.eventType.toLowerCase().includes(text)
      );
    }
    return true;
  });


  const columns: ColumnsType<GatewayAuthLogRecord> = [
    {
      title: "事件ID",
      dataIndex: "eventId",
      key: "eventId",
      width: 220,
      ellipsis: true,
      render: (id) => (
        <span className={styles.idCell}>
          {id}
        </span>
      ),
    },
    {
      title: "事件类型",
      dataIndex: "eventType",
      key: "eventType",
      width: 120,
      filters: [
        { text: "认证成功", value: "auth_success" },
        { text: "认证失败", value: "auth_failed" },
        { text: "已断开", value: "disconnected" },
      ],
      onFilter: (value, record) => record.eventType === value,
      render: (type: GatewayAuthEventType) => {
        const config = eventTypeMap[type] || {
          text: type,
          color: "#999",
          icon: null,
        };
        const color = config.color;
        const r = parseInt(color.slice(1, 3), 16);
        const g = parseInt(color.slice(3, 5), 16);
        const b = parseInt(color.slice(5, 7), 16);
        return (
          <Tag
            className={styles.eventTag}
            style={{
              color,
              backgroundColor: `rgba(${r}, ${g}, ${b}, 0.3)`,
            }}
          >
            {config.text}
          </Tag>
        );
      },
    },
    {
      title: "时间",
      dataIndex: "logTimestamp",
      key: "logTimestamp",
      width: 170,
      sorter: (a, b) =>
        new Date(a.logTimestamp).getTime() - new Date(b.logTimestamp).getTime(),
      render: (time) => (
        <span className={styles.timeCell}>{formatTime(time)}</span>
      ),
    },
    {
      title: "远程IP",
      dataIndex: "remoteIp",
      key: "remoteIp",
      width: 130,
      render: (ip) => (
        <span className={styles.ipCell}>
          {ip}
        </span>
      ),
    },
    {
      title: "客户端",
      dataIndex: "client",
      key: "client",
      width: 180,
      render: (client, record) => (
        <span className={styles.clientCell}>
          <span className={styles.clientName}>{client}</span>
          {record.clientVersion && (
            <span className={styles.clientVersion}>
              v{record.clientVersion}
            </span>
          )}
        </span>
      ),
    },
    {
      title: "连接ID",
      dataIndex: "connId",
      key: "connId",
      width: 150,
      ellipsis: true,
      render: (connId) => (
        <Tooltip title={connId}>
          <span className={styles.connIdCell}>
            {connId ? connId.slice(0, 8) + "..." : "-"}
          </span>
        </Tooltip>
      ),
    },
    {
      title: "认证模式",
      dataIndex: "authMode",
      key: "authMode",
      width: 100,
      render: (mode) =>
        mode ? (
          <Tag className={styles.authModeTag}>
            {mode}
          </Tag>
        ) : (
          <span className={styles.noAuthMode}>-</span>
        ),
    },
    {
      title: "认证原因",
      dataIndex: "authReason",
      key: "authReason",
      width: 130,
      ellipsis: true,
      render: (reason, record) => {
        const displayText =
          record.disconnectReason && record.disconnectReason !== "n/a"
            ? record.disconnectReason
            : reason || "-";
        const isError =
          record.eventType === "auth_failed" ||
          (!!record.disconnectCode && record.disconnectReason && record.disconnectReason !== "n/a");
        return (
          <Tooltip title={displayText}>
            <span className={`${styles.reasonCell} ${isError ? styles.reasonError : styles.reasonDefault}`}>
              {displayText}
            </span>
          </Tooltip>
        );
      },
    },
    {
      title: "日志级别",
      dataIndex: "logLevel",
      key: "logLevel",
      width: 90,
      render: (level) => {
        const colorMap: Record<string, string> = {
          INFO: "#52c41a",
          WARN: "#faad14",
          ERROR: "#ff4d4f",
          DEBUG: "#1890ff",
        };
        const color = colorMap[level] || "#999";
        return (
          <Tag
            style={{
              borderColor: color,
              color,
              background: `${color}10`,
            }}
          >
            {level || "-"}
          </Tag>
        );
      },
    },
  ];

  return (
    <div>
      {/* 统计概览 + 筛选栏 */}
      <div className={styles.statsBar}>
        {/* 左侧：统计概览 */}
        <div className={styles.statsLeft}>
          <div className={styles.statItem}>
            <Badge status="success" />
            <span className={styles.statLabel}>认证成功</span>
            <span className={styles.statValueSuccess}>
              {stats.success}
            </span>
          </div>
          <div className={styles.statItem}>
            <Badge status="error" />
            <span className={styles.statLabel}>认证失败</span>
            <span className={styles.statValueDanger}>
              {stats.failed}
            </span>
          </div>
          <div className={styles.statItem}>
            <Badge status="default" />
            <span className={styles.statLabel}>已断开</span>
            <span className={styles.statValueDefault}>
              {stats.disconnected}
            </span>
          </div>
          <div className={styles.statItem}>
            <span className={styles.statLabel}>总计</span>
            <span className={styles.statValuePrimary}>
              {stats.total}
            </span>
          </div>
        </div>

        {/* 右侧：筛选栏 */}
        <div className={styles.filterRight}>
          <Input
            placeholder="搜索事件ID、IP、客户端"
            suffix={<SearchOutlined />}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            className={styles.searchInput}
            allowClear
            size="middle"
          />
          <Tooltip title="重置筛选">
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                setSearchText("");
                setEventTypeFilter("all");
                setLogLevelFilter("all");
              }}
            />
          </Tooltip>
        </div>
      </div>

      {/* 表格 */}
      <div className={styles.tableWrapper}>
        <Table
          columns={columns}
          dataSource={filteredData}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条记录`,
            showQuickJumper: true,
          }}
          size="middle"
          scroll={{ x: 1300 }}
          rowClassName={(record) =>
            record.eventType === "auth_failed"
              ? "failure-row"
              : record.eventType === "disconnected"
                ? "timeout-row"
                : ""
          }
          expandable={{
            expandedRowRender: (record) => (
              <div className={styles.expandedRow}>
                <div className={styles.expandedContent}>
                  {/* 基本信息 */}
                  <div className={styles.expandedSection}>
                    <div className={styles.expandedTitle}>
                      📋 详细信息
                    </div>
                    <div className={parentStyles.auditLogTerminal}>
                      <div className={parentStyles.terminalContent}>
                        {[
                          { label: "连接ID", value: record.connId },
                          { label: "远程IP", value: record.remoteIp },
                          { label: "客户端", value: `${record.client} v${record.clientVersion}` },
                          { label: "认证模式", value: record.authMode || "-" },
                          { label: "认证原因", value: record.authReason || "-" },
                          { label: "子系统", value: record.subsystem || "-" },
                          { label: "运行时", value: `${record.runtime} ${record.runtimeVersion}` },
                          { label: "主机名", value: record.hostname || "-" },
                          ...(record.disconnectCode
                            ? [{ label: "断开码", value: record.disconnectCode }]
                            : []),
                          ...(record.disconnectReason && record.disconnectReason !== "n/a"
                            ? [{ label: "断开原因", value: record.disconnectReason }]
                            : []),
                        ].map((item, i) => (
                          <div key={i} className={parentStyles.terminalLine}>
                            <span className={parentStyles.lineNumber}>{i + 1}</span>
                            <span className={parentStyles.lineContent}>
                              <span className={parentStyles.key}>"{item.label}"</span>
                              {": "}
                              <span className={parentStyles.string}>"{item.value}"</span>
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  {/* 原始日志 */}
                  {record.rawLine && (
                    <div className={styles.expandedSection}>
                      <div className={styles.expandedTitle}>
                        📄 原始日志
                      </div>
                      <div className={parentStyles.auditLogTerminal}>
                        <div className={parentStyles.terminalContent}>
                          {record.rawLine.split("\\n").map((line, i) => (
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
                </div>
              </div>
            ),
            rowExpandable: (record) =>
              !!(record.connId || record.rawLine),
          }}
        />
      </div>
    </div>
  );
};

export default GatewayAuthLogTable;