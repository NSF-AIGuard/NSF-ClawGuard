/**
 * SQLite 数据库模块
 *
 * 统一管理所有持久化存储，替代原有的 CSV 方案。
 * 使用 sql.js（纯 JavaScript 实现），无需编译原生模块。
 *
 * 数据表：
 *   - security_events    安全事件（配置扫描、命令拦截、内容审查等）
 *   - token_usage        Token 使用量记录
 *   - tool_call          工具调用记录
 *   - gateway_auth_logs  Gateway 认证日志
 */

import initSqlJs, {
  type BindParams,
  type Database as SqlJsDatabase,
} from "sql.js";
// @ts-ignore — Vite/tsup 会将 wasm 文件以 base64 字符串形式内联
import wasmBase64 from "sql.js/dist/sql-wasm.wasm";
import * as path from "path";
import * as fs from "fs";
import { currentPluginRoot } from "./utils.js";

// ═══════════════════════════════════════════════════════════════
// 模块级状态
// ═══════════════════════════════════════════════════════════════

/** 单例数据库实例 */
let _db: SqlJsDatabase | null = null;

/** 数据库文件路径 */
let _dbPath = "";

/** sql.js 初始化 Promise（防止并发初始化） */
let _sqlPromise: Promise<void> | null = null;

// ═══════════════════════════════════════════════════════════════
// 数据库初始化 & 持久化
// ═══════════════════════════════════════════════════════════════

/**
 * 将 base64 编码的 WASM 二进制转换为 ArrayBuffer
 * sql.js 需要 ArrayBuffer 格式来初始化
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * 初始化 sql.js 并打开（或创建）数据库文件
 *
 * - Node 环境下从内联的 base64 WASM 加载，无需额外文件
 * - 浏览器环境下从 CDN 加载 WASM
 * - 数据库文件位于 `<pluginRoot>/data/lm-security.db`
 */
async function initSql(): Promise<void> {
  if (_db) return;

  const isNode = typeof process !== "undefined" && process.versions?.node;

  const SQL = isNode
    ? await initSqlJs({ wasmBinary: base64ToArrayBuffer(wasmBase64) })
    : await initSqlJs({ locateFile: (f: string) => `https://sql.js.org/dist/${f}` });

  // 确保数据目录存在
  const dbDir = path.join(currentPluginRoot(), "data");
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  _dbPath = path.join(dbDir, "lm-security.db");

  // 若已有数据库文件则从磁盘加载，否则创建空数据库
  _db = fs.existsSync(_dbPath)
    ? new SQL.Database(fs.readFileSync(_dbPath))
    : new SQL.Database();

  initTables(_db);
  saveDb();
}

/**
 * 将内存中的数据库持久化到磁盘
 * 每次写操作后调用，确保数据不丢失
 */
function saveDb(): void {
  if (!_db || !_dbPath) return;
  const data = _db.export();
  fs.writeFileSync(_dbPath, Buffer.from(data));
}

// ═══════════════════════════════════════════════════════════════
// 建表 & 索引
// ═══════════════════════════════════════════════════════════════

/** 安全事件表 DDL */
const DDL_SECURITY_EVENTS = `
  CREATE TABLE IF NOT EXISTS security_events (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id                TEXT NOT NULL,
    category                TEXT NOT NULL,
    sub_category            TEXT NOT NULL,
    sub_category_description TEXT NOT NULL,
    threat_level            TEXT NOT NULL,
    event_time              TEXT NOT NULL,
    recommendation          TEXT NOT NULL,
    event_info              TEXT NOT NULL
  )`;

/** Token 使用量表 DDL */
const DDL_TOKEN_USAGE = `
  CREATE TABLE IF NOT EXISTS token_usage (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            TEXT NOT NULL,
    session_key         TEXT NOT NULL,
    agent_id            TEXT NOT NULL,
    model               TEXT NOT NULL,
    input_tokens        INTEGER NOT NULL,
    output_tokens       INTEGER NOT NULL,
    total_tokens        INTEGER NOT NULL,
    cache_read_tokens   INTEGER NOT NULL,
    cache_write_tokens  INTEGER NOT NULL,
    event_time          TEXT NOT NULL,
    extra_info          TEXT NOT NULL
  )`;

/** 工具调用表 DDL */
const DDL_TOOL_CALL = `
  CREATE TABLE IF NOT EXISTS tool_call (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL,
    session_key     TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    tool_call_id    TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    params          TEXT NOT NULL,
    result          TEXT NOT NULL,
    is_success      INTEGER NOT NULL,
    error_message   TEXT NOT NULL,
    duration_ms     INTEGER NOT NULL,
    event_time      TEXT NOT NULL
  )`;

/** Gateway 认证日志表 DDL */
const DDL_GATEWAY_AUTH_LOGS = `
  CREATE TABLE IF NOT EXISTS gateway_auth_logs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id           TEXT NOT NULL,
    event_type         TEXT NOT NULL,
    log_timestamp      TEXT NOT NULL,
    conn_id            TEXT NOT NULL,
    remote_ip          TEXT NOT NULL,
    client             TEXT NOT NULL,
    client_version     TEXT NOT NULL,
    disconnect_code    TEXT NOT NULL,
    disconnect_reason  TEXT NOT NULL,
    auth_mode          TEXT NOT NULL,
    auth_reason        TEXT NOT NULL,
    user_agent         TEXT NOT NULL,
    subsystem          TEXT NOT NULL,
    log_level          TEXT NOT NULL,
    runtime            TEXT NOT NULL,
    runtime_version    TEXT NOT NULL,
    hostname           TEXT NOT NULL,
    log_file           TEXT NOT NULL,
    raw_line           TEXT NOT NULL
  )`;

/** 索引定义：为高频查询字段建立索引 */
const DDL_INDEXES = [
  // security_events 索引
  "CREATE INDEX IF NOT EXISTS idx_security_event_time    ON security_events(event_time)",
  "CREATE INDEX IF NOT EXISTS idx_security_category      ON security_events(category)",
  "CREATE INDEX IF NOT EXISTS idx_security_sub_category  ON security_events(sub_category)",
  // token_usage 索引
  "CREATE INDEX IF NOT EXISTS idx_token_event_time       ON token_usage(event_time)",
  "CREATE INDEX IF NOT EXISTS idx_token_session          ON token_usage(session_key)",
  // tool_call 索引
  "CREATE INDEX IF NOT EXISTS idx_tool_event_time        ON tool_call(event_time)",
  "CREATE INDEX IF NOT EXISTS idx_tool_session           ON tool_call(session_key)",
  "CREATE INDEX IF NOT EXISTS idx_tool_tool_name         ON tool_call(tool_name)",
  // gateway_auth_logs 索引
  "CREATE INDEX IF NOT EXISTS idx_gw_event_type          ON gateway_auth_logs(event_type)",
  "CREATE INDEX IF NOT EXISTS idx_gw_conn_id             ON gateway_auth_logs(conn_id)",
  "CREATE INDEX IF NOT EXISTS idx_gw_log_timestamp       ON gateway_auth_logs(log_timestamp)",
];

/**
 * 执行建表和索引创建
 * 使用 IF NOT EXISTS 保证幂等
 */
function initTables(db: SqlJsDatabase): void {
  const ddlList = [
    DDL_SECURITY_EVENTS,
    DDL_TOKEN_USAGE,
    DDL_TOOL_CALL,
    DDL_GATEWAY_AUTH_LOGS,
  ];

  for (const ddl of ddlList) {
    try {
      db.run(ddl);
    } catch (err) {
      console.error("[DB] 建表失败:", err);
    }
  }

  for (const indexDdl of DDL_INDEXES) {
    try {
      db.run(indexDdl);
    } catch (err) {
      console.error("[DB] 建索引失败:", err);
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// 通用查询 & 插入工具函数
// ═══════════════════════════════════════════════════════════════

/**
 * 通用条件查询
 *
 * 根据提供的条件列表动态构建 WHERE 子句，返回查询结果。
 * 条件列表中值为 undefined / null / "" 的条目会被自动跳过。
 *
 * @param table       - 目标表名
 * @param conditions  - 筛选条件列表，每项为 [字段值, 列名]
 * @param timeColumn  - 时间范围过滤所使用的列名
 * @param startTime   - 起始时间（>=），可选
 * @param endTime     - 结束时间（<=），可选
 * @param limit       - 最大返回条数，默认 100
 * @returns 符合条件的记录数组
 */
function queryWithFilter(
  table: string,
  conditions: Array<[unknown, string]>,
  timeColumn: string,
  startTime?: string,
  endTime?: string,
  limit: number = 100,
): Array<Record<string, unknown>> {
  const db = getDb();

  // 动态构建 WHERE 子句
  let sql = `SELECT * FROM ${table} WHERE 1=1`;
  const params: unknown[] = [];

  // 追加等值条件（跳过空值）
  for (const [value, column] of conditions) {
    if (value !== undefined && value !== null && value !== "") {
      sql += ` AND ${column} = ?`;
      params.push(value);
    }
  }

  // 追加时间范围条件
  if (startTime) {
    sql += ` AND ${timeColumn} >= ?`;
    params.push(startTime);
  }
  if (endTime) {
    sql += ` AND ${timeColumn} <= ?`;
    params.push(endTime);
  }

  // 按主键倒序，限制返回条数
  sql += " ORDER BY id DESC LIMIT ?";
  params.push(limit);

  // 执行查询并收集结果
  const stmt = db.prepare(sql);
  stmt.bind(params as BindParams);
  const results: Array<Record<string, unknown>> = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject() as Record<string, unknown>);
  }
  stmt.free();

  return results;
}

/**
 * 通用插入操作
 *
 * 执行 INSERT 语句后自动持久化到磁盘。
 *
 * @param sql    - INSERT SQL 语句（含占位符）
 * @param params - 绑定参数
 */
async function executeInsert(sql: string, params: BindParams): Promise<void> {
  const db = await ensureDb();
  db.run(sql, params);
  saveDb();
}

// ═══════════════════════════════════════════════════════════════
// 数据库连接管理
// ═══════════════════════════════════════════════════════════════

/**
 * 确保数据库已初始化（懒加载 + 防重入）
 * 所有数据库操作的入口点
 */
export async function ensureDb(): Promise<SqlJsDatabase> {
  if (!_db) {
    if (!_sqlPromise) {
      _sqlPromise = initSql();
    }
    await _sqlPromise;
  }
  return _db!;
}

/**
 * 获取已初始化的数据库实例（同步版本）
 * 仅在确认数据库已初始化后使用，否则抛出异常
 */
function getDb(): SqlJsDatabase {
  if (!_db) {
    throw new Error("Database not initialized. Call ensureDb() first.");
  }
  return _db;
}

/**
 * 关闭数据库连接并持久化
 */
export async function dbClose(): Promise<void> {
  if (_db) {
    saveDb();
    _db.close();
    _db = null;
    _sqlPromise = null;
  }
}

/**
 * 获取数据库文件路径
 * 会在需要时自动初始化数据库
 */
export async function dbGetDBPath(): Promise<string> {
  await ensureDb();
  return _dbPath;
}

// ═══════════════════════════════════════════════════════════════
// security_events 表操作
// ═══════════════════════════════════════════════════════════════

const INSERT_SECURITY_EVENT = `
  INSERT INTO security_events
    (event_id, category, sub_category, sub_category_description, threat_level, event_time, recommendation, event_info)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`;

/** 插入一条安全事件 */
export async function dbInsertSecurityEvent(
  eventId: string,
  category: string,
  subCategory: string,
  subCategoryDescription: string,
  threatLevel: string,
  eventTime: string,
  recommendation: string,
  eventInfo: string,
): Promise<void> {
  await executeInsert(INSERT_SECURITY_EVENT, [
    eventId, category, subCategory, subCategoryDescription,
    threatLevel, eventTime, recommendation, eventInfo,
  ]);
}

/** 按条件查询安全事件 */
export async function dbQuerySecurityEvents(filter: {
  category?: string;
  subCategory?: string;
  threatLevel?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
}): Promise<Array<Record<string, unknown>>> {
  return queryWithFilter(
    "security_events",
    [
      [filter.category, "category"],
      [filter.subCategory, "sub_category"],
      [filter.threatLevel, "threat_level"],
    ],
    "event_time",
    filter.startTime,
    filter.endTime,
    filter.limit,
  );
}

// ═══════════════════════════════════════════════════════════════
// token_usage 表操作
// ═══════════════════════════════════════════════════════════════

const INSERT_TOKEN_USAGE = `
  INSERT INTO token_usage
    (event_id, session_key, agent_id, model, input_tokens, output_tokens, total_tokens, cache_read_tokens, cache_write_tokens, event_time, extra_info)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

/** 插入一条 Token 使用量记录 */
export async function dbInsertTokenUsage(
  eventId: string,
  sessionKey: string,
  agentId: string,
  model: string,
  inputTokens: number,
  outputTokens: number,
  totalTokens: number,
  cacheReadTokens: number,
  cacheWriteTokens: number,
  eventTime: string,
  extraInfo: string,
): Promise<void> {
  await executeInsert(INSERT_TOKEN_USAGE, [
    eventId, sessionKey, agentId, model,
    inputTokens, outputTokens, totalTokens,
    cacheReadTokens, cacheWriteTokens, eventTime, extraInfo,
  ]);
}

/** 按条件查询 Token 使用量 */
export async function dbQueryTokenUsage(filter: {
  sessionKey?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
}): Promise<Array<Record<string, unknown>>> {
  return queryWithFilter(
    "token_usage",
    [[filter.sessionKey, "session_key"]],
    "event_time",
    filter.startTime,
    filter.endTime,
    filter.limit,
  );
}

// ═══════════════════════════════════════════════════════════════
// tool_call 表操作
// ═══════════════════════════════════════════════════════════════

const INSERT_TOOL_CALL = `
  INSERT INTO tool_call
    (event_id, session_key, agent_id, run_id, tool_call_id, tool_name, params, result, is_success, error_message, duration_ms, event_time)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

/** 插入一条工具调用记录 */
export async function dbInsertToolCall(
  eventId: string,
  sessionKey: string,
  agentId: string,
  runId: string,
  toolCallId: string,
  toolName: string,
  params: string,
  result: string,
  isSuccess: boolean,
  errorMessage: string,
  durationMs: number,
  eventTime: string,
): Promise<void> {
  await executeInsert(INSERT_TOOL_CALL, [
    eventId, sessionKey, agentId, runId, toolCallId, toolName,
    params, result, isSuccess ? 1 : 0, errorMessage, durationMs, eventTime,
  ]);
}

/** 按条件查询工具调用记录 */
export async function dbQueryToolCall(filter: {
  sessionKey?: string;
  toolName?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
}): Promise<Array<Record<string, unknown>>> {
  return queryWithFilter(
    "tool_call",
    [
      [filter.sessionKey, "session_key"],
      [filter.toolName, "tool_name"],
    ],
    "event_time",
    filter.startTime,
    filter.endTime,
    filter.limit,
  );
}

// ═══════════════════════════════════════════════════════════════
// gateway_auth_logs 表操作
// ═══════════════════════════════════════════════════════════════

const INSERT_GW_AUTH_LOG = `
  INSERT INTO gateway_auth_logs
    (event_id, event_type, log_timestamp, conn_id, remote_ip, client, client_version,
     disconnect_code, disconnect_reason, auth_mode, auth_reason, user_agent,
     subsystem, log_level, runtime, runtime_version, hostname, log_file, raw_line)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

/** 插入一条 Gateway 认证日志 */
export async function dbInsertGWAuthLog(
  eventId: string,
  eventType: string,
  logTimestamp: string,
  connId: string,
  remoteIp: string,
  client: string,
  clientVersion: string,
  disconnectCode: string,
  disconnectReason: string,
  authMode: string,
  authReason: string,
  userAgent: string,
  subsystem: string,
  logLevel: string,
  runtime: string,
  runtimeVersion: string,
  hostname: string,
  logFile: string,
  rawLine: string,
): Promise<void> {
  await executeInsert(INSERT_GW_AUTH_LOG, [
    eventId, eventType, logTimestamp, connId, remoteIp, client, clientVersion,
    disconnectCode, disconnectReason, authMode, authReason, userAgent,
    subsystem, logLevel, runtime, runtimeVersion, hostname, logFile, rawLine,
  ]);
}

/** 按条件查询 Gateway 认证日志 */
export async function dbQueryGWAuthLogs(filter: {
  eventType?: string;
  connId?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
}): Promise<Array<Record<string, unknown>>> {
  return queryWithFilter(
    "gateway_auth_logs",
    [
      [filter.eventType, "event_type"],
      [filter.connId, "conn_id"],
    ],
    "log_timestamp",
    filter.startTime,
    filter.endTime,
    filter.limit,
  );
}

// ═══════════════════════════════════════════════════════════════
// 统计
// ═══════════════════════════════════════════════════════════════

/** 需要统计的表名列表 */
const STATS_TABLES = [
  "security_events",
  "token_usage",
  "tool_call",
  "gateway_auth_logs",
] as const;

type StatsTableName = (typeof STATS_TABLES)[number];

/** 各表记录数统计结果 */
export type DbStatsResult = Record<StatsTableName, number>;

/**
 * 获取各数据表的记录总数
 * 用于 Dashboard 概览面板展示
 */
export async function dbGetStats(): Promise<DbStatsResult> {
  const db = await ensureDb();
  const results = {} as DbStatsResult;

  for (const table of STATS_TABLES) {
    try {
      const stmt = db.prepare(`SELECT COUNT(*) as count FROM ${table}`);
      if (stmt.step()) {
        const row = stmt.getAsObject() as { count: number };
        results[table] = row.count;
      }
      stmt.free();
    } catch {
      results[table] = 0;
    }
  }

  return results;
}