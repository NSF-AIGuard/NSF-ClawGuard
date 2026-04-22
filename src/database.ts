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
// tsup 打包时通过 define 注入，生产环境为 true，开发环境为 undefined
declare const __BUNDLED__: boolean | undefined;

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

  let SQL;
  if (isNode) {
    let wasmBinary: ArrayBuffer;

    if (typeof __BUNDLED__ !== "undefined" && __BUNDLED__) {
      // 生产环境：tsup 已将 WASM 文件内联为 base64 字符串，动态导入仅在打包时生效
      // @ts-ignore
      const { default: wasmBase64 } = await import("sql.js/dist/sql-wasm.wasm");
      wasmBinary = base64ToArrayBuffer(wasmBase64);
    } else {
      // 开发环境：从 node_modules 直接读取 WASM 文件
      const { createRequire } = await import("module");
      const require = createRequire(import.meta.url);
      const sqlJsDir = path.dirname(require.resolve("sql.js"));
      const wasmPath = path.join(sqlJsDir, "sql-wasm.wasm");
      const buf = fs.readFileSync(wasmPath);
      wasmBinary = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    }

    SQL = await initSqlJs({ wasmBinary });
  } else {
    SQL = await initSqlJs({
      locateFile: (f: string) => `https://sql.js.org/dist/${f}`,
    });
  }

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
    event_info              TEXT NOT NULL,
    source                  TEXT NOT NULL DEFAULT 'local',
    action                  TEXT NOT NULL DEFAULT ''
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
    event_time      TEXT NOT NULL,
    action          TEXT NOT NULL DEFAULT ''
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

/** 策略版本配置表 DDL */
const DDL_policy_config = `
  CREATE TABLE IF NOT EXISTS policy_config (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_version          TEXT NOT NULL,
    skill_check_enabled    INTEGER NOT NULL DEFAULT 1,
    command_check_enabled  INTEGER NOT NULL DEFAULT 1,
    config_check_enabled  INTEGER NOT NULL DEFAULT 1,
    block_on_violation    INTEGER NOT NULL DEFAULT 0,
    extra_command_blacklist TEXT NOT NULL DEFAULT '',
    skill_id_blacklist     TEXT NOT NULL DEFAULT '',
    llm_mode             TEXT NOT NULL DEFAULT '',
    llm_proxy            TEXT NOT NULL DEFAULT '',
    onboard_command      TEXT NOT NULL DEFAULT '',
    needSetLLM           INTEGER NOT NULL DEFAULT 0,
    updated_at           TEXT NOT NULL,
    previous_model       TEXT NOT NULL DEFAULT '',
    heartbeat_interval   INTEGER NOT NULL DEFAULT 30
  )`;

/** 默认模型配置表 DDL */
const DDL_DEFAULT_MODEL_CONFIG = `
  CREATE TABLE IF NOT EXISTS default_model_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`;

/** 索引定义：为高频查询字段建立索引 */
const DDL_INDEXES = [
  // security_events 索引
  "CREATE INDEX IF NOT EXISTS idx_security_event_time    ON security_events(event_time)",
  "CREATE INDEX IF NOT EXISTS idx_security_category      ON security_events(category)",
  "CREATE INDEX IF NOT EXISTS idx_security_sub_category  ON security_events(sub_category)",
  "CREATE INDEX IF NOT EXISTS idx_security_dedup         ON security_events(event_id)",
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
    DDL_policy_config,
    DDL_DEFAULT_MODEL_CONFIG,
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

  // 数据库迁移：为已存在的 security_events 表添加 source 列
  try {
    const checkColumnSql = "SELECT source FROM security_events LIMIT 1";
    db.run(checkColumnSql);
  } catch (err) {
    // 列不存在，添加它
    try {
      db.run("ALTER TABLE security_events ADD COLUMN source TEXT NOT NULL DEFAULT 'local'");
      console.log("[DB] 迁移: 已为 security_events 表添加 source 列");
    } catch (alterErr) {
      console.error("[DB] 迁移失败:", alterErr);
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
  idAfter?: number,
  offset?: number,
  likeConditions?: Array<[string, string]>,
  /** OR 模糊搜索：传入 [搜索词, [列名列表]]，生成 (col1 LIKE ? OR col2 LIKE ?) */
  searchOr?: [string, string[]],
  /** 排序方向，默认 "DESC" */
  sortOrder?: "ASC" | "DESC",
): Array<Record<string, unknown>> {
  const db = getDb();

  // 动态构建 WHERE 子句
  let sql = `SELECT * FROM ${table} WHERE 1=1`;
  const params: unknown[] = [];
  if (idAfter !== undefined) {
    sql += " AND id > ?";
    params.push(idAfter);
  }

  // 追加等值条件（跳过空值）
  for (const [value, column] of conditions) {
    if (value !== undefined && value !== null && value !== "") {
      sql += ` AND ${column} = ?`;
      params.push(value);
    }
  }

  // 追加模糊匹配条件（LIKE AND）
  for (const [value, column] of likeConditions || []) {
    if (value !== undefined && value !== null && value !== "") {
      sql += ` AND ${column} LIKE ?`;
      params.push(`%${value}%`);
    }
  }

  // 追加 OR 模糊搜索条件：AND (col1 LIKE ? OR col2 LIKE ?)
  if (searchOr && searchOr[0] && searchOr[1].length > 0) {
    const [term, columns] = searchOr;
    const likeClauses = columns.map((col) => `${col} LIKE ?`).join(" OR ");
    sql += ` AND (${likeClauses})`;
    for (const _col of columns) {
      params.push(`%${term}%`);
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

  // 按时间排列，限制返回条数
  const order = sortOrder === "ASC" ? "ASC" : "DESC";
  sql += ` ORDER BY ${timeColumn} ${order} LIMIT ?`;
  params.push(limit);

  // 追加偏移量（分页）
  if (offset !== undefined && offset > 0) {
    sql += " OFFSET ?";
    params.push(offset);
  }

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
 * 通用计数查询
 *
 * 与 queryWithFilter 使用相同的筛选逻辑，但返回匹配记录总数。
 *
 * @param table           - 目标表名
 * @param conditions      - 等值筛选条件列表
 * @param timeColumn      - 时间列名
 * @param startTime       - 起始时间（>=），可选
 * @param endTime         - 结束时间（<=），可选
 * @param likeConditions  - 模糊匹配条件列表，可选
 * @returns 匹配的记录总数
 */
function countWithFilter(
  table: string,
  conditions: Array<[unknown, string]>,
  timeColumn: string,
  startTime?: string,
  endTime?: string,
  likeConditions?: Array<[string, string]>,
  /** OR 模糊搜索：传入 [搜索词, [列名列表]]，生成 (col1 LIKE ? OR col2 LIKE ?) */
  searchOr?: [string, string[]],
): number {
  const db = getDb();

  let sql = `SELECT COUNT(*) as total FROM ${table} WHERE 1=1`;
  const params: unknown[] = [];

  // 追加等值条件
  for (const [value, column] of conditions) {
    if (value !== undefined && value !== null && value !== "") {
      sql += ` AND ${column} = ?`;
      params.push(value);
    }
  }

  // 追加模糊匹配条件
  for (const [value, column] of likeConditions || []) {
    if (value !== undefined && value !== null && value !== "") {
      sql += ` AND ${column} LIKE ?`;
      params.push(`%${value}%`);
    }
  }

  // 追加 OR 模糊搜索条件：AND (col1 LIKE ? OR col2 LIKE ?)
  if (searchOr && searchOr[0] && searchOr[1].length > 0) {
    const [term, columns] = searchOr;
    const likeClauses = columns.map((col) => `${col} LIKE ?`).join(" OR ");
    sql += ` AND (${likeClauses})`;
    for (const _col of columns) {
      params.push(`%${term}%`);
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

  const stmt = db.prepare(sql);
  stmt.bind(params as BindParams);
  let total = 0;
  if (stmt.step()) {
    const row = stmt.getAsObject() as { total: number };
    total = Number(row.total) || 0;
  }
  stmt.free();

  return total;
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
    (event_id, category, sub_category, sub_category_description, threat_level, event_time, recommendation, event_info, source, action)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

/**
 * 插入一条安全事件（带去重）
 *
 * 先按 event_id 查询是否已存在相同事件：
 * - 若已存在，仅更新 event_time 为最新时间
 * - 若不存在，执行 INSERT 插入新记录
 */
export async function dbInsertSecurityEvent(
  eventId: string,
  category: string,
  subCategory: string,
  subCategoryDescription: string,
  threatLevel: string,
  eventTime: string,
  recommendation: string,
  eventInfo: string,
  source: 'local' | 'cloud' = 'local',
  action: string = '',
): Promise<void> {
  const db = await ensureDb();

  // 查询是否已存在相同事件（event_id 匹配）
  const checkSql = `
    SELECT id FROM security_events
    WHERE event_id = ?
    LIMIT 1
  `;
  const stmt = db.prepare(checkSql);
  stmt.bind([eventId] as BindParams);

  if (stmt.step()) {
    // 已存在相同事件，仅更新 event_time
    const row = stmt.getAsObject() as { id: number };
    stmt.free();
    db.run(
      "UPDATE security_events SET event_time = ? WHERE id = ?",
      [eventTime, row.id],
    );
  } else {
    stmt.free();
    // 不存在，插入新记录
    db.run(INSERT_SECURITY_EVENT, [
      eventId,
      category,
      subCategory,
      subCategoryDescription,
      threatLevel,
      eventTime,
      recommendation,
      eventInfo,
      source,
      action,
    ]);
  }

  saveDb();
}

/** 按条件查询安全事件 */
export async function dbQuerySecurityEvents(filter: {
  category?: string;
  subCategory?: string;
  threatLevel?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
  idAfter?: number;
  source?: string;
}): Promise<Array<Record<string, unknown>>> {
  return queryWithFilter(
    "security_events",
    [
      [filter.category, "category"],
      [filter.subCategory, "sub_category"],
      [filter.threatLevel, "threat_level"],
      [filter.source, "source"],
    ],
    "event_time",
    filter.startTime,
    filter.endTime,
    filter.limit,
    filter.idAfter,
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
    eventId,
    sessionKey,
    agentId,
    model,
    inputTokens,
    outputTokens,
    totalTokens,
    cacheReadTokens,
    cacheWriteTokens,
    eventTime,
    extraInfo,
  ]);
}

/** 按条件查询 Token 使用量 */
export async function dbQueryTokenUsage(filter: {
  sessionKey?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
  idAfter?: number;
  offset?: number;
}): Promise<Array<Record<string, unknown>>> {
  return queryWithFilter(
    "token_usage",
    [[filter.sessionKey, "session_key"]],
    "event_time",
    filter.startTime,
    filter.endTime,
    filter.limit,
    filter.idAfter,
    filter.offset,
  );
}

/** 按条件统计 Token 使用量记录总数 */
export async function dbCountTokenUsage(filter: {
  sessionKey?: string;
  startTime?: string;
  endTime?: string;
}): Promise<number> {
  return countWithFilter(
    "token_usage",
    [[filter.sessionKey, "session_key"]],
    "event_time",
    filter.startTime,
    filter.endTime,
  );
}

// ═══════════════════════════════════════════════════════════════
// tool_call 表操作
// ═══════════════════════════════════════════════════════════════

const INSERT_TOOL_CALL = `
  INSERT INTO tool_call
    (event_id, session_key, agent_id, run_id, tool_call_id, tool_name, params, result, is_success, error_message, duration_ms, event_time, action)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
  action: string = '',
): Promise<void> {
  await executeInsert(INSERT_TOOL_CALL, [
    eventId,
    sessionKey,
    agentId,
    runId,
    toolCallId,
    toolName,
    params,
    result,
    isSuccess ? 1 : 0,
    errorMessage,
    durationMs,
    eventTime,
    action,
  ]);
}

/** 按条件查询工具调用记录 */
export async function dbQueryToolCall(filter: {
  sessionKey?: string;
  search?: string;
  isSuccess?: number;
  action?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
  idAfter?: number;
  offset?: number;
}): Promise<Array<Record<string, unknown>>> {
  const eqConditions: Array<[unknown, string]> = [
    [filter.sessionKey, "session_key"],
  ];
  if (filter.isSuccess !== undefined && filter.isSuccess !== null) {
    eqConditions.push([filter.isSuccess, "is_success"]);
  }
  if (filter.action !== undefined && filter.action !== null && filter.action !== "") {
    eqConditions.push([filter.action, "action"]);
  }

  // search 参数使用 OR 模糊匹配 tool_name 和 tool_call_id
  const searchOr: [string, string[]] | undefined =
    filter.search
      ? [filter.search, ["tool_name", "tool_call_id"]]
      : undefined;

  return queryWithFilter(
    "tool_call",
    eqConditions,
    "event_time",
    filter.startTime,
    filter.endTime,
    filter.limit,
    filter.idAfter,
    filter.offset,
    undefined,
    searchOr,
  );
}

/** 按条件统计工具调用记录总数 */
export async function dbCountToolCall(filter: {
  search?: string;
  isSuccess?: number;
  action?: string;
  startTime?: string;
  endTime?: string;
}): Promise<number> {
  const eqConditions: Array<[unknown, string]> = [];
  if (filter.isSuccess !== undefined && filter.isSuccess !== null) {
    eqConditions.push([filter.isSuccess, "is_success"]);
  }
  if (filter.action !== undefined && filter.action !== null && filter.action !== "") {
    eqConditions.push([filter.action, "action"]);
  }

  // search 参数使用 OR 模糊匹配 tool_name 和 tool_call_id
  const searchOr: [string, string[]] | undefined =
    filter.search
      ? [filter.search, ["tool_name", "tool_call_id"]]
      : undefined;

  return countWithFilter(
    "tool_call",
    eqConditions,
    "event_time",
    filter.startTime,
    filter.endTime,
    undefined,
    searchOr,
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
    eventId,
    eventType,
    logTimestamp,
    connId,
    remoteIp,
    client,
    clientVersion,
    disconnectCode,
    disconnectReason,
    authMode,
    authReason,
    userAgent,
    subsystem,
    logLevel,
    runtime,
    runtimeVersion,
    hostname,
    logFile,
    rawLine,
  ]);
}

/** 按条件查询 Gateway 认证日志 */
export async function dbQueryGWAuthLogs(filter: {
  eventType?: string;
  eventId?: string;
  connId?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
  idAfter?: number;
  offset?: number;
  sortOrder?: "ASC" | "DESC";
}): Promise<Array<Record<string, unknown>>> {
  const likeConditions: Array<[string, string]> = [];
  if (filter.eventId) {
    likeConditions.push([filter.eventId, "event_id"]);
  }

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
    filter.idAfter,
    filter.offset,
    likeConditions.length > 0 ? likeConditions : undefined,
    undefined,
    filter.sortOrder,
  );
}

/** 按条件统计 Gateway 认证日志记录总数 */
export async function dbCountGWAuthLogs(filter: {
  eventType?: string;
  eventId?: string;
  connId?: string;
  startTime?: string;
  endTime?: string;
}): Promise<number> {
  const likeConditions: Array<[string, string]> = [];
  if (filter.eventId) {
    likeConditions.push([filter.eventId, "event_id"]);
  }

  return countWithFilter(
    "gateway_auth_logs",
    [
      [filter.eventType, "event_type"],
      [filter.connId, "conn_id"],
    ],
    "log_timestamp",
    filter.startTime,
    filter.endTime,
    likeConditions.length > 0 ? likeConditions : undefined,
  );
}

// ═══════════════════════════════════════════════════════════════
// policy_config 表操作
// ═══════════════════════════════════════════════════════════════

/** 策略配置接口 */
export interface PolicyConfig {
  id: number;
  policy_version: string;
  skill_check_enabled: boolean;
  command_check_enabled: boolean;
  config_check_enabled: boolean;
  block_on_violation: boolean;
  extra_command_blacklist: string;
  skill_id_blacklist: string;
  llm_mode: string;
  llm_proxy: string;
  onboard_command: string;
  needSetLLM: boolean;
  updated_at: string;
  previous_model: string;
  heartbeat_interval: number;
}

/** 插入或更新策略版本配置 */
export async function dbUpsertPolicyConfig(config: Omit<PolicyConfig, 'id'>): Promise<void> {
  const db = await ensureDb();

  const insertSql = `
    INSERT INTO policy_config (
      policy_version, skill_check_enabled, command_check_enabled, config_check_enabled,
      block_on_violation, extra_command_blacklist, skill_id_blacklist,
      llm_mode, llm_proxy, onboard_command, needSetLLM, updated_at, previous_model, heartbeat_interval
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.run(insertSql, [
    config.policy_version,
    config.skill_check_enabled ? 1 : 0,
    config.command_check_enabled ? 1 : 0,
    config.config_check_enabled ? 1 : 0,
    config.block_on_violation ? 1 : 0,
    config.extra_command_blacklist,
    config.skill_id_blacklist,
    config.llm_mode,
    config.llm_proxy,
    config.onboard_command,
    config.needSetLLM ? 1 : 0,
    config.updated_at,
    config.previous_model,
    config.heartbeat_interval,
  ]);

  saveDb();
}

/** 根据 policy_version 查询策略配置 */
export async function dbQueryPolicyConfig(
  policyVersion: string,
): Promise<PolicyConfig | null> {
  const db = await ensureDb();
  const sql = "SELECT * FROM policy_config WHERE policy_version = ? ORDER BY id DESC LIMIT 1";
  const stmt = db.prepare(sql);
  stmt.bind([policyVersion]);
  if (stmt.step()) {
    const row = stmt.getAsObject() as Record<string, unknown>;
    stmt.free();
    return {
      id: row.id as number,
      policy_version: row.policy_version as string,
      skill_check_enabled: Boolean(row.skill_check_enabled),
      command_check_enabled: Boolean(row.command_check_enabled),
      config_check_enabled: Boolean(row.config_check_enabled),
      block_on_violation: Boolean(row.block_on_violation),
      extra_command_blacklist: row.extra_command_blacklist as string,
      skill_id_blacklist: row.skill_id_blacklist as string,
      llm_mode: row.llm_mode as string,
      llm_proxy: row.llm_proxy as string,
      onboard_command: row.onboard_command as string,
      needSetLLM: Boolean(row.needSetLLM),
      updated_at: row.updated_at as string,
      previous_model: (row.previous_model as string) || '',
      heartbeat_interval: (row.heartbeat_interval as number) || 30,
    };
  }
  stmt.free();
  return null;
}

/** 更新 needSetLLM 字段 */
export async function dbUpdateNeedSetLLM(needSetLLM: boolean, id: number): Promise<void> {
  const db = await ensureDb();
  const sql = "UPDATE policy_config SET needSetLLM = ? WHERE id = ?";
  db.run(sql, [needSetLLM ? 1 : 0, id]);
  saveDb();
}

/** 默认模型配置接口 */
export interface DefaultModelConfig {
  id: number;
  provider_id: string;
  model_id: string;
  updated_at: string;
}

/** 保存默认模型配置 */
export async function dbSaveDefaultModel(config: Omit<DefaultModelConfig, 'id' | 'updated_at'>): Promise<void> {
  const db = await ensureDb();
  const now = new Date().toISOString();
  const insertSql = `
      INSERT INTO default_model_config (
        provider_id, model_id, updated_at
      ) VALUES (?, ?, ?)
    `;
  db.run(insertSql, [
    config.provider_id,
    config.model_id,
    now,
  ]);

  saveDb();
}

/** 获取默认模型配置 */
export async function dbGetDefaultModel(): Promise<DefaultModelConfig | null> {
  const db = await ensureDb();
  const sql = "SELECT * FROM default_model_config ORDER BY id DESC LIMIT 1";
  const stmt = db.prepare(sql);
  if (stmt.step()) {
    const row = stmt.getAsObject() as Record<string, unknown>;
    stmt.free();
    return {
      id: row.id as number,
      provider_id: row.provider_id as string,
      model_id: row.model_id as string,
      updated_at: row.updated_at as string,
    };
  }
  stmt.free();
  return null;
}

/** 获取最新的策略配置（按 id 倒序） */
export async function dbGetLatestPolicyConfig(): Promise<PolicyConfig | null> {
  const db = await ensureDb();
  const sql = "SELECT * FROM policy_config ORDER BY id DESC LIMIT 1";
  const stmt = db.prepare(sql);
  if (stmt.step()) {
    const row = stmt.getAsObject() as Record<string, unknown>;
    stmt.free();
    return {
      id: row.id as number,
      policy_version: row.policy_version as string,
      skill_check_enabled: Boolean(row.skill_check_enabled),
      command_check_enabled: Boolean(row.command_check_enabled),
      config_check_enabled: Boolean(row.config_check_enabled),
      block_on_violation: Boolean(row.block_on_violation),
      extra_command_blacklist: row.extra_command_blacklist as string,
      skill_id_blacklist: row.skill_id_blacklist as string,
      llm_mode: row.llm_mode as string,
      llm_proxy: row.llm_proxy as string,
      onboard_command: row.onboard_command as string,
      needSetLLM: Boolean(row.needSetLLM),
      updated_at: row.updated_at as string,
      previous_model: (row.previous_model as string) || '',
      heartbeat_interval: (row.heartbeat_interval as number) || 30,
    };
  }
  stmt.free();
  return null;
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
