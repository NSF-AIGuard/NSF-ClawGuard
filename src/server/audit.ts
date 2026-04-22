import {
  dbQueryTokenUsage,
  dbQueryToolCall,
  dbQueryGWAuthLogs,
  dbCountTokenUsage,
  dbCountToolCall,
  dbCountGWAuthLogs,
} from "../database.js";
import type { IncomingMessage, ServerResponse } from "http";

// ═══════════════════════════════════════════════════════════════
// 工具函数
// ═══════════════════════════════════════════════════════════════

function parseISODate(isoStr: string): Date {
  return new Date(isoStr);
}

/**
 * 从请求的 URL 中解析查询参数
 * 安全地获取 req.url，用 URLSearchParams 解析 query string
 */
function getQueryParams(req: IncomingMessage): URLSearchParams {
  const urlStr = req.url || "";
  const qIdx = urlStr.indexOf("?");
  const search = qIdx >= 0 ? urlStr.slice(qIdx) : "";
  return new URLSearchParams(search);
}

/**
 * 解析分页参数
 * @returns { pageSize, page, offset }
 */
function parsePagination(params: URLSearchParams): {
  pageSize: number;
  page: number;
  offset: number;
} {
  const pageSize = Math.max(1, Math.min(500, Number(params.get("pageSize")) || 10));
  const page = Math.max(1, Number(params.get("page")) || 1);
  const offset = (page - 1) * pageSize;
  return { pageSize, page, offset };
}

/**
 * 构造分页响应数据
 */
function paginateResult<T>(
  list: T[],
  total: number,
  page: number,
  pageSize: number,
) {
  const totalPages = Math.ceil(total / pageSize);
  return {
    items: list,
    total,
    page,
    pageSize,
    totalPages,
  };
}

// ── Token Usage ────────────────────────────────────────────────

export async function tokenUsageHandler(
  req: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const qp = getQueryParams(req);
    const { pageSize, page, offset } = parsePagination(qp);

    const filter = {
      sessionKey: qp.get("sessionKey") || undefined,
      startTime: qp.get("startTime") || undefined,
      endTime: qp.get("endTime") || undefined,
    };

    const [rows, total] = await Promise.all([
      dbQueryTokenUsage({ ...filter, limit: pageSize, offset }),
      dbCountTokenUsage(filter),
    ]);

    const items = rows.map((row) => ({
      key: String(row["event_id"] || ""),
      sessionId: String(row["session_key"] || ""),
      startTime: String(row["event_time"] || ""),
      inputTokens: Number(row["input_tokens"] || 0),
      outputTokens: Number(row["output_tokens"] || 0),
      totalTokens: Number(row["total_tokens"] || 0),
      cacheReadTokens: Number(row["cache_read_tokens"] || 0),
      cacheWriteTokens: Number(row["cache_write_tokens"] || 0),
      model: String(row["model"] || ""),
      extraInfo: String(row["extra_info"] || ""),
      agentId: String(row["agent_id"] || ""),
    }));

    res.json(paginateResult(items, total, page, pageSize));
  } catch (error) {
    res.error("读取 token_usage", error);
  }
}

// ── Overview ───────────────────────────────────────────────────

export async function overview(_: IncomingMessage, res: ServerResponse) {
  try {
    const now = new Date();
    const todayStart = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
      0, 0, 0, 0,
    );
    const todayEnd = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
      23, 59, 59, 999,
    );
    const yesterdayStart = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate() - 1,
      0, 0, 0, 0,
    );
    const yesterdayEnd = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate() - 1,
      23, 59, 59, 999,
    );

    const tokenRows = await dbQueryTokenUsage({});
    const toolRows = await dbQueryToolCall({});
    const authRows = await dbQueryGWAuthLogs({});

    const todayTokens = tokenRows.filter((r) => {
      const t = parseISODate(String(r["event_time"] || ""));
      return t >= todayStart && t <= todayEnd;
    });
    const yesterdayTokens = tokenRows.filter((r) => {
      const t = parseISODate(String(r["event_time"] || ""));
      return t >= yesterdayStart && t <= yesterdayEnd;
    });

    const todaySessions = new Set(
      todayTokens.map((r) => String(r["session_key"] || "")),
    );
    const yesterdaySessions = new Set(
      yesterdayTokens.map((r) => String(r["session_key"] || "")),
    );

    const todayTotalTokens = todayTokens.reduce(
      (s, r) => s + Number(r["total_tokens"] || 0), 0,
    );
    const yesterdayTotalTokens = yesterdayTokens.reduce(
      (s, r) => s + Number(r["total_tokens"] || 0), 0,
    );

    const tokenDiff = todayTotalTokens - yesterdayTotalTokens;
    const tokenDiffPercent =
      yesterdayTotalTokens > 0
        ? ((tokenDiff / yesterdayTotalTokens) * 100).toFixed(2)
        : todayTotalTokens > 0
          ? "100.00"
          : "0.00";

    const sessionDiff = todaySessions.size - yesterdaySessions.size;
    const sessionDiffPercent =
      yesterdaySessions.size > 0
        ? ((sessionDiff / yesterdaySessions.size) * 100).toFixed(2)
        : todaySessions.size > 0
          ? "100.00"
          : "0.00";

    const todayToolRows = toolRows.filter((r) => {
      const t = parseISODate(String(r["event_time"] || ""));
      return t >= todayStart && t <= todayEnd;
    });
    const todayToolNum = todayToolRows.length;
    const toolSuccessNum = todayToolRows.filter(
      (r) => Number(r["is_success"]) === 1,
    ).length;
    const toolSuccessRate =
      todayToolNum <= 0
        ? "100"
        : ((toolSuccessNum / todayToolNum) * 100).toFixed(2);

    const todayAuthRows = authRows.filter((r) => {
      const t = parseISODate(String(r["log_timestamp"] || ""));
      return t >= todayStart && t <= todayEnd;
    });
    const authFailureNum = todayAuthRows.filter(
      (r) => String(r["event_type"]) === "auth_failed",
    ).length;
    const authFailureRate =
      todayAuthRows.length <= 0
        ? "100"
        : ((authFailureNum / todayAuthRows.length) * 100).toFixed(2);

    res.json({
      totalSessions: todaySessions.size,
      todayTokenConsumption: todayTotalTokens,
      todayToolCalls: todayToolNum,
      todayAuthEvents: todayAuthRows.length,
      authFailureRate,
      toolSuccessRate,
      tokenDiffPercent,
      today: {
        sessionCount: todaySessions.size,
        totalTokens: todayTotalTokens,
      },
      yesterday: {
        sessionCount: yesterdaySessions.size,
        totalTokens: yesterdayTotalTokens,
      },
      diff: {
        sessionCount: sessionDiff,
        sessionDiffPercent,
        tokens: tokenDiff,
        tokenDiffPercent,
      },
    });
  } catch (error) {
    res.error("overview", error);
  }
}

// ── Gateway Auth Logs ──────────────────────────────────────────

export async function gatewayAuthLogHandler(
  req: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const qp = getQueryParams(req);
    const { pageSize, page, offset } = parsePagination(qp);

    const timeSortParam = qp.get("timeSort") || undefined;
    const sortOrder: "ASC" | "DESC" | undefined =
      timeSortParam?.toUpperCase() === "ASC" ? "ASC" : undefined;

    const filter = {
      eventType: qp.get("eventType") || undefined,
      eventId: qp.get("eventId") || undefined,
      connId: qp.get("connId") || undefined,
      startTime: qp.get("startTime") || undefined,
      endTime: qp.get("endTime") || undefined,
      sortOrder,
    };

    const [rows, total] = await Promise.all([
      dbQueryGWAuthLogs({ ...filter, limit: pageSize, offset }),
      dbCountGWAuthLogs(filter),
    ]);

    const items = rows.map((row) => ({
      key: String(row["event_id"] || ""),
      eventId: String(row["event_id"] || ""),
      eventType: String(row["event_type"] || ""),
      logTimestamp: String(row["log_timestamp"] || ""),
      connId: String(row["conn_id"] || ""),
      remoteIp: String(row["remote_ip"] || ""),
      client: String(row["client"] || ""),
      clientVersion: String(row["client_version"] || ""),
      disconnectCode: String(row["disconnect_code"] || ""),
      disconnectReason: String(row["disconnect_reason"] || ""),
      authMode: String(row["auth_mode"] || ""),
      authReason: String(row["auth_reason"] || ""),
      userAgent: String(row["user_agent"] || ""),
      subsystem: String(row["subsystem"] || ""),
      logLevel: String(row["log_level"] || ""),
      runtime: String(row["runtime"] || ""),
      runtimeVersion: String(row["runtime_version"] || ""),
      hostname: String(row["hostname"] || ""),
      rawLine: String(row["raw_line"] || ""),
    }));

    res.json(paginateResult(items, total, page, pageSize));
  } catch (error) {
    res.error("读取 gateway_auth_logs", error);
  }
}

// ── Tool Call ─────────────────────────────────────────────────

export async function toolCallHandler(req: IncomingMessage, res: ServerResponse) {
  try {
    const qp = getQueryParams(req);
    const { pageSize, page, offset } = parsePagination(qp);

    // 解析 isSuccess 参数：支持 "true"/"1" → 1, "false"/"0" → 0
    let isSuccess: number | undefined;
    const isSuccessStr = qp.get("isSuccess");
    if (isSuccessStr !== null && isSuccessStr !== "") {
      if (isSuccessStr === "true" || isSuccessStr === "1") {
        isSuccess = 1;
      } else if (isSuccessStr === "false" || isSuccessStr === "0") {
        isSuccess = 0;
      }
    }

    const actionParam = qp.get("action") || undefined;

    const filter = {
      isSuccess,
      action: actionParam,
      search: qp.get("search") || undefined,
      startTime: qp.get("startTime") || undefined,
      endTime: qp.get("endTime") || undefined,
    };

    const [rows, total] = await Promise.all([
      dbQueryToolCall({ ...filter, limit: pageSize, offset }),
      dbCountToolCall(filter),
    ]);

    const items = rows.map((row) => ({
      runId: String(row["run_id"] || ""),
      toolCallId: String(row["tool_call_id"] || ""),
      key: String(row["event_id"] || ""),
      id: String(row["event_id"] || ""),
      toolName: String(row["tool_name"] || ""),
      callTime: Number(row["duration_ms"] || 0),
      inputParams: String(row["params"] || ""),
      outputResult: String(row["result"] || ""),
      sessionId: String(row["session_key"] || ""),
      startTime: String(row["event_time"] || ""),
      errorMessage: String(row["error_message"] || ""),
      agentId: String(row["agent_id"] || ""),
      isSuccess: Boolean(Number(row["is_success"]) === 1),
      action: String(row["action"] || ""),
    }));

    res.json(paginateResult(items, total, page, pageSize));
  } catch (error) {
    res.error("读取 tool_call", error);
  }
}