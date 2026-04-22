import { ensureDb } from "../database.js";
import type { BindParams } from "sql.js";
import type { IncomingMessage, ServerResponse } from "http";

export type ThreatLevel = "critical" | "high" | "medium" | "low" | "info";

export interface ThreatEvent {
  id: string;
  category: string;
  sub_category: string;
  threat_level: ThreatLevel;
  recommendation: string;
  event_time: string;
  event_info: string;
  sub_category_description: string;
}

/** 查询安全事件列表（支持分页和威胁级别筛选） */
export async function inspectHandler(
  req: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const qp = getQueryParams(req);
    const page = Math.max(1, Number(qp.get("page")) || 1);
    const pageSize = Math.max(1, Math.min(200, Number(qp.get("pageSize")) || 10));
    const threatLevel = qp.get("threat_level") || undefined;
    const category = qp.get("category") || undefined;
    const offset = (page - 1) * pageSize;

    const db = await ensureDb();

    // 查询总数
    let countSql = "SELECT COUNT(*) AS cnt FROM security_events WHERE 1=1";
    const countParams: BindParams = [];
    if (threatLevel) {
      countSql += " AND threat_level = ?";
      countParams.push(threatLevel);
    }
    if (category) {
      countSql += " AND category = ?";
      countParams.push(category);
    }
    const countStmt = db.prepare(countSql);
    countStmt.bind(countParams);
    let total = 0;
    if (countStmt.step()) {
      total = (countStmt.getAsObject() as { cnt: number }).cnt;
    }
    countStmt.free();

    // 查询分页数据
    let dataSql = "SELECT * FROM security_events WHERE 1=1";
    const dataParams: BindParams = [];
    if (threatLevel) {
      dataSql += " AND threat_level = ?";
      dataParams.push(threatLevel);
    }
    if (category) {
      dataSql += " AND category = ?";
      dataParams.push(category);
    }
    dataSql += " ORDER BY event_time DESC LIMIT ? OFFSET ?";
    dataParams.push(pageSize, offset);

    const dataStmt = db.prepare(dataSql);
    dataStmt.bind(dataParams);

    const items: ThreatEvent[] = [];
    while (dataStmt.step()) {
      const row = dataStmt.getAsObject();
      items.push({
        id: String(row["event_id"] || ""),
        category: String(row["category"] || ""),
        sub_category: String(row["sub_category"] || ""),
        sub_category_description: String(row["sub_category_description"] || ""),
        threat_level: String(row["threat_level"] || "info") as ThreatLevel,
        event_time: String(row["event_time"] || ""),
        recommendation: String(row["recommendation"] || ""),
        event_info: String(row["event_info"] || ""),
      });
    }
    dataStmt.free();

    res.json({ items, total, page, pageSize });
  } catch (error) {
    res.error("读取安全事件", error);
  }
}

/**
 * 统计最近7天内每天产生的安全事件数量
 *
 * 返回格式：
 * {
 *   success: true,
 *   data: [
 *     { date: "2026-04-02", count: 5 },
 *     { date: "2026-04-03", count: 3 },
 *     ...
 *   ]
 * }
 */
/**
 * 从请求的 URL 中解析查询参数
 */
function getQueryParams(req: IncomingMessage): URLSearchParams {
  const urlStr = req.url || "";
  const qIdx = urlStr.indexOf("?");
  const search = qIdx >= 0 ? urlStr.slice(qIdx) : "";
  return new URLSearchParams(search);
}

/** 风险分布统计（按 category 统计数量） */
export async function riskDistributionHandler(
  _req: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const db = await ensureDb();

    const sql = `
      SELECT
        SUM(CASE WHEN category = 'config_security' THEN 1 ELSE 0 END) AS config_security,
        SUM(CASE WHEN category = 'skill_security' THEN 1 ELSE 0 END) AS skill_security,
        SUM(CASE WHEN category = 'command_violation' THEN 1 ELSE 0 END) AS command_violation,
        SUM(CASE WHEN category = 'content_check' THEN 1 ELSE 0 END) AS content_check
      FROM security_events
    `;

    const stmt = db.prepare(sql);
    stmt.bind([]);

    let stats = {
      config_security: 0,
      skill_security: 0,
      command_violation: 0,
      content_check: 0,
    };

    if (stmt.step()) {
      const row = stmt.getAsObject() as Record<string, number>;
      stats = {
        config_security: Number(row["config_security"]) || 0,
        skill_security: Number(row["skill_security"]) || 0,
        command_violation: Number(row["command_violation"]) || 0,
        content_check: Number(row["content_check"]) || 0,
      };
    }
    stmt.free();

    res.json(stats);
  } catch (error) {
    res.error("获取风险分布统计", error);
  }
}

/** 获取事件统计数据（按威胁级别统计数量） */
export async function eventStatsHandler(
  _req: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const db = await ensureDb();

    const sql = `
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN threat_level = 'critical' THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN threat_level = 'high' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN threat_level = 'medium' THEN 1 ELSE 0 END) AS medium,
        SUM(CASE WHEN threat_level = 'low' THEN 1 ELSE 0 END) AS low,
        SUM(CASE WHEN threat_level = 'info' THEN 1 ELSE 0 END) AS info
      FROM security_events
    `;

    const stmt = db.prepare(sql);
    stmt.bind([]);

    let stats = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    if (stmt.step()) {
      const row = stmt.getAsObject() as Record<string, number>;
      stats = {
        total: Number(row["total"]) || 0,
        critical: Number(row["critical"]) || 0,
        high: Number(row["high"]) || 0,
        medium: Number(row["medium"]) || 0,
        low: Number(row["low"]) || 0,
        info: Number(row["info"]) || 0,
      };
    }
    stmt.free();

    res.json(stats);
  } catch (error) {
    res.error("获取事件统计", error);
  }
}

export async function securityEventStatsHandler(
  req: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const db = await ensureDb();
    const qp = getQueryParams(req);

    // 解析可选的 threat_level 筛选参数
    const threatLevel = qp.get("threat_level") || undefined;

    // 计算7天前的日期（ISO 格式，精确到天）
    const now = new Date();
    const sevenDaysAgo = new Date(now);
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const startDate = sevenDaysAgo.toISOString().slice(0, 10); // "YYYY-MM-DD"

    // 按 date(event_time) 分组统计最近7天的事件数
    // 如果传入了 threat_level 参数则增加过滤条件
    let sql = `
      SELECT DATE(event_time) AS date, COUNT(*) AS count
      FROM security_events
      WHERE event_time >= ?
    `;
    const params: BindParams = [startDate];

    if (threatLevel) {
      sql += " AND threat_level = ?";
      params.push(threatLevel);
    }

    sql += " GROUP BY DATE(event_time) ORDER BY date ASC";

    const stmt = db.prepare(sql);
    stmt.bind(params);

    const data: Array<{ date: string; count: number }> = [];
    while (stmt.step()) {
      const row = stmt.getAsObject() as { date: string; count: number };
      data.push({
        date: String(row.date || ""),
        count: Number(row.count) || 0,
      });
    }
    stmt.free();

    // 补全7天内没有事件的日期（count = 0）
    const dateMap = new Map(data.map((item) => [item.date, item.count]));
    const fullData: Array<{ date: string; count: number }> = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().slice(0, 10);
      fullData.push({
        date: dateStr,
        count: dateMap.get(dateStr) || 0,
      });
    }

    res.json(fullData);
  } catch (error) {
    res.error("统计安全事件", error);
  }
}
