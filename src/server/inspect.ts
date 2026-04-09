import { dbQuerySecurityEvents, ensureDb } from "../database.js";
import type { IncomingMessage, ServerResponse } from "http";
import type { Logger } from "../types.js";

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

/** 查询安全事件列表 */
export async function inspectHandler(
  _: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const rows = await dbQuerySecurityEvents({ limit: 500 });
    const data = rows.map((row) => ({
      id: String(row["event_id"] || ""),
      category: String(row["category"] || ""),
      sub_category: String(row["sub_category"] || ""),
      sub_category_description: String(row["sub_category_description"] || ""),
      threat_level: String(row["threat_level"] || "info") as ThreatLevel,
      event_time: String(row["event_time"] || ""),
      recommendation: String(row["recommendation"] || ""),
      event_info: String(row["event_info"] || ""),
    }));
    res.json(data);
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
export async function securityEventStatsHandler(
  _: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const db = await ensureDb();

    // 计算7天前的日期（ISO 格式，精确到天）
    const now = new Date();
    const sevenDaysAgo = new Date(now);
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const startDate = sevenDaysAgo.toISOString().slice(0, 10); // "YYYY-MM-DD"

    // 按 date(event_time) 分组统计最近7天的事件数
    const sql = `
      SELECT DATE(event_time) AS date, COUNT(*) AS count
      FROM security_events
      WHERE event_time >= ?
      GROUP BY DATE(event_time)
      ORDER BY date ASC
    `;

    const stmt = db.prepare(sql);
    stmt.bind([startDate]);

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