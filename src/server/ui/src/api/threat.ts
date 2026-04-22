import { http } from "@/utils/request";
import type { ThreatEvent } from "@/types/threat";
import type { Statistics, RiskDistribution } from "@/types/dashboard";

/**
 * 威胁事件分页响应
 */
export interface ThreatListResponse {
  items: ThreatEvent[];
  total: number;
  page: number;
  pageSize: number;
}

/**
 * 威胁事件查询参数
 */
export interface ThreatListParams {
  page?: number;
  pageSize?: number;
  threat_level?: string;
  category?: string;
}

/**
 * 获取威胁事件列表（支持分页和威胁级别筛选）
 */
export const getThreatList = async (
  params?: ThreatListParams,
): Promise<ThreatListResponse> => {
  return await http.get<ThreatListResponse>("/lm-securty/events", { params });
};

/**
 * 安全事件统计数据类型
 */
export interface SecurityEventStat {
  date: string;
  count: number;
}

/**
 * 获取事件统计数据（按威胁级别统计数量）
 */
export const getEventStats = async (): Promise<Statistics> => {
  return await http.get<Statistics>("/lm-securty/eventStats");
};

/**
 * 获取风险分布统计（按 category 统计数量）
 */
export const getRiskDistribution = async (): Promise<RiskDistribution> => {
  return await http.get<RiskDistribution>("/lm-securty/riskDistribution");
};

/**
 * 获取安全事件统计数据（折线图）
 * @returns Promise<SecurityEventStat[]> 安全事件统计数组
 */
export const getSecurityEventStats = async (): Promise<SecurityEventStat[]> => {
  return await http.get<SecurityEventStat[]>("/lm-securty/securityEventStats");
};
