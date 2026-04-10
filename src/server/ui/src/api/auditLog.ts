import { http } from "@/utils/request";
import type {
  AuthLogRecord,
  TokenConsumptionRecord,
  ToolCallRecord,
  OverviewStatistics,
  GatewayAuthLogRecord,
} from "@/types/auditLog";

/**
 * 获取认证日志列表
 * @returns Promise<AuthLogRecord[]>
 */
export const getAuthLogList = async (): Promise<AuthLogRecord[]> => {
  return  http.get<AuthLogRecord[]>("/api/audit/auth-logs");
};

/**
 * 获取会话Token消耗列表
 * @returns Promise<TokenConsumptionRecord[]>
 */
export const getTokenConsumptionList = async (): Promise<
  TokenConsumptionRecord[]
> => {
  return http.get<TokenConsumptionRecord[]>("/lm-securty/tokenUsage");
};

/**
 * 获取工具调用记录列表
 * @returns Promise<ToolCallRecord[]>
 */
export const getToolCallList = async (): Promise<ToolCallRecord[]> => {
  return http.get<ToolCallRecord[]>("/lm-securty/toolCall");
};

/**
 * 获取概览统计数据
 * @returns Promise<OverviewStatistics>
 */
export const getOverviewStatistics = async (): Promise<OverviewStatistics> => {
  return http.get<OverviewStatistics>("/lm-securty/overview");
};

/**
 * 获取网关认证日志列表
 * @returns Promise<GatewayAuthLogRecord[]>
 */
export const getGatewayAuthLogList = async (): Promise<
  GatewayAuthLogRecord[]
> => {
  return http.get<GatewayAuthLogRecord[]>("/lm-securty/gatewayAuthLogs");
};
