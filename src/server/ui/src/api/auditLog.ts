import { http } from "@/utils/request";
import type {
  AuthLogRecord,
  TokenConsumptionRecord,
  ToolCallRecord,
  OverviewStatistics,
  GatewayAuthLogRecord,
  PaginatedResponse,
  ToolCallQueryParams,
  TokenUsageQueryParams,
  GatewayAuthLogQueryParams,
} from "@/types/auditLog";

/**
 * 获取认证日志列表
 * @returns Promise<AuthLogRecord[]>
 */
export const getAuthLogList = async (): Promise<AuthLogRecord[]> => {
  return  http.get<AuthLogRecord[]>("/api/audit/auth-logs");
};

/**
 * 获取会话Token消耗列表（支持分页和筛选）
 */
export const getTokenConsumptionList = async (
  params?: TokenUsageQueryParams,
): Promise<PaginatedResponse<TokenConsumptionRecord>> => {
  return http.get<PaginatedResponse<TokenConsumptionRecord>>("/lm-securty/tokenUsage", { params });
};

/**
 * 获取工具调用记录列表（支持分页和筛选）
 */
export const getToolCallList = async (
  params?: ToolCallQueryParams,
): Promise<PaginatedResponse<ToolCallRecord>> => {
  return http.get<PaginatedResponse<ToolCallRecord>>("/lm-securty/toolCall", { params });
};

/**
 * 获取概览统计数据
 * @returns Promise<OverviewStatistics>
 */
export const getOverviewStatistics = async (): Promise<OverviewStatistics> => {
  return http.get<OverviewStatistics>("/lm-securty/overview");
};

/**
 * 获取网关认证日志列表（支持分页和筛选）
 */
export const getGatewayAuthLogList = async (
  params?: GatewayAuthLogQueryParams,
): Promise<PaginatedResponse<GatewayAuthLogRecord>> => {
  return http.get<PaginatedResponse<GatewayAuthLogRecord>>("/lm-securty/gatewayAuthLogs", { params });
};
