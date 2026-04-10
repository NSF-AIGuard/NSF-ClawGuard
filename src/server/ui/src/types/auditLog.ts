/**
 * 审计日志相关类型定义
 */

/** 认证操作类型 */
export type AuthAction = 'login' | 'logout'

/** 认证状态 */
export type AuthStatus = 'success' | 'failure'

/** 工具调用状态 */
export type ToolCallStatus = 'success' | 'failure' | 'timeout'

/** 认证日志记录 */
export interface AuthLogRecord {
  key: string
  id: string
  time: string
  username: string
  ip: string
  action: AuthAction
  status: AuthStatus
  userAgent: string
  sessionId: string
  details?: string
}

/** 会话Token消耗记录 */
export interface TokenConsumptionRecord {
  key: string
  sessionId: string
  startTime: string
  inputTokens: number
  outputTokens: number
  totalTokens: number
  cacheReadTokens: number
  cacheWriteTokens: number
  model: string
}

/** 工具调用记录 */
export interface ToolCallRecord {
  key: string
  id: string
  toolName: string
  startTime: string
  isSuccess: boolean
  callTime: number // 毫秒
  sessionId: string
  inputParams?: string
  outputResult?: string
  errorMessage?: string
}

/** 网关认证日志事件类型 */
export type GatewayAuthEventType = 'auth_success' | 'auth_failed' | 'disconnected'

/** 网关认证日志记录 */
export interface GatewayAuthLogRecord {
  key: string
  eventId: string
  eventType: GatewayAuthEventType
  logTimestamp: string
  connId: string
  remoteIp: string
  client: string
  clientVersion: string
  disconnectCode: string
  disconnectReason: string
  authMode: string
  authReason: string
  userAgent: string
  subsystem: string
  logLevel: string
  runtime: string
  runtimeVersion: string
  hostname: string
  rawLine?: string
}

/** 概览统计数据 */
export interface OverviewStatistics {
  totalSessions: number
  todayTokenConsumption: number
  todayToolCalls: number
  todayAuthEvents: number
  authFailureRate: number
  toolSuccessRate: number
  tokenDiffPercent: string
}