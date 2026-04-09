import React from 'react'
import {
  LoginOutlined,
  LogoutOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons'
import type { AuthAction, AuthStatus, ToolCallStatus } from '@/types/auditLog'

/** 认证操作类型映射 */
export const authActionMap: Record<AuthAction, { text: string; color: string; icon: React.ReactNode }> = {
  login: { text: '登录', color: '#1890ff', icon: <LoginOutlined /> },
  logout: { text: '登出', color: '#8c8c8c', icon: <LogoutOutlined /> },
}

/** 认证状态映射 */
export const authStatusMap: Record<AuthStatus, { text: string; color: string; icon: React.ReactNode }> = {
  success: { text: '成功', color: '#52c41a', icon: <CheckCircleOutlined /> },
  failure: { text: '失败', color: '#ff4d4f', icon: <CloseCircleOutlined /> },
}

/** 工具调用状态映射 */
export const toolCallStatusMap: Record<ToolCallStatus, { text: string; color: string; icon: React.ReactNode }> = {
  success: { text: '成功', color: '#52c41a', icon: <CheckCircleOutlined /> },
  failure: { text: '失败', color: '#ff4d4f', icon: <CloseCircleOutlined /> },
  timeout: { text: '超时', color: '#faad14', icon: <ClockCircleOutlined /> },
}

/** 格式化时间 */
export const formatTime = (time: string): string => {
  const date = new Date(time)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** 格式化持续时间 */
export const formatDuration = (seconds: number): string => {
  if (seconds < 60) return `${seconds}秒`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}分${seconds % 60}秒`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}小时${minutes}分`
}

/** 格式化Token数量 */
export const formatTokens = (count: number): string => {
  if (count < 1000) return `${count}`
  if (count < 1000000) return `${(count / 1000).toFixed(1)}K`
  return `${(count / 1000000).toFixed(2)}M`
}

/** 随机IP */
const randomIp = (): string => `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`

/** 用户代理列表 */
const userAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) Firefox/122.0',
  'OpenClaw-Agent/1.0 (Security Scanner)',
  'LM-Security-Client/2.1.0',
]

/** 工具名称列表 */
const toolNames = [
  'nmap_scanner',
  'sql_injection_detector',
  'xss_scanner',
  'port_scanner',
  'vulnerability_assessor',
  'log_analyzer',
  'threat_intelligence_query',
  'file_integrity_checker',
  'network_traffic_analyzer',
  'certificate_validator',
]

/** 生成Mock认证日志数据 */
export const mockAuthLogData = (): import('@/types/auditLog').AuthLogRecord[] => {
  const usernames = ['admin', 'analyst', 'operator', 'scanner', 'auditor', 'guest', 'system']
  const actions: AuthAction[] = ['login', 'logout']
  const statuses: AuthStatus[] = ['success', 'success', 'success', 'success', 'failure', 'success', 'success']

  return Array.from({ length: 30 }, (_, i) => {
    const action = actions[Math.floor(Math.random() * actions.length)]
    const status = statuses[Math.floor(Math.random() * statuses.length)]
    const username = usernames[Math.floor(Math.random() * usernames.length)]
    return {
      key: `auth-${i}`,
      id: `AUTH-${String(i + 1).padStart(6, '0')}`,
      time: new Date(Date.now() - i * 180000 - Math.random() * 60000).toISOString(),
      username,
      ip: randomIp(),
      action,
      status,
      userAgent: userAgents[Math.floor(Math.random() * userAgents.length)],
      sessionId: `sess-${String(Math.floor(Math.random() * 9000) + 1000)}`,
      details: status === 'failure'
        ? `用户 ${username} 在 ${action === 'login' ? '登录' : '登出'} 时认证失败，IP来源: ${randomIp()}`
        : undefined,
    }
  })
}

/** 生成Mock Token消耗数据 */
export const mockTokenConsumptionData = (): import('@/types/auditLog').TokenConsumptionRecord[] => {
  const models = ['GPT-4', 'GPT-3.5-Turbo', 'Claude-3', 'Qwen-72B', 'DeepSeek-V2']

  return Array.from({ length: 20 }, (_, i) => {
    const inputTokens = Math.floor(Math.random() * 8000) + 500
    const outputTokens = Math.floor(Math.random() * 4000) + 200
    const cacheReadTokens = Math.floor(Math.random() * 3000) + 100
    const cacheWriteTokens = Math.floor(Math.random() * 1500) + 50
    return {
      key: `token-${i}`,
      sessionId: `session-${String(i + 1).padStart(4, '0')}`,
      startTime: new Date(Date.now() - i * 600000 - Math.random() * 300000).toISOString(),
      inputTokens,
      outputTokens,
      totalTokens: inputTokens + outputTokens,
      cacheReadTokens,
      cacheWriteTokens,
      model: models[Math.floor(Math.random() * models.length)],
    }
  }).sort((a, b) => b.totalTokens - a.totalTokens)
}

/** 生成Mock工具调用数据 */
export const mockToolCallData = (): import('@/types/auditLog').ToolCallRecord[] => {
  const statuses: ToolCallStatus[] = ['success', 'success', 'success', 'failure', 'success', 'timeout', 'success']

  return Array.from({ length: 25 }, (_, i) => {
    const status = statuses[Math.floor(Math.random() * statuses.length)]
    const toolName = toolNames[Math.floor(Math.random() * toolNames.length)]
    return {
      key: `tool-${i}`,
      id: `TC-${String(i + 1).padStart(6, '0')}`,
      toolName,
      startTime:new Date().toISOString(),
      callTime: new Date(Date.now() - i * 240000 - Math.random() * 120000).getTime(),
      isSuccess:false,
      duration: Math.floor(Math.random() * 5000) + 100,
      sessionId: `session-${String(Math.floor(Math.random() * 20) + 1).padStart(4, '0')}`,
      inputParams: JSON.stringify({ target: randomIp(), scan_type: 'full', timeout: 30 }, null, 2),
      outputResult: status === 'success'
        ? JSON.stringify({ status: 'completed', findings: Math.floor(Math.random() * 10) }, null, 2)
        : undefined,
      errorMessage: status === 'failure'
        ? `工具 ${toolName} 执行失败：连接超时或目标拒绝访问`
        : status === 'timeout'
        ? `工具 ${toolName} 执行超时：超过最大等待时间`
        : undefined,
    }
  })
}

/** 生成Mock概览统计数据 */
export const mockOverviewStatistics = (): import('@/types/auditLog').OverviewStatistics => {
  const totalSessions = Math.floor(Math.random() * 50) + 20
  const todayTokenConsumption = Math.floor(Math.random() * 500000) + 50000
  const todayToolCalls = Math.floor(Math.random() * 200) + 50
  const todayAuthEvents = Math.floor(Math.random() * 100) + 30
  const authFailureRate = parseFloat((Math.random() * 15 + 2).toFixed(1))
  const toolSuccessRate = parseFloat((85 + Math.random() * 14).toFixed(1))

  return {
    totalSessions,
    todayTokenConsumption,
    todayToolCalls,
    todayAuthEvents,
    authFailureRate,
    toolSuccessRate,
    tokenDiffPercent: '0'
  }
}

/** Token消耗趋势 Mock 数据 */
export const mockTokenTrendData = () => {
  return Array.from({ length: 7 }, (_, i) => ({
    date: new Date(Date.now() - (6 - i) * 86400000).toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' }),
    inputTokens: Math.floor(Math.random() * 30000) + 10000,
    outputTokens: Math.floor(Math.random() * 20000) + 5000,
  }))
}