import { http } from '@/utils/request'
import type { ThreatEvent } from '@/types/threat'


/**
 * 获取威胁事件列表
 * @returns Promise<ThreatEvent[]> 威胁事件数组
 */
export const getThreatList = async (): Promise<ThreatEvent[]> => {
  return await http.get<ThreatEvent[]>('/lm-securty/events')
}

/**
 * 安全事件统计数据类型
 */
export interface SecurityEventStat {
  date: string;
  count: number;
}

/**
 * 获取安全事件统计数据（折线图）
 * @returns Promise<SecurityEventStat[]> 安全事件统计数组
 */
export const getSecurityEventStats = async (): Promise<SecurityEventStat[]> => {
  return await http.get<SecurityEventStat[]>('/lm-securty/securityEventStats')
}
