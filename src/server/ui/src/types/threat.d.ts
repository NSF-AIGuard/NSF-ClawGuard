/**
 * 威胁级别枚举
 */
export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

/**
 * 安全威胁事件接口
 */
export interface ThreatEvent {
  id:string;
  /** 一级分类 */
  category: string
  /** 二级分类 */
  sub_category: string
  /** 威胁级别 */
  threat_level: ThreatLevel
  /** 处置建议 */
  recommendation: string
  /** 事件时间 (ISO8601格式) */
  event_time: string
  sub_category_description:string;
  event_info:string
}