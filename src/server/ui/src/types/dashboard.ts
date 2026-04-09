import {ThreatLevel} from './threat'
// Dashboard 相关类型定义

export interface SecurityEvent {
  key: string
  category: string
  subCategory: string
  threatLevel: ThreatLevel;
  recommendation: string
  eventTime: string;
  subCategoryDescription:string;
  eventInfo?: string;
}

export interface ThreatLevelConfig {
  text: string
  color: string
}

export interface CategoryConfig {
  text: string
  color: string
}

export interface Statistics {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}