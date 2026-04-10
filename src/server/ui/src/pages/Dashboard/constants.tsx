import React from 'react'
import { 
  FireOutlined,
  AlertOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  InfoCircleOutlined,
  CloseCircleOutlined,
  LockOutlined,
  SafetyOutlined,
  ToolOutlined,
  SyncOutlined,
  AuditOutlined
} from '@ant-design/icons'
import type { ThreatLevelConfig, CategoryConfig } from '@/types/dashboard'

// 威胁级别映射
export const threatLevelMap: Record<string, ThreatLevelConfig> = {
  critical: { text: '严重', color: '#ff4d4f' },
  high: { text: '高危', color: '#ff7a45' },
  medium: { text: '中危', color: '#faad14' },
  low: { text: '低危', color: '#52c41a' },
  info: { text: '信息', color: '#1890ff' },
  none: { text: '无', color: '#d9d9d9' },
  warning: { text: '警告', color: '#faad14' }
}

// 获取威胁级别图标
export const getThreatLevelIcon = (level: string): React.ReactNode => {
  const iconMap: Record<string, JSX.Element> = {
    critical: <FireOutlined />,
    high: <AlertOutlined />,
    medium: <WarningOutlined />,
    low: <CheckCircleOutlined />,
    info: <InfoCircleOutlined />,
    none: <CloseCircleOutlined />,
    warning: <WarningOutlined />
  }
  return iconMap[level] || <CheckCircleOutlined />
}

// 分类映射
export const categoryMap: Record<string, CategoryConfig> = {
  config_security: { text: '配置安全', color: '#55a722' },
  skill_security: { text: 'Skill安全', color: '#1890ff' },
  command_violation: { text: '危险命令', color: '#ff4d4f' },
  component_change: { text: '组件变更', color: '#52c41a' },
  content_check: { text: '上下文检查', color: '#722ed1' }
}

// 获取分类图标
export const getCategoryIcon = (category: string): React.ReactNode => {
  const iconMap: Record<string, JSX.Element> = {
    config_security: <LockOutlined />,
    skill_security: <SafetyOutlined />,
    command_violation: <ToolOutlined />,
    component_change: <SyncOutlined />,
    content_check: <AuditOutlined />
  }
  return iconMap[category] || <SafetyOutlined />
}
