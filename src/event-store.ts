/**
 * 事件存储模块
 *
 * 基于 SQLite 数据库统一存储各类安全检测结果。
 *
 * 支持的事件类别：
 * - config_security: Gateway 配置安全扫描
 * - skill_security: Skill 代码静态安全扫描
 * - command_violation: 运行时危险命令拦截
 * - content_check: 内容安全审查（输入/输出拦截）
 * - token_usage: Token 使用量
 * - tool_call: 工具调用记录
 */

import { getScanResults, type ScanResult } from './config-scanner.js';
import type { SkillScanReport } from './skill-scanner.js';
import { getLogger } from './logger.js';
import {
  dbInsertSecurityEvent,
  dbInsertTokenUsage,
  dbInsertToolCall,
  dbQuerySecurityEvents,
  dbQueryTokenUsage,
  dbQueryToolCall,
  dbGetStats,
  dbGetDBPath,
  ensureDb,
} from './database.js';

// ─────────────────────────────────────────────────────────────
// 类型定义
// ─────────────────────────────────────────────────────────────

export interface SecurityEvent {
  event_id: string;
  category: 'config_security' | 'skill_security' | 'command_violation' | 'content_check' | 'gateway_auth';
  sub_category: string;
  sub_category_description: string;
  threat_level: 'critical' | 'high' | 'medium' | 'low' | 'info';
  event_time: string;
  recommendation: string;
  event_info: string;
}

export interface TokenUsageEvent {
  event_id: string;
  session_key: string;
  agent_id: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  event_time: string;
  extra_info: string;
}

export interface ToolCallEvent {
  event_id: string;
  session_key: string;
  agent_id: string;
  run_id: string;
  tool_call_id: string;
  tool_name: string;
  params: string;
  result: string;
  is_success: boolean;
  error_message: string;
  duration_ms: number;
  event_time: string;
}

// ─────────────────────────────────────────────────────────────
// sub_category → 推荐处置映射
// ─────────────────────────────────────────────────────────────

const SUB_CATEGORY_RECOMMENDATIONS: Record<string, string> = {
  'token-security': '请使用环境变量或密钥管理服务存储令牌和密钥，勿硬编码在配置中',
  'network-security': '请通过加密协议通信，绑定可信地址或通过反向代理访问',
  'session-security': '请立即配置认证并设置会话超时，切勿关闭安全功能',
  'data-protection': '请将工作区和日志限制在专用目录，禁用敏感信息记录',
  'plugin-security': '请仅安装来源可信的插件，配置白名单',
  'execution-security': '请启用执行安全检查，限制写入路径范围',
  'rate-compliance': '请配置速率限制，高安全标准建议不超过 30 次/分钟',
  'runtime-check': '请升级受支持的运行时版本，修复依赖漏洞，审查可疑配置文件',
  'ssrf-risk': '网址参数需经过严格验证和白名单过滤，禁止用户可控网址直接传入网络请求',
  'prompt-injection': '用户输入必须经过严格转义或结构化处理后再传入大语言模型，禁止直接拼接',
  'dangerous-syscall': '优先使用安全的接口替代命令执行，审查该调用的必要性',
  'credential-access': '确保访问密钥的目的正当且已获授权，勿将密钥写入日志或外部文件',
  'sensitive-path': '检查是否需要访问该敏感路径，移除不必要的路径引用',
  'dangerous-combination': '移除网络请求调用或限制访问目标；限制命令执行参数来源；禁止将用户输入写入可执行文件',
  'typosquatting': '安装前请验证来源和作者身份，勿安装来源不明的同名扩展',
  'metadata-quality': '请补充完整且真实的元数据，确保至少包含说明文件或配置文件',
  'install-hook': '禁止在安装脚本中执行远程下载并直接执行的操作，移除可疑的安装前后钩子',
  'permission-constraint': '建议添加引擎版本约束限制支持的运行时版本',
  'reverse-shell': '检测到反弹远程控制行为，请立即排查是否为恶意操作',
  'remote-code-execution': '检测到远程代码执行行为，请确认操作意图',
  'system-destruction': '检测到系统破坏操作，请立即终止并排查',
  'credential-theft': '检测到凭证窃取行为，请立即排查是否为恶意操作',
  'privilege-escalation': '检测到权限提升/持久化操作，请立即排查',
  'download-execute': '检测到下载执行链行为，请确认操作意图',
  'encoding-obfuscation': '检测到编码混淆行为，可能为绕过检测的恶意操作',
  'process-injection': '检测到进程注入行为，请立即排查',
  'kernel-module': '检测到内核模块操作，请确认是否为授权行为',
  'remote-service-disruption': '检测到远程服务中断操作，请确认操作意图',
  'other-dangerous': '检测到其他危险命令，请确认操作意图',
  'input-blocked': '拦截用户输入，禁止传入恶意提示词',
  'output-blocked': '拦截助手输出内容，终止本次响应',
  'check-passed': '内容检查通过，无异常',
  'auth-success': '认证成功，记录来源和认证方式',
  'auth-failed': '认证失败，请检查认证凭证是否正确，排查是否为暴力破解或凭证泄露',
  'auth-failed-invalid-token': 'Token 无效或已过期，请检查 Gateway 配置的令牌',
  'auth-failed-wrong-credentials': '认证凭据错误，请确认用户名和密码是否正确',
  'auth-failed-rate-limited': '认证请求被限流，可能是暴力破解尝试，请检查访问来源',
  'auth-failed-unknown': '未知认证失败原因，请检查 Gateway 日志',
};

const SUB_CATEGORY_DESCRIPTIONS: Record<string, string> = {
  'token-security': '令牌密钥安全',
  'network-security': '网络安全',
  'session-security': '会话安全',
  'data-protection': '数据保护',
  'plugin-security': '插件安全',
  'execution-security': '执行安全',
  'rate-compliance': '速率限制',
  'runtime-check': '运行时检查',
  'ssrf-risk': '服务端请求伪造',
  'prompt-injection': '提示词注入',
  'dangerous-syscall': '危险系统调用',
  'credential-access': '凭证访问',
  'sensitive-path': '敏感路径访问',
  'dangerous-combination': '危险组合模式',
  'typosquatting': '名称仿冒',
  'metadata-quality': '元数据质量',
  'install-hook': '安装钩子风险',
  'permission-constraint': '权限约束缺失',
  'reverse-shell': '反弹Shell',
  'remote-code-execution': '远程代码执行',
  'system-destruction': '系统破坏',
  'credential-theft': '凭证窃取',
  'privilege-escalation': '权限提升',
  'download-execute': '下载执行',
  'encoding-obfuscation': '编码混淆',
  'process-injection': '进程注入',
  'kernel-module': '内核模块操作',
  'remote-service-disruption': '远程服务中断',
  'other-dangerous': '其他危险命令',
  'input-blocked': '输入拦截',
  'output-blocked': '输出拦截',
  'check-passed': '检查通过',
  'auth-success': 'Gateway 认证成功',
  'auth-failed': 'Gateway 认证失败',
  'auth-failed-invalid-token': 'Token 无效或已过期',
  'auth-failed-wrong-credentials': '认证凭据错误',
  'auth-failed-rate-limited': '认证请求被限流',
  'auth-failed-unknown': '未知认证失败',
};

// config_security rule → sub_category
const RULE_TO_SUB_CATEGORY: Record<string, string> = {
  'token-entropy': 'token-security', 'token-weak-pattern': 'token-security',
  'api-key-exposed': 'token-security', 'hardcoded-secrets': 'token-security',
  'private-key-leak': 'token-security', 'mnemonic-leak': 'token-security',
  'gateway-bind-exposed': 'network-security', 'tls-required': 'network-security',
  'cors-wildcard': 'network-security', 'api-endpoint-safety': 'network-security',
  'webhook-url-insecure': 'network-security', 'dangerous-flags': 'network-security',
  'env-injection': 'network-security', 'untrusted-proxy-config': 'network-security',
  'tailscale-remote-url-exposure': 'network-security', 'tailscale-enabled': 'network-security',
  'tailscale-security': 'network-security',
  'session-timeout-missing': 'session-security', 'session-ttl': 'session-security',
  'session-isolation': 'session-security', 'session-scope-broad': 'session-security',
  'gateway-auth-mode-insecure': 'session-security', 'gateway-auth-disabled': 'session-security',
  'workspace-not-restricted': 'data-protection', 'log-level-verbose': 'data-protection',
  'log-include-sensitive': 'data-protection', 'owner-display-info-leak': 'data-protection',
  'web-search-safety': 'data-protection',
  'plugins-allow-missing': 'plugin-security', 'plugin-source-untrusted': 'plugin-security',
  'unverified-plugin-source': 'plugin-security',
  'exec-security-disabled': 'execution-security', 'exec-permission-control': 'execution-security',
  'write-no-restrictions': 'execution-security', 'deny-commands-ineffective': 'execution-security',
  'dangerous-allow-commands': 'execution-security', 'native-commands-security': 'execution-security',
  'native-commands-auto': 'execution-security', 'mcp-untrusted-commands': 'execution-security',
  'rate-limiting': 'rate-compliance',
  'npm-audit': 'runtime-check', 'node-eol': 'runtime-check',
  'soul-md-injection': 'runtime-check', 'version-outdated': 'runtime-check',
  'agent-defaults-security': 'execution-security', 'internal-hooks-security': 'plugin-security',
  'default-port-exposed': 'network-security', 'browser-control-port': 'network-security',
  'webhooks-enabled': 'network-security', 'tools-profile-permissive': 'execution-security',
};

// skill_security rule → sub_category
const SKILL_RULE_TO_SUB_CATEGORY: Record<string, string> = {
  'skill-ssrf-risk': 'ssrf-risk', 'skill-prompt-injection': 'prompt-injection',
  'skill-dangerous-syscall': 'dangerous-syscall', 'skill-credential-access': 'credential-access',
  'skill-sensitive-path': 'sensitive-path', 'skill-dangerous-combination': 'dangerous-combination',
  'skill-typosquatting': 'typosquatting',
  'skill-metadata-missing': 'metadata-quality', 'skill-metadata-incomplete': 'metadata-quality',
  'skill-metadata-invalid': 'metadata-quality', 'skill-dangerous-install-hook': 'install-hook',
  'skill-no-engines-constraint': 'permission-constraint', 'skill-no-keywords': 'permission-constraint',
};

// ─────────────────────────────────────────────────────────────
// 事件 ID 生成
// ─────────────────────────────────────────────────────────────

function generateEventId(category: string): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 10);
  return `${category}_${timestamp}_${random}`;
}

// ─────────────────────────────────────────────────────────────
// config_security 转换
// ─────────────────────────────────────────────────────────────

function scanResultToSecurityEvent(result: ScanResult, category: string): Omit<SecurityEvent, 'event_id'> {
  const subCategory = RULE_TO_SUB_CATEGORY[result.rule] || result.rule;
  const recommendation = SUB_CATEGORY_RECOMMENDATIONS[subCategory] || result.suggestion || '请根据实际情况进行处理';
  const subCategoryDescription = SUB_CATEGORY_DESCRIPTIONS[subCategory] || subCategory;
  const eventInfo = [
    `规则: ${result.rule}`, `路径: ${result.path}`, `描述: ${result.message}`,
    result.currentValue !== undefined ? `当前值: ${JSON.stringify(result.currentValue)}` : '',
  ].filter(Boolean).join(' | ');
  return {
    category: category as SecurityEvent['category'],
    sub_category: subCategory,
    sub_category_description: subCategoryDescription,
    threat_level: result.severity,
    event_time: new Date().toISOString(),
    recommendation,
    event_info: eventInfo,
  };
}

// ─────────────────────────────────────────────────────────────
// skill_security 转换
// ─────────────────────────────────────────────────────────────

function skillFindingToSecurityEvent(
  skillName: string, skillPath: string, rule: string, severity: string, message: string,
): Omit<SecurityEvent, 'event_id'> {
  const subCategory = SKILL_RULE_TO_SUB_CATEGORY[rule] || rule;
  const recommendation = SUB_CATEGORY_RECOMMENDATIONS[subCategory] || '请根据 Skill 安全扫描建议进行处理';
  const subCategoryDescription = SUB_CATEGORY_DESCRIPTIONS[subCategory] || subCategory;
  const eventInfo = [
    `Skill: ${skillName}`, `路径: ${skillPath}`, `规则: ${rule}`,
    `威胁等级: ${severity}`, `描述: ${message}`,
  ].join(' | ');
  return {
    category: 'skill_security',
    sub_category: subCategory,
    sub_category_description: subCategoryDescription,
    threat_level: severity as SecurityEvent['threat_level'],
    event_time: new Date().toISOString(),
    recommendation,
    event_info: eventInfo,
  };
}

// ─────────────────────────────────────────────────────────────
// command_violation 转换
// ─────────────────────────────────────────────────────────────

function commandViolationToSecurityEvent(
  command: string, reason: string, source: string,
): Omit<SecurityEvent, 'event_id'> {
  const lowerReason = reason.toLowerCase();
  let subCategory = 'other-dangerous';
  if (lowerReason.includes('reverse shell') || (lowerReason.includes('shell') && lowerReason.includes('/dev/tcp'))) subCategory = 'reverse-shell';
  else if (lowerReason.includes('system destruction') || lowerReason.includes('rm -rf') || lowerReason.includes('mkfs')) subCategory = 'system-destruction';
  else if (lowerReason.includes('credential') || lowerReason.includes('lsass') || lowerReason.includes('password')) subCategory = 'credential-theft';
  else if (lowerReason.includes('privilege') || lowerReason.includes('potato') || lowerReason.includes('escalation')) subCategory = 'privilege-escalation';
  else if (lowerReason.includes('download') || (lowerReason.includes('curl') && lowerReason.includes('|'))) subCategory = 'download-execute';
  else if (lowerReason.includes('encoding') || lowerReason.includes('base64') || lowerReason.includes('obfuscation')) subCategory = 'encoding-obfuscation';
  else if (lowerReason.includes('process injection') || lowerReason.includes('gdb') || lowerReason.includes('ptrace')) subCategory = 'process-injection';
  else if (lowerReason.includes('kernel') || lowerReason.includes('insmod')) subCategory = 'kernel-module';
  else if (lowerReason.includes('remote-code-execution') || lowerReason.includes('node -e') || lowerReason.includes('python -c')) subCategory = 'remote-code-execution';
  else if (lowerReason.includes('service disruption') || lowerReason.includes('sshd') || lowerReason.includes('stop')) subCategory = 'remote-service-disruption';

  const recommendation = SUB_CATEGORY_RECOMMENDATIONS[subCategory] || '请立即终止该操作并排查原因';
  const subCategoryDescription = SUB_CATEGORY_DESCRIPTIONS[subCategory] || subCategory;
  const eventInfo = [`命令: ${command}`, `危险原因: ${reason}`, `检测来源: ${source}`].join(' | ');
  return {
    category: 'command_violation',
    sub_category: subCategory,
    sub_category_description: subCategoryDescription,
    threat_level: 'critical',
    event_time: new Date().toISOString(),
    recommendation,
    event_info: eventInfo,
  };
}

// ─────────────────────────────────────────────────────────────
// content_check 转换
// ─────────────────────────────────────────────────────────────

function contentCheckToSecurityEvent(
  stage: 'input' | 'output', content: string, suggestion: string,
  sessionId: string, reqMsgId: string,
): Omit<SecurityEvent, 'event_id'> {
  const isBlocked = suggestion === 'block';
  const subCategory = isBlocked ? (stage === 'input' ? 'input-blocked' : 'output-blocked') : 'check-passed';
  const recommendation = SUB_CATEGORY_RECOMMENDATIONS[subCategory] || '内容检查通过';
  const subCategoryDescription = SUB_CATEGORY_DESCRIPTIONS[subCategory] || subCategory;
  const eventInfo = [
    `阶段: ${stage === 'input' ? '用户输入' : 'AI 输出'}`,
    `建议: ${suggestion}`,
    `会话ID: ${sessionId || 'N/A'}`,
    `请求ID: ${reqMsgId || 'N/A'}`,
    `内容摘要: ${content.substring(0, 200)}${content.length > 200 ? '...' : ''}`,
  ].join(' | ');
  return {
    category: 'content_check',
    sub_category: subCategory,
    sub_category_description: subCategoryDescription,
    threat_level: isBlocked ? 'critical' : 'info',
    event_time: new Date().toISOString(),
    recommendation,
    event_info: eventInfo,
  };
}

// ─────────────────────────────────────────────────────────────
// gateway_auth 转换
// ─────────────────────────────────────────────────────────────

export interface GatewayAuthEventData {
  authMethod: string;
  clientId: string;
  reason?: string;
  source?: string;
  ip?: string;
  userAgent?: string;
}

function gatewayAuthToSecurityEvent(
  success: boolean, data: GatewayAuthEventData, eventTime?: string,
): Omit<SecurityEvent, 'event_id'> {
  let subCategory: string;
  let threatLevel: SecurityEvent['threat_level'];
  if (success) {
    subCategory = 'auth-success';
    threatLevel = 'info';
  } else {
    const reason = (data.reason || '').toLowerCase();
    if (reason.includes('invalid token') || reason.includes('expired') || reason.includes('token')) subCategory = 'auth-failed-invalid-token';
    else if (reason.includes('credentials') || reason.includes('password') || reason.includes('wrong')) subCategory = 'auth-failed-wrong-credentials';
    else if (reason.includes('rate') || reason.includes('limit') || reason.includes('too many')) subCategory = 'auth-failed-rate-limited';
    else subCategory = 'auth-failed-unknown';
    threatLevel = reason.includes('rate') || reason.includes('brute') ? 'high' : 'medium';
  }
  const recommendation = SUB_CATEGORY_RECOMMENDATIONS[subCategory] || (success ? '认证成功' : '请检查认证配置');
  const subCategoryDescription = SUB_CATEGORY_DESCRIPTIONS[subCategory] || subCategory;
  const eventInfo = [
    `认证方式: ${data.authMethod}`, `客户端ID: ${data.clientId}`, `结果: ${success ? '成功' : '失败'}`,
    data.source ? `来源: ${data.source}` : '',
    data.ip ? `IP地址: ${data.ip}` : '',
    data.userAgent ? `User-Agent: ${data.userAgent}` : '',
    data.reason ? `原因: ${data.reason}` : '',
  ].filter(Boolean).join(' | ');
  return {
    category: 'gateway_auth',
    sub_category: subCategory,
    sub_category_description: subCategoryDescription,
    threat_level: threatLevel,
    event_time: eventTime || new Date().toISOString(),
    recommendation,
    event_info: eventInfo,
  };
}

// ─────────────────────────────────────────────────────────────
// 公开 API：config_security
// ─────────────────────────────────────────────────────────────

export async function saveConfigSecurityEvents(): Promise<number> {
  const logger = getLogger();
  const { results } = getScanResults();
  if (results.length === 0) {
    logger?.info('[EventStore] config_security: 无问题项');
    return 0;
  }
  for (const r of results) {
    const event = scanResultToSecurityEvent(r, 'config_security');
    await dbInsertSecurityEvent(generateEventId('config_security'), event.category, event.sub_category,
      event.sub_category_description, event.threat_level, event.event_time, event.recommendation, event.event_info);
  }
  logger?.info(`[EventStore] config_security: 已落地 ${results.length} 条`);
  return results.length;
}

export async function saveRuntimeCheckEvents(
  soulResults: ScanResult[], npmResults: ScanResult[], nodeEolResults: ScanResult[],
): Promise<number> {
  const logger = getLogger();
  const allResults = [...soulResults, ...npmResults, ...nodeEolResults];
  if (allResults.length === 0) {
    logger?.info('[EventStore] runtime-check: 无问题项');
    return 0;
  }
  for (const r of allResults) {
    const event = scanResultToSecurityEvent(r, 'config_security');
    await dbInsertSecurityEvent(generateEventId('runtime_check'), event.category, event.sub_category,
      event.sub_category_description, event.threat_level, event.event_time, event.recommendation, event.event_info);
  }
  logger?.info(`[EventStore] runtime-check: 已落地 ${allResults.length} 条`);
  return allResults.length;
}

// ─────────────────────────────────────────────────────────────
// 公开 API：skill_security
// ─────────────────────────────────────────────────────────────

export async function saveSkillSecurityEvents(skillReports: Map<string, SkillScanReport>): Promise<number> {
  const logger = getLogger();
  let count = 0;
  for (const [skillName, report] of skillReports) {
    for (const finding of report.findings) {
      if (finding.severity === 'none') continue;
      const event = skillFindingToSecurityEvent(skillName, report.skillPath, finding.rule, finding.severity, finding.message);
      await dbInsertSecurityEvent(generateEventId('skill_security'), event.category, event.sub_category,
        event.sub_category_description, event.threat_level, event.event_time, event.recommendation, event.event_info);
      count++;
    }
  }
  if (count === 0) {
    logger?.info('[EventStore] skill_security: 无问题项');
  } else {
    logger?.info(`[EventStore] skill_security: 已落地 ${count} 条`);
  }
  return count;
}

// ─────────────────────────────────────────────────────────────
// 公开 API：command_violation
// ─────────────────────────────────────────────────────────────

export async function saveCommandViolationEvent(
  command: string, reason: string, source: 'local' | 'remote',
): Promise<void> {
  const logger = getLogger();
  const sourceText = source === 'local' ? '本地规则' : '远端API';
  const event = commandViolationToSecurityEvent(command, reason, sourceText);
  await dbInsertSecurityEvent(generateEventId('command_violation'), event.category, event.sub_category,
    event.sub_category_description, event.threat_level, event.event_time, event.recommendation, event.event_info);
  logger?.info(`[EventStore] command_violation: 已记录 - ${reason}`);
}

// ─────────────────────────────────────────────────────────────
// 公开 API：content_check
// ─────────────────────────────────────────────────────────────

export async function saveContentCheckEvent(
  content: string, stage: 'input' | 'output', suggestion: string,
  sessionId: string = '', reqMsgId: string = '',
): Promise<void> {
  const logger = getLogger();
  const event = contentCheckToSecurityEvent(stage, content, suggestion, sessionId, reqMsgId);
  await dbInsertSecurityEvent(generateEventId('content_check'), event.category, event.sub_category,
    event.sub_category_description, event.threat_level, event.event_time, event.recommendation, event.event_info);
  if (suggestion === 'block') {
    logger?.warn(`[EventStore] content_check: ${stage === 'input' ? '输入' : '输出'}被拦截`);
  }
}

// ─────────────────────────────────────────────────────────────
// 公开 API：gateway_auth
// ─────────────────────────────────────────────────────────────

export async function saveGatewayAuthEvent(
  success: boolean, data: GatewayAuthEventData, eventTime?: string,
): Promise<void> {
  const logger = getLogger();
  const event = gatewayAuthToSecurityEvent(success, data, eventTime);
  await dbInsertSecurityEvent(generateEventId('gateway_auth'), event.category, event.sub_category,
    event.sub_category_description, event.threat_level, event.event_time, event.recommendation, event.event_info);
  if (success) {
    logger?.info(`[EventStore] gateway_auth: 认证成功 - ${data.authMethod} from ${data.source || 'unknown'}`);
  } else {
    logger?.warn(`[EventStore] gateway_auth: 认证失败 - ${data.authMethod} from ${data.source || 'unknown'}: ${data.reason}`);
  }
}

// ─────────────────────────────────────────────────────────────
// 公开 API：token_usage
// ─────────────────────────────────────────────────────────────

export async function saveTokenUsageEvent(
  sessionKey: string, agentId: string, model: string,
  inputTokens: number, outputTokens: number, totalTokens: number,
  cacheReadTokens: number = 0, cacheWriteTokens: number = 0,
  extraInfo: Record<string, unknown> = {},
): Promise<void> {
  const logger = getLogger();
  await dbInsertTokenUsage(
    generateEventId('token_usage'),
    sessionKey || 'N/A', agentId || 'N/A', model || 'N/A',
    inputTokens, outputTokens, totalTokens,
    cacheReadTokens, cacheWriteTokens,
    new Date().toISOString(),
    JSON.stringify(extraInfo),
  );
  logger?.info(`[EventStore] token_usage: session=${sessionKey} model=${model} tokens=${totalTokens}`);
}

export async function readTokenUsageEvents(limit: number = 100): Promise<TokenUsageEvent[]> {
  const rows = await dbQueryTokenUsage({ limit });
  return rows as unknown as TokenUsageEvent[];
}

// ─────────────────────────────────────────────────────────────
// 公开 API：tool_call
// ─────────────────────────────────────────────────────────────

export async function saveToolCallEvent(
  sessionKey: string, agentId: string, runId: string, toolCallId: string,
  toolName: string, params: Record<string, unknown>, result: unknown,
  isSuccess: boolean, errorMessage: string, durationMs: number,
): Promise<void> {
  const logger = getLogger();
  await dbInsertToolCall(
    generateEventId('tool_call'),
    sessionKey || 'N/A', agentId || 'N/A', runId || 'N/A', toolCallId || 'N/A',
    toolName,
    JSON.stringify(params),
    JSON.stringify(result),
    isSuccess, errorMessage || 'none', durationMs ?? -1,
    new Date().toISOString(),
  );
  logger?.info(`[EventStore] tool_call: tool=${toolName} success=${isSuccess} duration=${durationMs}ms session=${sessionKey}`);
}

export async function readToolCallEvents(limit: number = 100): Promise<ToolCallEvent[]> {
  const rows = await dbQueryToolCall({ limit });
  return rows.map(row => ({
    ...row,
    is_success: Boolean(row.is_success),
  })) as unknown as ToolCallEvent[];
}

// ─────────────────────────────────────────────────────────────
// 读取接口
// ─────────────────────────────────────────────────────────────

export async function readConfigSecurityEvents(filter: {
  category?: string; subCategory?: string; threatLevel?: string; limit?: number;
} = {}): Promise<SecurityEvent[]> {
  return await dbQuerySecurityEvents(filter) as unknown as SecurityEvent[];
}

export async function readSkillSecurityEvents(limit: number = 100): Promise<SecurityEvent[]> {
  return await dbQuerySecurityEvents({ category: 'skill_security', limit }) as unknown as SecurityEvent[];
}

export async function readCommandViolationEvents(limit: number = 100): Promise<SecurityEvent[]> {
  return await dbQuerySecurityEvents({ category: 'command_violation', limit }) as unknown as SecurityEvent[];
}

export async function readContentCheckEvents(limit: number = 100): Promise<SecurityEvent[]> {
  return await dbQuerySecurityEvents({ category: 'content_check', limit }) as unknown as SecurityEvent[];
}

export async function readGatewayAuthEvents(limit: number = 100): Promise<SecurityEvent[]> {
  return await dbQuerySecurityEvents({ category: 'gateway_auth', limit }) as unknown as SecurityEvent[];
}

// ─────────────────────────────────────────────────────────────
// 统计 & 路径接口
// ─────────────────────────────────────────────────────────────

export { dbGetStats as getEventStoreStats, dbGetDBPath as getDBPath };
