import requestManager from "./request.js";
import { checkCommandSafety } from "./command-security.js";
import { getLogger } from "./logger.js";
import * as fs from "fs";
import * as path from "path";
import { currentPluginRoot } from "./utils.js";
import {
  ensureDb,
  dbQueryGWAuthLogs,
  dbQueryTokenUsage,
  dbQueryToolCall,
  dbQuerySecurityEvents,
} from "./database.js";
import type FormData from "form-data";
import type { IInputMsgData } from "./types.js";

interface IViolation {
  command: string;
  reason: string;
  level: "critical" | "high" | "medium" | "low" | "info";
  occurred_at: string;
}
interface IGatewayAuthLog {
  id: number;
  event_id: string;
  event_type: "auth_success" | "auth_failed" | "disconnected";
  log_timestamp: string;
  conn_id: string;
  remote_ip?: string;
  client?: string;
  client_version?: string;
  disconnect_code?: string;
  disconnect_reason?: string;
  auth_mode?: string;
  auth_reason?: string;
  user_agent?: string;
  subsystem?: string;
  log_level?: string;
  runtime?: string;
  runtime_version?: string;
  hostname?: string;
  log_file?: string;
  raw_line?: string;
}


const violationQueue: IViolation[] = [];
let isReporting = false;
let isGatewayAuthLogReporting = false;
let isTokenUsageLogReporting = false;
let isToolCallLogReporting = false;
let isSecurityEventLogReporting = false;

let reportTimer: ReturnType<typeof setInterval> | null = null;

let isDbReady = false;

export function setDbReady(): void {
  isDbReady = true;
}

interface UploadProgressConfig {
  gateway_auth_log: {
    last_uploaded_id: number;
    last_uploaded_time: string;
  };
  token_usage: {
    last_uploaded_id: number;
    last_uploaded_time: string;
  };
  tool_call: {
    last_uploaded_id: number;
    last_uploaded_time: string;
  };
  security_event_log: {
    last_uploaded_id: number;
    last_uploaded_time: string;
  };
}

const UPLOAD_CONFIG_FILE = "data/upload-progress.json";

function getUploadProgressFilePath(): string {
  return path.join(currentPluginRoot(), UPLOAD_CONFIG_FILE);
}

function loadUploadProgress(): UploadProgressConfig {
  const configPath = getUploadProgressFilePath();
  const defaultConfig: UploadProgressConfig = {
    gateway_auth_log: {
      last_uploaded_id: 0,
      last_uploaded_time: "",
    },
    token_usage: {
      last_uploaded_id: 0,
      last_uploaded_time: "",
    },
    tool_call: {
      last_uploaded_id: 0,
      last_uploaded_time: "",
    },
    security_event_log: {
      last_uploaded_id: 0,
      last_uploaded_time: "",
    },
  };

  try {
    if (fs.existsSync(configPath)) {
      const content = fs.readFileSync(configPath, "utf-8");
      const loadedConfig = JSON.parse(content) as Partial<UploadProgressConfig>;
      const mergedConfig: UploadProgressConfig = {
        gateway_auth_log: {
          ...defaultConfig.gateway_auth_log,
          ...loadedConfig.gateway_auth_log,
        },
        token_usage: {
          ...defaultConfig.token_usage,
          ...loadedConfig.token_usage,
        },
        tool_call: {
          ...defaultConfig.tool_call,
          ...loadedConfig.tool_call,
        },
        security_event_log: {
          ...defaultConfig.security_event_log,
          ...loadedConfig.security_event_log,
        },
      };
      return mergedConfig;
    }
  } catch (error) {
    const logger = getLogger();
    logger?.error(`[Config] 读取上传进度配置文件失败: ${error}`);
  }
  return defaultConfig;
}

function saveUploadProgress(config: UploadProgressConfig): void {
  const configPath = getUploadProgressFilePath();
  try {
    const configDir = path.dirname(configPath);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf-8");
  } catch (error) {
    const logger = getLogger();
    logger?.error(`[Config] 保存上传进度配置文件失败: ${error}`);
  }
}

function updateGatewayAuthLogUploadProgress(lastId: number): void {
  const config = loadUploadProgress();
  config.gateway_auth_log.last_uploaded_id = lastId;
  config.gateway_auth_log.last_uploaded_time = new Date().toISOString();
  saveUploadProgress(config);
}

function getLastUploadedId(): number {
  const config = loadUploadProgress();
  return config.gateway_auth_log.last_uploaded_id;
}

function updateTokenUsageUploadProgress(lastId: number): void {
  const config = loadUploadProgress();
  config.token_usage.last_uploaded_id = lastId;
  config.token_usage.last_uploaded_time = new Date().toISOString();
  saveUploadProgress(config);
}

function getLastUploadedTokenUsageId(): number {
  const config = loadUploadProgress();
  return config.token_usage.last_uploaded_id;
}

function updateToolCallUploadProgress(lastId: number): void {
  const config = loadUploadProgress();
  config.tool_call.last_uploaded_id = lastId;
  config.tool_call.last_uploaded_time = new Date().toISOString();
  saveUploadProgress(config);
}

function getLastUploadedToolCallId(): number {
  const config = loadUploadProgress();
  return config.tool_call.last_uploaded_id;
}

function updateSecurityEventLogUploadProgress(lastId: number): void {
  const config = loadUploadProgress();
  config.security_event_log.last_uploaded_id = lastId;
  config.security_event_log.last_uploaded_time = new Date().toISOString();
  saveUploadProgress(config);
}

function _getLastUploadedSecurityEventLogId(): number {
  const config = loadUploadProgress();
  return config.security_event_log.last_uploaded_id;
}

function addViolation(violation: IViolation): void {
  violationQueue.push(violation);
}
export async function addGatewayAuthLog(log: Omit<IGatewayAuthLog, "id">): Promise<void> {
  const { dbInsertGWAuthLog } = await import("./database.js");
  await dbInsertGWAuthLog(
    log.event_id,
    log.event_type,
    log.log_timestamp,
    log.conn_id,
    log.remote_ip || "",
    log.client || "",
    log.client_version || "",
    log.disconnect_code || "",
    log.disconnect_reason || "",
    log.auth_mode || "",
    log.auth_reason || "",
    log.user_agent || "",
    log.subsystem || "",
    log.log_level || "",
    log.runtime || "",
    log.runtime_version || "",
    log.hostname || "",
    log.log_file || "",
    log.raw_line || "",
  );
}

async function reportGatewayAuthLogs(): Promise<void> {
  const logger = getLogger();
  if (isGatewayAuthLogReporting || isPluginRevoked || !requestManager.isRemoteEnabled || !isDbReady) {
    return;
  }

  isGatewayAuthLogReporting = true;

  try {
    await ensureDb();
    const lastUploadedId = getLastUploadedId();
    const logs = await dbQueryGWAuthLogs({
      idAfter: lastUploadedId,
      limit: 500,
    });

    if (logs.length === 0) {
      return;
    }

    const logsForApi = logs.map((log) => ({
      event_id: log.event_id as string,
      event_type: log.event_type as "auth_success" | "auth_failed" | "disconnected",
      log_timestamp: log.log_timestamp as string,
      conn_id: log.conn_id as string,
      remote_ip: log.remote_ip as string,
      client: log.client as string,
      client_version: log.client_version as string,
      disconnect_code: log.disconnect_code as string,
      disconnect_reason: log.disconnect_reason as string,
      auth_mode: log.auth_mode as string,
      auth_reason: log.auth_reason as string,
      user_agent: log.user_agent as string,
      subsystem: log.subsystem as string,
      log_level: log.log_level as string,
      runtime: log.runtime as string,
      runtime_version: log.runtime_version as string,
      hostname: log.hostname as string,
      log_file: log.log_file as string,
      raw_line: log.raw_line as string,
    }));

    const response = await requestManager.post<
      ApiResponse<{
        errCode: number;
        errMsg: string;
        data: Record<string, unknown>;
      }>
    >("/api/v1/terminal/gateway-auth-logs", { logs: logsForApi });

    const result = unWrapData(response);
    const maxId = Math.max(...logs.map((log) => log.id as number));
    updateGatewayAuthLogUploadProgress(maxId);
  } catch (error) {
    logger?.error(`[API Error] /api/v1/terminal/gateway-auth-logs - 请求异常: ${error}`);
  } finally {
    isGatewayAuthLogReporting = false;
  }
}

export function startGatewayAuthLogReporter(intervalMs: number = 30000): void {
  const timerKey = "gatewayAuthLogReportTimer";
  if ((global as any)[timerKey]) {
    return;
  }
  (global as any)[timerKey] = setInterval(() => {
    reportGatewayAuthLogs();
  }, intervalMs);
}

export function stopGatewayAuthLogReporter(): void {
  const timerKey = "gatewayAuthLogReportTimer";
  if ((global as any)[timerKey]) {
    clearInterval((global as any)[timerKey]);
    (global as any)[timerKey] = null;
  }
}

export async function flushGatewayAuthLogs(): Promise<void> {
  await reportGatewayAuthLogs();
}

export async function getGatewayAuthLogQueueSize(): Promise<number> {
  try {
    await ensureDb();
    const logs = await dbQueryGWAuthLogs({ limit: 10000 });
    const lastUploadedId = getLastUploadedId();
    return logs.filter((log) => (log.id as number) > lastUploadedId).length;
  } catch {
    return 0;
  }
}

export function getLastUploadedGatewayAuthLogId(): number {
  return getLastUploadedId();
}

async function reportTokenUsageLogs(): Promise<void> {
  const logger = getLogger();
  if (isTokenUsageLogReporting || isPluginRevoked || !requestManager.isRemoteEnabled || !isDbReady) {
    return;
  }

  isTokenUsageLogReporting = true;

  try {
    await ensureDb();
    const lastUploadedId = getLastUploadedTokenUsageId();
    const logs = await dbQueryTokenUsage({
      idAfter: lastUploadedId,
      limit: 500,
    });

    if (logs.length === 0) {
      return;
    }

    const logsForApi = logs.map((log) => ({
      event_id: log.event_id as string,
      session_key: log.session_key as string,
      agent_id: log.agent_id as string,
      model: log.model as string,
      input_tokens: log.input_tokens as number,
      output_tokens: log.output_tokens as number,
      total_tokens: log.total_tokens as number,
      cache_read_tokens: log.cache_read_tokens as number,
      cache_write_tokens: log.cache_write_tokens as number,
      event_time: log.event_time as string,
      extra_info: log.extra_info ? JSON.parse(log.extra_info as string) : {},
    }));

    const response = await requestManager.post<
      ApiResponse<{
        errCode: number;
        errMsg: string;
        data: Record<string, unknown>;
      }>
    >("/api/v1/terminal/token-usage-logs", { logs: logsForApi });

    const result = unWrapData(response);
    const maxId = Math.max(...logs.map((log) => log.id as number));
    updateTokenUsageUploadProgress(maxId);
  } catch (error) {
    logger?.error(`[API Error] /api/v1/terminal/token-usage-logs - 请求异常: ${error}`);
  } finally {
    isTokenUsageLogReporting = false;
  }
}

export function startTokenUsageLogReporter(intervalMs: number = 30000): void {
  const timerKey = "tokenUsageLogReportTimer";
  if ((global as any)[timerKey]) {
    return;
  }
  (global as any)[timerKey] = setInterval(() => {
    reportTokenUsageLogs();
  }, intervalMs);
}

export function stopTokenUsageLogReporter(): void {
  const timerKey = "tokenUsageLogReportTimer";
  if ((global as any)[timerKey]) {
    clearInterval((global as any)[timerKey]);
    (global as any)[timerKey] = null;
  }
}

export async function flushTokenUsageLogs(): Promise<void> {
  await reportTokenUsageLogs();
}

export async function getTokenUsageLogQueueSize(): Promise<number> {
  try {
    await ensureDb();
    const logs = await dbQueryTokenUsage({ limit: 10000 });
    const lastUploadedId = getLastUploadedTokenUsageId();
    return logs.filter((log) => (log.id as number) > lastUploadedId).length;
  } catch {
    return 0;
  }
}

export function getLastUploadedTokenUsageLogId(): number {
  return getLastUploadedTokenUsageId();
}

async function reportToolCallLogs(): Promise<void> {
  const logger = getLogger();
  if (isToolCallLogReporting || isPluginRevoked || !requestManager.isRemoteEnabled || !isDbReady) {
    return;
  }

  isToolCallLogReporting = true;

  try {
    await ensureDb();
    const lastUploadedId = getLastUploadedToolCallId();
    const logs = await dbQueryToolCall({
      idAfter: lastUploadedId,
      limit: 500,
    });

    if (logs.length === 0) {
      return;
    }

    const logsForApi = logs.map((log) => ({
      event_id: log.event_id as string,
      session_key: log.session_key as string,
      agent_id: log.agent_id as string,
      run_id: log.run_id as string,
      tool_call_id: log.tool_call_id as string,
      tool_name: log.tool_name as string,
      params: log.params ? JSON.parse(log.params as string) : {},
      result: log.result ? JSON.parse(log.result as string) : {},
      is_success: Boolean(log.is_success),
      error_message: log.error_message as string,
      duration_ms: log.duration_ms as number,
      event_time: log.event_time as string,
    }));

    const response = await requestManager.post<
      ApiResponse<{
        errCode: number;
        errMsg: string;
        data: Record<string, unknown>;
      }>
    >("/api/v1/terminal/tool-call-logs", { logs: logsForApi });

    const result = unWrapData(response);
    const maxId = Math.max(...logs.map((log) => log.id as number));
    updateToolCallUploadProgress(maxId);
  } catch (error) {
    logger?.error(`[API Error] /api/v1/terminal/tool-call-logs - 请求异常: ${error}`);
  } finally {
    isToolCallLogReporting = false;
  }
}

export function startToolCallLogReporter(intervalMs: number = 30000): void {
  const timerKey = "toolCallLogReportTimer";
  if ((global as any)[timerKey]) {
    return;
  }
  (global as any)[timerKey] = setInterval(() => {
    reportToolCallLogs();
  }, intervalMs);
}

export function stopToolCallLogReporter(): void {
  const timerKey = "toolCallLogReportTimer";
  if ((global as any)[timerKey]) {
    clearInterval((global as any)[timerKey]);
    (global as any)[timerKey] = null;
  }
}

export async function flushToolCallLogs(): Promise<void> {
  await reportToolCallLogs();
}

export async function getToolCallLogQueueSize(): Promise<number> {
  try {
    await ensureDb();
    const logs = await dbQueryToolCall({ limit: 10000 });
    const lastUploadedId = getLastUploadedToolCallId();
    return logs.filter((log) => (log.id as number) > lastUploadedId).length;
  } catch {
    return 0;
  }
}

export function getLastUploadedToolCallLogId(): number {
  return getLastUploadedToolCallId();
}


async function reportViolations(): Promise<void> {
  const logger = getLogger();
  if (
    isReporting ||
    violationQueue.length === 0 ||
    isPluginRevoked ||
    !requestManager.isRemoteEnabled
  ) {
    return;
  }

  isReporting = true;

  const violationsToReport = violationQueue.splice(0, violationQueue.length);

  try {
    // logger?.info(`[API Request] POST /api/v1/terminal/violations - 开始上报违规信息, 数量: ${violationsToReport.length}`);
    const response = await requestManager.post<
      ApiResponse<{
        errCode: number;
        errMsg: string;
        data: Record<string, unknown>;
      }>
    >("/api/v1/terminal/violations", { violations: violationsToReport });

    const result = unWrapData(response);
    // logger?.info(`[API Response] /api/v1/terminal/violations - 上报成功, 响应数据: ${JSON.stringify(result)}`);
  } catch (error) {
    logger?.error(
      `[API Error] /api/v1/terminal/violations - 请求异常: ${error}`,
    );
    violationQueue.push(...violationsToReport);
  } finally {
    isReporting = false;
  }
}

export function startViolationReporter(intervalMs: number = 30000): void {
  if (reportTimer !== null) {
    return;
  }

  reportTimer = setInterval(() => {
    reportViolations();
  }, intervalMs);
}

export function stopViolationReporter(): void {
  if (reportTimer !== null) {
    clearInterval(reportTimer);
    reportTimer = null;
  }
}

export async function flushViolations(): Promise<void> {
  await reportViolations();
}

export function getViolationQueueSize(): number {
  return violationQueue.length;
}

let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
export let isPluginRevoked = false;

async function sendHeartbeat(pluginVersion: string): Promise<boolean> {
  const logger = getLogger();
  if (isPluginRevoked || !requestManager.isRemoteEnabled) {
    return false;
  }

  try {
    // logger?.info(`[API Request] POST /api/v1/terminal/heartbeat - plugin_version: ${pluginVersion}`);
    const response = await requestManager.post<
      ApiResponse<{
        errCode: number;
        errMsg: string;
        data: Record<string, unknown>;
      }>
    >("/api/v1/terminal/heartbeat", { plugin_version: pluginVersion });

    // const result = unWrapData(response);
    // logger?.info(`[API Response] /api/v1/terminal/heartbeat - 心跳成功, 响应数据: ${JSON.stringify(result)}`);
    return true;
  } catch (error) {
    logger?.error(
      `[API Error] /api/v1/terminal/heartbeat - 请求异常: ${error}`,
    );
    return false;
  }
}

async function heartbeatWithRevocationCheck(
  pluginVersion: string,
): Promise<void> {
  const logger = getLogger();
  if (isPluginRevoked || !requestManager.isRemoteEnabled) {
    return;
  }

  try {
    // logger?.info(`[API Request] POST /api/v1/terminal/heartbeat (revocation check) - plugin_version: ${pluginVersion}`);
    const response = await requestManager.post<
      ApiResponse<{
        errCode: number;
        errMsg: string;
        data: Record<string, unknown>;
      }>
    >("/api/v1/terminal/heartbeat", { plugin_version: pluginVersion });

    // const result = unWrapData(response);
    // logger?.info(`[API Response] /api/v1/terminal/heartbeat (revocation check) - 心跳成功, 响应数据: ${JSON.stringify(result)}`);
  } catch (error) {
    const axiosError = error as { response?: { status?: number } };
    if (axiosError.response?.status === 401) {
      logger?.error(
        `[API Error] /api/v1/terminal/heartbeat - 检测到插件被撤销 (401 Unauthorized)`,
      );
      isPluginRevoked = true;
    } else {
      logger?.error(
        `[API Error] /api/v1/terminal/heartbeat - 请求异常: ${error}`,
      );
    }
  }
}

export function startHeartbeatReporter(
  pluginVersion: string,
  intervalMs: number = 60000,
): void {
  if (heartbeatTimer !== null || isPluginRevoked) {
    return;
  }

  heartbeatWithRevocationCheck(pluginVersion);

  heartbeatTimer = setInterval(() => {
    heartbeatWithRevocationCheck(pluginVersion);
  }, intervalMs);
}

export function stopHeartbeatReporter(): void {
  if (heartbeatTimer !== null) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

export function isPluginRevokedStatus(): boolean {
  return isPluginRevoked;
}

export async function sendHeartbeatOnce(
  pluginVersion: string,
): Promise<boolean> {
  return await sendHeartbeat(pluginVersion);
}

interface ICheckContentResponse {
  safe: boolean;
  suggestion: "block" | "pass";
  sessionId: string;
  reqMsgId: string;
  securityAnswer: string;
}
// 修改：明确 Axios 响应结构
interface ApiResponse<T> {
  data: T;
}
function unWrapData<T>(response: { data: { data: T } }): T {
  return response.data.data;
}

export function checkContent(data: IInputMsgData) {
  if (!requestManager.isRemoteEnabled) {
    return Promise.resolve({
      safe: true,
      suggestion: "pass" as const,
      sessionId: "",
      reqMsgId: "",
      securityAnswer: "",
    });
  }
  return requestManager
    .post<ApiResponse<ICheckContentResponse>>("/api/v1/question/check", data)
    .then(unWrapData);
}

interface ICheckResponseData {
  is_safe: boolean;
  categories: Array<string>;
  reason: string;
  details: {
    matched_pattern: string;
  };
  source: "local" | "remote";
}
export function checkCommad(command: string, filePath?: string) {
  const localMatches = checkCommandSafety(command, filePath);
  if (localMatches.length > 0) {
    const matchedReasons = localMatches.map((m) => m.name).join("; ");
    const violation: IViolation = {
      command: command || `[file_path: ${filePath}]`,
      reason: matchedReasons,
      level: "critical",
      occurred_at: new Date().toISOString(),
    };
    addViolation(violation);

    return Promise.resolve({
      is_safe: false,
      categories: ["command"],
      reason: matchedReasons,
      details: {
        matched_pattern: matchedReasons,
      },
      source: "local",
    });
  }

  if (!requestManager.isRemoteEnabled) {
    return Promise.resolve({
      is_safe: true,
      categories: [],
      reason: "",
      details: { matched_pattern: "" },
      source: "local" as const,
    });
  }

  const data = {
    check_type: "command",
    command,
  };
  return requestManager
    .post<
      ApiResponse<ICheckResponseData>
    >("/api/v1/question/openclaw-check", data)
    .then((response) => {
      const result = unWrapData(response);
      return {
        ...result,
        source: "remote" as const,
      };
    });
}

export function uploadDetectFile(formData: FormData) {
  if (!requestManager.isRemoteEnabled) {
    return Promise.reject(new Error("远端功能已禁用，无法上传检测文件"));
  }
  const newHeaders = formData.getHeaders();
  return requestManager
    .post<ApiResponse<any>>("/api/v1/terminal/scan", formData, {
      headers: newHeaders as any,
    })
    .then(unWrapData);
}

async function reportSecurityEventLogs(): Promise<void> {
  const logger = getLogger();
  if (isSecurityEventLogReporting || isPluginRevoked || !requestManager.isRemoteEnabled || !isDbReady) {
    return;
  }

  isSecurityEventLogReporting = true;

  try {
    await ensureDb();
    const lastUploadedId = _getLastUploadedSecurityEventLogId();
    const logs = await dbQuerySecurityEvents({
      idAfter: lastUploadedId,
      limit: 500,
    });

    if (logs.length === 0) {
      return;
    }

    const logsForApi = logs.map((log) => ({
      event_id: log.event_id as string,
      category: log.category as string,
      sub_category: log.sub_category as string,
      sub_category_description: log.sub_category_description as string,
      threat_level: log.threat_level as string,
      event_time: log.event_time as string,
      recommendation: log.recommendation as string,
      event_info: log.event_info as string,
    }));

    const response = await requestManager.post<
      ApiResponse<{
        errCode: number;
        errMsg: string;
        data: Record<string, unknown>;
      }>
    >("/api/v1/terminal/security-event-logs", { logs: logsForApi });

    const result = unWrapData(response);
    const maxId = Math.max(...logs.map((log) => log.id as number));
    updateSecurityEventLogUploadProgress(maxId);
  } catch (error) {
    logger?.error(`[API Error] /api/v1/terminal/security-event-logs - 请求异常: ${error}`);
  } finally {
    isSecurityEventLogReporting = false;
  }
}

export function startSecurityEventLogReporter(intervalMs: number = 30000): void {
  const timerKey = "securityEventLogReportTimer";
  if ((global as any)[timerKey]) {
    return;
  }
  (global as any)[timerKey] = setInterval(() => {
    reportSecurityEventLogs();
  }, intervalMs);
}

export function stopSecurityEventLogReporter(): void {
  const timerKey = "securityEventLogReportTimer";
  if ((global as any)[timerKey]) {
    clearInterval((global as any)[timerKey]);
    (global as any)[timerKey] = null;
  }
}

export async function flushSecurityEventLogs(): Promise<void> {
  await reportSecurityEventLogs();
}

export async function getSecurityEventLogQueueSize(): Promise<number> {
  try {
    await ensureDb();
    const logs = await dbQuerySecurityEvents({ limit: 10000 });
    const lastUploadedId = _getLastUploadedSecurityEventLogId();
    return logs.filter((log) => (log.id as number) > lastUploadedId).length;
  } catch {
    return 0;
  }
}

export function getLastUploadedSecurityEventLogId(): number {
  return _getLastUploadedSecurityEventLogId();
}

