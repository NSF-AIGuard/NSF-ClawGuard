import requestManager from "./request.js";
import { checkCommandSafety } from "./command-security.js";
import type FormData from "form-data";
import type { IInputMsgData } from "./types.js";
import { getLogger } from "./logger.js";

interface IViolation {
  command: string;
  reason: string;
  level: "critical" | "high" | "medium" | "low" | "info";
  occurred_at: string;
}

const violationQueue: IViolation[] = [];
let isReporting = false;
let reportTimer: ReturnType<typeof setInterval> | null = null;

function addViolation(violation: IViolation): void {
  violationQueue.push(violation);
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
