// import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import requestManager from "./src/request.js";
import initializeLogger from "./src/logger.js";
import {
  checkContent,
  checkCommad,
  startViolationReporter,
  startHeartbeatReporter,
  uploadDetectFile,
} from "./src/api.js";
import {
  getScanResults,
  checkSoulMdInjection,
  checkNpmAudit,
  checkNodeEol,
} from "./src/config-scanner.js";
import { scanAllSkills } from "./src/skill-scanner.js";
import registerHttpRoute from "./src/server/index.js";
import {
  saveConfigSecurityEvents,
  saveRuntimeCheckEvents,
  saveSkillSecurityEvents,
  saveCommandViolationEvent,
  saveContentCheckEvent,
  saveTokenUsageEvent,
  saveToolCallEvent,
} from "./src/event-store.js";
import {
  dbInsertGWAuthLog,
  dbGetDBPath,
  dbGetStats,
  dbQueryGWAuthLogs,
  ensureDb,
} from "./src/database.js";
import registerCli from "./src/cli/index.js";

import type {
  OpenClawPluginApi,
  PluginHookAgentContext,
  PluginHookLlmOutputEvent,
} from "./src/types.js";

export default async function register(api: OpenClawPluginApi) {
  const pluginVersion = api.version;
  const hackLogger = initializeLogger(api);
  const ok = requestManager.initialize(hackLogger);
  registerCli(api, hackLogger, uploadDetectFile);
  registerHttpRoute(api);
  await ensureDb();
  // 启动时运行配置文件安全扫描
  const { results } = getScanResults();
  if (results.length > 0) {
    const critical = results.filter((r) => r.severity === "critical");
    const mediums = results.filter((r) => r.severity === "medium");

    if (critical.length > 0) {
      hackLogger.warn(`🔴 配置安全扫描发现 ${critical.length} 个严重问题`);
      for (const r of critical) {
        hackLogger.warn(`   - ${r.path}: ${r.message}`);
      }
    }
    if (mediums.length > 0) {
      hackLogger.info(`🟡 配置安全扫描发现 ${mediums.length} 个中危问题`);
    }
    if (critical.length === 0 && mediums.length === 0) {
      hackLogger.info(`✅ 配置安全扫描: 未发现安全问题`);
    }

    try {
      const savedCount = await saveConfigSecurityEvents();
      if (savedCount > 0) {
        hackLogger.info(`📝 已将 ${savedCount} 条配置安全事件落地到 CSV`);
      }
    } catch (err) {
      hackLogger.error(`🔍 CSV 落地失败: ${err}`);
    }
  } else {
    hackLogger.info(`✅ 配置安全扫描: 无问题或无法加载配置`);
  }

  // ── 运行时安全检查 ──────────────────────────────────────
  // SOUL.md 提示注入检测
  let soulResults: ReturnType<typeof checkSoulMdInjection> = [];
  try {
    soulResults = checkSoulMdInjection();
    if (soulResults.length > 0) {
      hackLogger.warn(
        `🔴 SOUL.md 提示注入检测: 发现 ${soulResults.length} 个问题`,
      );
      for (const r of soulResults) {
        hackLogger.warn(`   - ${r.path}: ${r.message}`);
      }
    } else {
      hackLogger.info(`✅ SOUL.md 提示注入检测: 未发现问题`);
    }
  } catch (error) {
    hackLogger.error(`🔍 SOUL.md 检测失败: ${error}`);
  }

  // npm 依赖漏洞扫描
  let npmResults: ReturnType<typeof checkNpmAudit> = [];
  try {
    npmResults = checkNpmAudit();
    if (npmResults.length > 0) {
      const r = npmResults[0];
      if (r.severity === "critical") {
        hackLogger.error(`🔴 npm audit: ${r.message}`);
      } else if (r.severity === "medium") {
        hackLogger.warn(`🟠 npm audit: ${r.message}`);
      } else {
        hackLogger.info(`🟡 npm audit: ${r.message}`);
      }
    } else {
      hackLogger.info(`✅ npm audit: 未发现已知漏洞`);
    }
  } catch (error) {
    hackLogger.error(`🔍 npm audit 检测失败: ${error}`);
  }

  // Node.js 版本 EOL 检测
  let nodeEolResults: ReturnType<typeof checkNodeEol> = [];
  try {
    nodeEolResults = checkNodeEol();
    if (nodeEolResults.length > 0) {
      const r = nodeEolResults[0];
      if (r.severity === "critical") {
        hackLogger.error(`🔴 Node.js 版本 EOL: ${r.message}`);
      } else {
        hackLogger.warn(`🟡 Node.js 版本 EOL: ${r.message}`);
      }
    } else {
      hackLogger.info(`✅ Node.js 版本正常`);
    }
  } catch (error) {
    hackLogger.error(`🔍 Node.js 版本检测失败: ${error}`);
  }

  // 落地 runtime-check 事件（soul-md-injection, npm-audit, node-eol）
  try {
    const savedCount = await saveRuntimeCheckEvents(
      soulResults,
      npmResults,
      nodeEolResults,
    );
    if (savedCount > 0) {
      hackLogger.info(`📝 已将 ${savedCount} 条运行时检测事件落地到 CSV`);
    }
  } catch (err) {
    hackLogger.error(`🔍 runtime-check CSV 落地失败: ${err}`);
  }

  // ── Skill 本地静态安全扫描 ──────────────────────────────
  try {
    const skillReports = scanAllSkills();
    let skillCritical = 0,
      skillHigh = 0,
      skillMedium = 0,
      skillLow = 0;
    for (const report of skillReports.values()) {
      if (report.maxSeverity === "critical") skillCritical++;
      else if (report.maxSeverity === "high") skillHigh++;
      else if (report.maxSeverity === "medium") skillMedium++;
      else if (report.maxSeverity === "low") skillLow++;
    }
    if (skillCritical > 0) {
      hackLogger.error(
        `🔴 Skill 安全扫描: 发现 ${skillCritical} 个 Critical / ${skillHigh} 个 High 问题`,
      );
      for (const [name, report] of skillReports) {
        if (report.maxSeverity === "critical") {
          hackLogger.error(`   🔴 ${name}: ${report.totalFindings} 个问题`);
        }
      }
    } else if (skillHigh > 0) {
      hackLogger.warn(
        `🟠 Skill 安全扫描: 发现 ${skillHigh} 个 High / ${skillMedium} 个 Medium 问题`,
      );
    } else if (skillMedium > 0 || skillLow > 0) {
      hackLogger.info(
        `🟡 Skill 安全扫描: 发现 ${skillMedium} 个 Medium / ${skillLow} 个 Low 问题`,
      );
    } else {
      hackLogger.info(`✅ Skill 安全扫描: 未发现问题`);
    }

    // 落地 skill_security 事件
    try {
      const savedCount = await saveSkillSecurityEvents(skillReports);
      if (savedCount > 0) {
        hackLogger.info(`📝 已将 ${savedCount} 条 Skill 安全事件落地到 CSV`);
      }
    } catch (err) {
      hackLogger.error(`🔍 skill_security CSV 落地失败: ${err}`);
    }
  } catch (error) {
    hackLogger.error(`🔍 Skill 安全扫描失败: ${error}`);
  }

  // 只有远端功能启用时才启动违规上报和心跳
  if (ok) {
    startViolationReporter(30000);
    startHeartbeatReporter(pluginVersion, 60000);
  }

  // Hook: Check user input for threats
  api.on("message_received", async (event: { content: string }) => {
    const content = event.content;
    if (!content || content.length === 0) return;
    try {
      const result = await checkContent({
        question: content,
        stage: "input",
        flowDetect: 0,
      });
      hackLogger.info(`result ${JSON.stringify(result)}`);
      if (result.suggestion === "block") {
        hackLogger.warn(`检查到风险提示词输入: ${content}`);
      }
      // 落地 content_check 事件
      try {
        saveContentCheckEvent(
          content,
          "input",
          result.suggestion,
          result.sessionId || "",
          result.reqMsgId || "",
        );
      } catch (err) {
        hackLogger.error(`🔍 content_check CSV 落地失败: ${err}`);
      }
    } catch (error) {
      hackLogger.error(`🔍 用户输入风险提示词输入检测失败 ${error}`);
    }
  });

  // Hook: Check model output for threats (after agent finishes)
  api.on("agent_end", async (event: { messages: unknown[] }) => {
    if (event.messages && event.messages.length > 0) {
      let modelOutput = "";
      for (let i = event.messages.length - 1; i >= 0; i--) {
        const msg = event.messages[i] as Record<string, unknown>;
        if (msg && msg.role === "assistant") {
          modelOutput =
            typeof msg.content === "string"
              ? msg.content
              : JSON.stringify(msg.content);
          break;
        }
      }

      if (!modelOutput) {
        const lastMessage = event.messages[event.messages.length - 1];
        modelOutput =
          typeof lastMessage === "string"
            ? lastMessage
            : JSON.stringify(lastMessage);
      }

      if (modelOutput) {
        try {
          const result = await checkContent({
            question: modelOutput,
            stage: "input",
            flowDetect: 0,
          });
          if (result.suggestion === "block") {
            hackLogger.warn(`检测到agent风险输出: ${modelOutput}`);
          }
          // 落地 content_check 事件
          try {
            saveContentCheckEvent(
              modelOutput,
              "output",
              result.suggestion,
              result.sessionId || "",
              result.reqMsgId || "",
            );
          } catch (err) {
            hackLogger.error(`🔍 content_check CSV 落地失败: ${err}`);
          }
        } catch (error) {
          hackLogger.error(`🔍 agent风险输出检测失败 ${error}`);
        }
      }
    }
  });

  api.on(
    "before_tool_call",
    async (event: {
      toolName: string;
      params: Record<string, unknown>;
      runId?: string;
      toolCallId?: string;
    }) => {
      hackLogger.warn(
        `🔍 -----》event.toolName：[${event.toolName}]-----》event.params[${JSON.stringify(event.params)}]， runId[${event.runId}], toolCallId[${event.toolCallId}]`,
      );
      if (event.toolName === "exec") {
        const command = event.params?.command as string;
        if (command) {
          try {
            const result = await checkCommad(command);
            if (!result.is_safe) {
              const sourceText =
                result.source === "local" ? "本地规则" : "远端API";
              hackLogger.warn(
                `🔍 [${sourceText}] 命令${command}存在危险行为: ${result.reason}`,
              );
              // 落地 command_violation 事件
              try {
                saveCommandViolationEvent(
                  command,
                  result.reason,
                  result.source as "local" | "remote",
                );
              } catch (err) {
                hackLogger.error(`🔍 command_violation CSV 落地失败: ${err}`);
              }
              return;
            }
          } catch (error) {
            hackLogger.error(
              `🔍 tool_call风险输出检测失败 ${command} ${error}`,
            );
            return;
          }
        }
        return;
      }

      if (event.toolName === "write" || event.toolName === "edit") {
        const filePath = event.params?.file_path as string;
        if (filePath) {
          try {
            const result = await checkCommad("", filePath);
            if (!result.is_safe) {
              const sourceText =
                result.source === "local" ? "本地规则" : "远端API";
              hackLogger.warn(
                `🔍 [${sourceText}] 路径${filePath}存在危险行为: ${result.reason}`,
              );
              // 落地 command_violation 事件
              try {
                saveCommandViolationEvent(
                  `[file_path: ${filePath}]`,
                  result.reason,
                  result.source as "local" | "remote",
                );
              } catch (err) {
                hackLogger.error(`🔍 command_violation CSV 落地失败: ${err}`);
              }
              return;
            }
          } catch (error) {
            hackLogger.error(
              `🔍 tool_call路径风险检测失败 ${filePath} ${error}`,
            );
            return;
          }
        }
        return;
      }
    },
  );

  api.on(
    "after_tool_call",
    async (
      event: {
        toolName: string;
        params: Record<string, unknown>;
        runId?: string;
        toolCallId?: string;
        result?: unknown;
        error?: string;
        durationMs?: number;
      },
      ctx: { sessionKey?: string; agentId?: string },
    ) => {
      hackLogger.warn(
        `🔍 after_tool_call: tool=${event.toolName} runId=${event.runId} toolCallId=${event.toolCallId} durationMs=${event.durationMs} error=${event.error || "none"}`,
      );
      // 记录到 CSV
      try {
        saveToolCallEvent(
          ctx.sessionKey || "N/A",
          ctx.agentId || "N/A",
          event.runId || "N/A",
          event.toolCallId || "N/A",
          event.toolName,
          event.params,
          event.result,
          !event.error,
          event.error || "",
          event.durationMs ?? -1,
        );
      } catch (err) {
        hackLogger.error(`🔍 tool_call CSV 落地失败: ${err}`);
      }
    },
  );

  // ── Gateway 日志文件监听（认证日志）──────────────────────
  // ── 跨平台获取 OpenClaw 日志目录 ────────────────────────────
  function getOpenClawLogDir(): string {
    if (process.env.OPENCLAW_LOGS_DIR) {
      return process.env.OPENCLAW_LOGS_DIR;
    }
    if (process.platform === "win32" && process.env.LOCALAPPDATA) {
      return path.join(process.env.LOCALAPPDATA, "Temp", "openclaw");
    }
    return path.join(os.tmpdir(), "openclaw");
  }

  function generateGWEventId(): string {
    return `gw_auth_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
  }

  function startGatewayAuthLogWatcher(): void {
    const logDir = getOpenClawLogDir();
    let today = new Date().toISOString().slice(0, 10);
    let logPath = path.join(logDir, `openclaw-${today}.log`);

    // 记录每个文件的读取位置（offset）
    const fileOffsets = new Map<string, number>();

    // 已写入的去重集合：line hash → true
    const writtenLineHashes = new Set<string>();

    // 启动时从已有 DB 加载已有的去重记录（避免重启后重复写入）
    async function loadWrittenLineHashes(): Promise<void> {
      try {
        // 从 SQLite DB 加载已记录的去重键（conn_id + timestamp + event_type）
        const rows = await dbQueryGWAuthLogs({ limit: 10000 });
        for (const row of rows) {
          const key = `${row["conn_id"]}:${row["log_timestamp"]}:${row["event_type"]}`;
          writtenLineHashes.add(key);
        }
        hackLogger.info(`[Gateway Auth] 从 DB 加载 ${rows.length} 条去重记录`);
      } catch (e) {
        hackLogger.warn(`[Gateway Auth] 加载去重记录失败: ${e}`);
      }
    }

    function getFileOffset(fPath: string): number {
      if (!fileOffsets.has(fPath)) {
        try {
          fileOffsets.set(fPath, fs.statSync(fPath).size);
        } catch {
          fileOffsets.set(fPath, 0);
        }
      }
      return fileOffsets.get(fPath)!;
    }

    function setFileOffset(fPath: string, offset: number): void {
      fileOffsets.set(fPath, offset);
    }

    function switchToNewLogFile(): void {
      const newDate = new Date().toISOString().slice(0, 10);
      if (newDate === today) return;
      const newLogPath = path.join(logDir, `openclaw-${newDate}.log`);
      hackLogger.info(
        `[Gateway Auth] 日期变更，切换日志文件: ${logPath} → ${newLogPath}`,
      );
      today = newDate;
      logPath = newLogPath;
      // 新文件从头读
      fileOffsets.set(logPath, 0);
    }

    function readNewLines(
      fPath: string,
      startOffset: number,
      endOffset: number,
    ): { offset: number; line: string }[] {
      if (endOffset <= startOffset) return [];
      try {
        const fd = fs.openSync(fPath, "r");
        const buf = Buffer.alloc(endOffset - startOffset);
        fs.readSync(fd, buf, 0, endOffset - startOffset, startOffset);
        fs.closeSync(fd);
        const content = buf.toString("utf-8");
        const result: { offset: number; line: string }[] = [];
        let currentOffset = startOffset;
        const lines = content.split("\n");
        for (const line of lines) {
          if (line.trim()) {
            result.push({ offset: currentOffset, line });
          }
          currentOffset += Buffer.byteLength(line + "\n", "utf-8");
        }
        return result;
      } catch {
        return [];
      }
    }

    function extractDisconnectInfo(text: string): {
      code: string;
      reason: string;
    } {
      const codeMatch = text.match(/code=(\S+)/);
      const reasonMatch = text.match(/reason=(\S+)/);
      return {
        code: codeMatch ? codeMatch[1] : "",
        reason: reasonMatch ? reasonMatch[1] : "",
      };
    }

    function extractConnId(text: string): string {
      const m = text.match(/conn=([a-f0-9-]+)/i);
      return m ? m[1] : "";
    }

    function extractRemote(text: string): string {
      const m = text.match(/remote=([\d.]+)/);
      return m ? m[1] : "";
    }

    function extractClient(text: string): { client: string; version: string } {
      // 格式: "client=openclaw-control-ui webchat v2026.3.28"
      const m = text.match(/client=([^\s]+)\s+(.+)/);
      if (m) {
        const versionMatch = m[2].match(/v?(\d+\.\d+\.\d+)/);
        return {
          client: m[1],
          version: versionMatch ? versionMatch[1] : m[2],
        };
      }
      return { client: "", version: "" };
    }

    function classifyEvent(text: string): string {
      if (/webchat disconnected/i.test(text)) return "disconnected";
      if (/unauthorized|token_mismatch|handshake\s*fail/i.test(text))
        return "auth_failed";
      if (/webchat connected|authorized/i.test(text)) return "auth_success";
      if (/gateway\/ws/i.test(text)) return "ws_other";
      return "unknown";
    }

    function isAuthEvent(text: string): boolean {
      return /webchat\s+(connected|disconnected)|unauthorized|token_mismatch|handshake\s*fail/i.test(
        text,
      );
    }

    function processLineItem(item: { offset: number; line: string }): void {
      const { line } = item;
      const fPath = logPath;

      let logEntry: Record<string, unknown>;
      try {
        logEntry = JSON.parse(line);
      } catch {
        return;
      }

      // 解析 msg0（本身是 JSON 字符串）
      const msg0Raw = logEntry["0"];
      let msg0Obj: Record<string, unknown> = {};
      if (typeof msg0Raw === "string") {
        try {
          msg0Obj = JSON.parse(msg0Raw);
        } catch {
          /* ignore */
        }
      }

      // 判断 subsystem
      const subsystem =
        typeof msg0Obj["subsystem"] === "string" ? msg0Obj["subsystem"] : "";
      if (!/gateway\/ws/i.test(subsystem)) return;

      const msg1 = logEntry["1"];
      const authData =
        msg1 && typeof msg1 === "object" && !Array.isArray(msg1)
          ? (msg1 as Record<string, unknown>)
          : null;
      const msgText =
        typeof msg1 === "string"
          ? msg1
          : typeof msg0Raw === "string"
            ? msg0Raw
            : "";

      if (!isAuthEvent(msgText)) return;

      // 提取字段
      const connId = extractConnId(msgText);
      const remoteIp = authData
        ? String(authData["remote"] || extractRemote(msgText))
        : extractRemote(msgText);
      const { client, version: clientVersion } = extractClient(msgText);
      const { code: disconnectCode, reason: disconnectReason } =
        extractDisconnectInfo(msgText);
      const authMode = authData
        ? String(authData["authMode"] || "token")
        : "token";
      const authReason = authData ? String(authData["authReason"] || "") : "";
      const userAgent = authData ? String(authData["userAgent"] || "") : "";

      // 提取 meta
      const meta = (logEntry["_meta"] || {}) as Record<string, unknown>;
      const logTimestamp =
        (meta["date"] as string) ||
        (logEntry["time"] as string) ||
        new Date().toISOString();
      const logLevel = (meta["logLevelName"] as string) || "";
      const runtime = (meta["runtime"] as string) || "";
      const runtimeVersion = (meta["runtimeVersion"] as string) || "";
      const hostname = (meta["hostname"] as string) || "";

      const eventType = classifyEvent(msgText);

      // 去重：使用 conn_id + timestamp + event_type 组合键
      const dedupKey = `${connId}:${logTimestamp}:${eventType}`;
      if (writtenLineHashes.has(dedupKey)) return;
      writtenLineHashes.add(dedupKey);

      void dbInsertGWAuthLog(
        generateGWEventId(),
        eventType,
        logTimestamp,
        connId,
        remoteIp,
        client,
        clientVersion,
        disconnectCode,
        disconnectReason,
        authMode,
        authReason,
        userAgent,
        subsystem,
        logLevel,
        runtime,
        runtimeVersion,
        hostname,
        fPath,
        line,
      );

      if (eventType === "disconnected") {
        hackLogger.info(
          `[Gateway Auth] disconnected - conn=${connId} code=${disconnectCode} reason=${disconnectReason}`,
        );
      } else if (eventType === "auth_success") {
        hackLogger.info(
          `[Gateway Auth] auth_success - conn=${connId} client=${client} remote=${remoteIp}`,
        );
      } else if (eventType === "auth_failed") {
        hackLogger.warn(
          `[Gateway Auth] auth_failed - conn=${connId} reason=${authReason || msgText.slice(0, 100)}`,
        );
      }
    }

    void loadWrittenLineHashes();

    setInterval(() => {
      try {
        switchToNewLogFile();

        const currentSize = getFileOffset(logPath);
        let actualSize: number;
        try {
          actualSize = fs.statSync(logPath).size;
        } catch {
          return;
        }

        if (actualSize > currentSize) {
          const items = readNewLines(logPath, currentSize, actualSize);
          for (const item of items) {
            try {
              processLineItem(item);
            } catch (e) {
              // 忽略单行处理错误
            }
          }
          setFileOffset(logPath, actualSize);
        } else if (actualSize < currentSize) {
          // 文件被轮转，从头开始
          setFileOffset(logPath, 0);
        }
      } catch (e) {
        // 忽略轮询错误
      }
    }, 1000);
  }

  try {
    startGatewayAuthLogWatcher();
    const stats = await dbGetStats();
    const dbPath = await dbGetDBPath();
    hackLogger.info(
      `[Gateway Auth] 日志监听已启动，DB: ${dbPath}, 当前记录: security_events=${stats.security_events} token_usage=${stats.token_usage} tool_call=${stats.tool_call} gateway_auth_logs=${stats.gateway_auth_logs}`,
    );
  } catch (err) {
    hackLogger.error(`[Gateway Auth] 日志监听启动失败: ${err}`);
  }

  // ── Token 使用量采集（llm_output 事件）───────────────────
  api.on(
    "llm_output",
    async (event: PluginHookLlmOutputEvent, ctx: PluginHookAgentContext) => {
      try {
        // 优先从 event.usage 字段获取（兼容 camelCase 和小写两种格式）
        let inputTokens = event.usage?.input ?? 0;
        let outputTokens = event.usage?.output ?? 0;
        let totalTokens = event.usage?.total ?? 0;
        let cacheReadTokens = event.usage?.cacheRead ?? 0;
        let cacheWriteTokens = event.usage?.cacheWrite ?? 0;
        let model = event.model || "N/A";

        hackLogger.info(
          `[Token Usage] session=${ctx.sessionKey} model=${model} input=${inputTokens} output=${outputTokens} cacheRead=${cacheReadTokens} cacheWrite=${cacheWriteTokens} total=${totalTokens}`,
        );

        // 仅在有实际 token 消耗时记录
        if (totalTokens > 0 || inputTokens > 0 || outputTokens > 0) {
          if (!totalTokens && (inputTokens > 0 || outputTokens > 0)) {
            totalTokens = inputTokens + outputTokens;
          }
          await saveTokenUsageEvent(
            ctx.sessionKey || "N/A",
            ctx.agentId || "N/A",
            model,
            inputTokens,
            outputTokens,
            totalTokens,
            cacheReadTokens,
            cacheWriteTokens,
            {
              sessionKey: ctx.sessionKey,
              agentId: ctx.agentId,
              model: event.model,
            },
          );
          hackLogger.debug(
            `[Token Usage] session=${ctx.sessionKey} model=${model} input=${inputTokens} output=${outputTokens} cacheRead=${cacheReadTokens} cacheWrite=${cacheWriteTokens} total=${totalTokens}`,
          );
        }
      } catch (err) {
        hackLogger.error(`[Token Usage] 记录失败: ${err}`);
      }
    },
  );
}
