import path from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { execSync } from "node:child_process";

import type { Logger } from "../types.js";

// ─── Types ───────────────────────────────────────────────────────────────────

interface ScanConfig {
  searchStrings: string[];
  matchMode: "any" | "all";
  timeout: number;
  protocols: ("http" | "https")[];
  uris: string[];
  skipCommonPorts: boolean;
  commonPorts: number[];
  maxPorts: number;
  outputFormat: "json" | "console";
  showResponseContent: boolean;
}

interface PortProbeResult {
  protocol: string;
  port: number;
  uri: string;
  statusCode: number | null;
  headers: Record<string, string | string[] | undefined> | null;
  body: string | null;
  matches: string[];
  error: string | null;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const COLORS = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
} as const;

const TCP_LISTEN_STATE = 0x0a;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function colorize(text: string, color: keyof typeof COLORS): string {
  return `${COLORS[color]}${text}${COLORS.reset}`;
}

/** Convert a hex port string to decimal number. */
function hexToPort(hex: string): number {
  return parseInt(hex, 16);
}

/** Whether a port is in the common-ports skip list. */
function shouldSkipPort(port: number, config: ScanConfig): boolean {
  return config.skipCommonPorts && config.commonPorts.includes(port);
}

/** Sort and deduplicate a number array. */
function sortPorts(ports: number[]): number[] {
  return [...new Set(ports)].sort((a, b) => a - b);
}

// ─── Config Loading ──────────────────────────────────────────────────────────

function loadScanConfig(): ScanConfig | null {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const configFileName =
    os.platform() === "win32"
      ? "scan-config-windows.json"
      : "scan-config.json";

  try {
    const raw = fs.readFileSync(path.join(__dirname, configFileName), "utf-8");
    return JSON.parse(raw) as ScanConfig;
  } catch {
    return null;
  }
}

// ─── Port Discovery ──────────────────────────────────────────────────────────

/**
 * Parse `/proc/net/tcp` or `/proc/net/tcp6` to extract listening ports
 * bound on all interfaces (0.0.0.0 or ::).
 */
function parseProcNet(
  procPath: string,
  ipv6: boolean,
  config: ScanConfig,
): number[] {
  try {
    const content = fs.readFileSync(procPath, "utf-8");
    const ports = new Set<number>();

    const allInterfacesAddr = ipv6
      ? "00000000000000000000000000000000"
      : "00000000";

    for (const line of content.split("\n").slice(1)) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 10) continue;

      const state = parseInt(parts[3], 16);
      if (state !== TCP_LISTEN_STATE) continue;

      const [addrHex, portHex] = parts[1].split(":");
      if (addrHex === allInterfacesAddr) {
        const port = hexToPort(portHex);
        if (!shouldSkipPort(port, config)) {
          ports.add(port);
        }
      }
    }

    return [...ports];
  } catch {
    return [];
  }
}

/**
 * Use `netstat` to discover listening ports (works on Windows, macOS,
 * and as a Linux fallback).
 */
function getPortsViaNetstat(config: ScanConfig): number[] {
  try {
    const cmd =
      os.platform() === "win32"
        ? "netstat -an -p tcp"
        : "netstat -tlnp 2>/dev/null";

    const output = execSync(cmd, {
      encoding: "utf-8",
      windowsHide: true,
    });

    const ports = new Set<number>();

    for (const line of output.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      const parts = trimmed.split(/\s+/);
      const hasListenState = parts.some(
        (p) =>
          p.toUpperCase() === "LISTENING" || p.toUpperCase() === "LISTEN",
      );
      if (!hasListenState) continue;

      for (const part of parts) {
        const ipv4Match = part.match(/^(0\.0\.0\.0|\*):(\d+)$/);
        const ipv6Match = part.match(/^\[::\]:(\d+)$/);
        const match = ipv4Match || ipv6Match;

        if (match) {
          const port = parseInt(match[match.length - 1]);
          if (!shouldSkipPort(port, config)) {
            ports.add(port);
          }
          break;
        }
      }
    }

    return sortPorts([...ports]);
  } catch (error) {
    console.error(
      `${colorize("无法获取监听端口 (netstat):", "red")} ${(error as Error).toString()}`,
    );
    return [];
  }
}

/** Get listening ports across platforms, respecting the `maxPorts` limit. */
function getListeningPorts(config: ScanConfig, logs: string[]): number[] {
  try {
    let ports: number[];

    switch (os.platform()) {
      case "win32":
        ports = getPortsViaNetstat(config);
        break;
      case "linux": {
        const ipv4Ports = parseProcNet("/proc/net/tcp", false, config);
        const ipv6Ports = parseProcNet("/proc/net/tcp6", true, config);
        ports = sortPorts([...ipv4Ports, ...ipv6Ports]);
        break;
      }
      default:
        // macOS / other – fall back to netstat
        ports = getPortsViaNetstat(config);
    }

    if (ports.length > config.maxPorts) {
      logs.push(
        colorize(
          `警告: 发现 ${ports.length} 个监听端口，仅扫描前 ${config.maxPorts} 个`,
          "yellow",
        ),
      );
      ports = ports.slice(0, config.maxPorts);
    }

    return ports;
  } catch (error) {
    console.error(
      `${colorize("无法获取监听端口:", "red")} ${(error as Error).toString()}`,
    );
    return [];
  }
}

// ─── HTTP Probing ────────────────────────────────────────────────────────────

/** Check whether the response body contains the configured search strings. */
function checkSearchStrings(
  body: string,
  config: ScanConfig,
): { found: boolean; matches: string[] } {
  if (!body) return { found: false, matches: [] };

  const matches = config.searchStrings.filter((str) => body.includes(str));
  const found =
    config.matchMode === "any"
      ? matches.length > 0
      : matches.length === config.searchStrings.length;

  return { found, matches };
}

/** Send a single HTTP request and return the probe result. */
function sendRequest(
  protocol: string,
  port: number,
  uri: string,
  config: ScanConfig,
): Promise<PortProbeResult> {
  const client = protocol === "https" ? https : http;
  const url = `${protocol}://localhost:${port}${uri}`;

  const base = {
    protocol,
    port,
    uri,
    error: null as string | null,
  };

  return new Promise((resolve) => {
    const req = client.get(
      url,
      {
        timeout: config.timeout,
        headers: { "User-Agent": "OpenClaw-PortScanner/1.0" },
      },
      (res) => {
        let data = "";

        res.on("data", (chunk: Buffer) => {
          data += chunk;
        });

        res.on("end", () => {
          const { matches } = checkSearchStrings(data, config);
          resolve({
            ...base,
            statusCode: res.statusCode ?? null,
            headers: res.headers as PortProbeResult["headers"],
            body: config.showResponseContent ? data.substring(0, 200) : null,
            matches,
          });
        });
      },
    );

    req.on("error", (err: Error) => {
      resolve({
        ...base,
        statusCode: null,
        headers: null,
        body: null,
        matches: [],
        error: err.message,
      });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({
        ...base,
        statusCode: null,
        headers: null,
        body: null,
        matches: [],
        error: "Timeout",
      });
    });
  });
}

/** Probe a single port with all configured protocols and URIs. */
async function probePort(
  port: number,
  config: ScanConfig,
): Promise<PortProbeResult[]> {
  const results: PortProbeResult[] = [];

  for (const protocol of config.protocols) {
    for (const uri of config.uris) {
      try {
        results.push(await sendRequest(protocol, port, uri, config));
      } catch (error) {
        results.push({
          protocol,
          port,
          uri,
          statusCode: null,
          headers: null,
          body: null,
          matches: [],
          error: (error as Error).toString(),
        });
      }
    }
  }

  return results;
}

// ─── Result Formatting ───────────────────────────────────────────────────────

function formatResultsJSON(
  results: PortProbeResult[],
  config: ScanConfig,
): string {
  const output = {
    timestamp: new Date().toISOString(),
    config: {
      searchStrings: config.searchStrings,
      matchMode: config.matchMode,
      protocols: config.protocols,
    },
    results,
    summary: {
      total: results.length,
      withMatches: results.filter((r) => r.matches.length > 0).length,
      errors: results.filter((r) => r.error).length,
    },
  };
  return JSON.stringify(output, null, 2);
}

function formatResultsConsole(results: PortProbeResult[]): string {
  const lines: string[] = [`\n${colorize("=== 扫描结果 ===", "cyan")}`];
  let foundAny = false;

  for (const result of results) {
    const { protocol, port, uri, statusCode, error, matches, body } = result;

    if (error) {
      lines.push(
        `${colorize(`[${protocol}]:${port}${uri}`, "yellow")} ${colorize("错误", "red")}: ${error}`,
      );
      continue;
    }

    const statusColor =
      statusCode! >= 200 && statusCode! < 300 ? "green" : "yellow";
    const hasMatches = matches.length > 0;
    const matchFlag = hasMatches
      ? ` ${colorize(`⚠️ 匹配: ${matches.join(", ")}`, "red")}`
      : "";

    if (hasMatches) foundAny = true;

    lines.push(
      `${colorize(`[${protocol}]:${port}${uri}`, "cyan")} ${colorize(String(statusCode), statusColor)}${matchFlag}`,
    );

    if (body) {
      lines.push(
        `  ${colorize("响应片段:", "magenta")} ${body.substring(0, 100)}...`,
      );
    }
  }

  lines.push(
    foundAny
      ? colorize("⚠️ 警告: 发现包含搜索字符串的响应！", "red")
      : colorize("✓ 未发现包含搜索字符串的响应", "green"),
  );

  return lines.join("\n");
}

function buildMatchedSummary(matchedResults: PortProbeResult[]): string {
  if (matchedResults.length === 0) return "";

  const lines = [
    colorize(
      `发现 ${matchedResults.length} 个包含搜索字符串的响应:`,
      "red",
    ),
  ];
  for (const r of matchedResults) {
    lines.push(
      `  - ${r.protocol}://localhost:${r.port}${r.uri} (匹配: ${r.matches.join(", ")})`,
    );
  }
  return lines.join("\n");
}

// ─── Main Entry ──────────────────────────────────────────────────────────────

export default async function scanHolePort(logger: Logger): Promise<void> {
  const config = loadScanConfig();
  if (!config) {
    logger.error("配置文件读取失败");
    return;
  }

  const logs: string[] = [
    colorize("配置信息:", "cyan"),
    `平台: ${os.platform() === "win32" ? "(Windows)" : "(Linux)"}`,
    `搜索字符串: ${config.searchStrings.join(", ")}`,
    `匹配模式: ${config.matchMode}`,
    `超时时间: ${config.timeout}ms`,
    `协议: ${config.protocols.join(", ")}`,
  ];

  if (config.skipCommonPorts) {
    logs.push(`跳过常见端口: ${config.commonPorts.join(", ")}`);
  }

  logs.push(colorize("正在扫描监听在 0.0.0.0 的端口...", "cyan"));

  const ports = getListeningPorts(config, logs);
  if (ports.length === 0) {
    logs.push(colorize("未找到监听端口", "yellow"));
    logger.info(logs.join("\n"));
    return;
  }

  logs.push(
    `${colorize(`发现 ${ports.length} 个监听端口:`, "cyan")} ${ports.join(", ")}`,
  );

  // Probe each port sequentially
  const allResults: PortProbeResult[] = [];
  for (const port of ports) {
    logs.push(colorize(`正在探测端口 ${port}...`, "cyan"));
    allResults.push(...(await probePort(port, config)));
  }

  // Format and append results
  const formatted =
    config.outputFormat === "json"
      ? formatResultsJSON(allResults, config)
      : formatResultsConsole(allResults);
  logs.push(formatted);

  // Append matched-results summary
  const matchedResults = allResults.filter((r) => r.matches.length > 0);
  const matchedSummary = buildMatchedSummary(matchedResults);
  if (matchedSummary) {
    logs.push(matchedSummary);
  }

  logger.info(logs.join("\n"));
}