import { createRequire } from "node:module";
import * as path from "node:path";
import type * as fsTypes from "node:fs";

// ESM 的 import * as fs 创建的是不可变命名空间，无法赋值
// 通过 createRequire 获取可变的 CJS fs 对象，与 import * as fs 共享同一模块缓存
const require = createRequire(import.meta.url);
const fs = require("node:fs") as typeof import("node:fs");

/**
 * 匹配 openclaw-YYYY-MM-DD.log 格式的文件名
 */
const OPENCLAW_LOG_PATTERN = /openclaw-\d{4}-\d{2}-\d{2}\.log$/i;

/**
 * 从任意路径中提取文件名并检测是否为 openclaw 日志文件
 */
function isOpenClawLog(filePath: unknown): boolean {
  if (typeof filePath !== "string") return false;
  try {
    const basename = path.basename(filePath);
    return OPENCLAW_LOG_PATTERN.test(basename);
  } catch {
    return false;
  }
}

// ── 发布订阅机制 ────────────────────────────────────────
type LogWriteSubscriber = (data: string, filePath: string) => void;
const subscribers = new Set<LogWriteSubscriber>();

/**
 * 订阅 openclaw 日志文件的写入事件
 * 回调参数：(data: 写入的文本内容, filePath: 文件路径)
 */
export function subscribe(callback: LogWriteSubscriber): void {
  subscribers.add(callback);
}

/**
 * 取消订阅
 */
export function unsubscribe(callback: LogWriteSubscriber): void {
  subscribers.delete(callback);
}

// ── 保存原始方法引用 ──────────────────────────────────────
const originalAppendFileSync = fs.appendFileSync;

// ── 代理安装状态 ──────────────────────────────────────────
let installed = false;
function isAuthEvent(text: string): boolean {
  return /webchat\s+(connected|disconnected)|unauthorized|token_mismatch|handshake\s*fail/i.test(
    text,
  );
}
/**
 * 安装 fs.appendFileSync 代理：
 * - 当目标文件名匹配 openclaw-YYYY-MM-DD.log 时输出 console.log('正在写入日志')
 */
export function installProxy(): void {
  if (installed) return;
  installed = true;

  const proxiedAppendFileSync = (
    file: fsTypes.PathOrFileDescriptor,
    data:
      | string
      | NodeJS.ArrayBufferView
      | Iterable<string | NodeJS.ArrayBufferView>
      | AsyncIterable<string | NodeJS.ArrayBufferView>,
    options?: fsTypes.WriteFileOptions,
  ) => {
    if (isOpenClawLog(file)) {
      // 将 data 转为字符串并通知订阅者
      const dataStr =
        typeof data === "string"
          ? data
          : Buffer.isBuffer(data)
            ? data.toString("utf-8")
            : "";
      const filePath = typeof file === "string" ? file : String(file);
      if (isAuthEvent(dataStr)) {
        for (const cb of subscribers) {
          try {
            cb(dataStr, filePath);
          } catch {
            // 忽略订阅者回调错误
          }
        }
      }
    }
    return (originalAppendFileSync as (...args: unknown[]) => void).call(
      fs,
      file,
      data,
      options,
    );
  };
  fs.appendFileSync = proxiedAppendFileSync;
}

/**
 * 卸载代理，恢复 Node.js 原生 fs.appendFileSync
 */
export function uninstallProxy(): void {
  if (!installed) return;
  installed = false;
  fs.appendFileSync = originalAppendFileSync;
}
