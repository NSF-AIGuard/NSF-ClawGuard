import { LOG_PREFIX } from "./constants.js";
import type { PluginLogger } from "./types.js";

let hackLogger: PluginLogger | undefined = undefined;

type LoggerKey = keyof PluginLogger;
/**
 * 初始化日志记录器，对原始 logger 进行封装，自动添加前缀。
 *
 * @param api - 包含 logger 属性的对象（通常来自 VS Code 扩展上下文）
 * @param prefix - 可选的日志前缀，会附加到每条日志消息开头
 * @returns 封装后的 PluginLogger 实例
 */
export default function initializeLogger(
  api: { logger: PluginLogger },
  prefix: string = LOG_PREFIX,
): PluginLogger {
  // 如果已初始化，直接返回
  if (hackLogger) {
    return hackLogger;
  }

  const originalLogger = api.logger;
  hackLogger = {
    ...originalLogger,
  };
  // 构造带前缀的消息
  const formatMessage = (message: string): string => {
    return  `${prefix} ${message}`;
  };

  (Object.keys(originalLogger) as LoggerKey[]).forEach((method) => {
    hackLogger![method] = (message: string) =>
      originalLogger[method]!(formatMessage(message));
  });

  return hackLogger;
}
export function getLogger() {
  return hackLogger;
}
   