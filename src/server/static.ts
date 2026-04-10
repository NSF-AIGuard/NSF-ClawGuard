import { createReadStream } from "fs";
import { stat } from "fs/promises";
import { join, normalize, dirname} from "path";
import { fileURLToPath } from "node:url";

import type { IncomingMessage, ServerResponse } from "http";

// 简单 MIME 映射（可根据需要扩展）
const mimeTypes: Record<string, string> = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain",
};
const here = dirname(fileURLToPath(import.meta.url));
// 静态文件根目录
const uiRoot = join(here, "web");


/**
 * 尝试发送文件，如果文件不存在则返回 false
 */
async function trySendFile(fullPath: string, res: ServerResponse): Promise<boolean> {
  try {
    const stats = await stat(fullPath);
    if (!stats.isFile()) return false;

    const ext = fullPath.slice(fullPath.lastIndexOf("."));
    const contentType = mimeTypes[ext] || "application/octet-stream";

    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "public, max-age=3600");

    const stream = createReadStream(fullPath);
    stream.pipe(res);
    stream.on("error", (err) => {
      console.error("静态文件读取错误:", err);
      if (!res.headersSent) {
        res.statusCode = 500;
        res.end("Internal Server Error");
      }
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * 检查路径是否包含文件扩展名
 * @param url URL 路径
 * @returns 是否包含文件扩展名
 */
function hasFileExtension(url: string): boolean {
  return /\.[a-zA-Z0-9]+$/.test(url);
}

/**
 * 处理前端路由，返回 index.html（类似 Webpack 的 historyApiFallback）
 * @param res ServerResponse
 */
async function handleFrontendRoute(res: ServerResponse): Promise<boolean> {
  const indexPath = join(uiRoot, "index.html");
  return await trySendFile(indexPath, res);
}

/**
 * 静态文件 handler
 * @param req IncomingMessage
 * @param res ServerResponse
 */
export default async function staticHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = req.url || "";

  // 处理以 /web 开头的请求
  if (url.startsWith("/web")) {
    // 提取相对路径，并确保以 / 开头
    let relativePath = url.slice("/web".length);
    if (!relativePath.startsWith("/")) {
      relativePath = "/" + relativePath;
    }

    // 防止路径遍历
    const fullPath = normalize(join(uiRoot, relativePath));
    if (!fullPath.startsWith(uiRoot)) {
      res.statusCode = 403;
      res.end("Forbidden");
      return;
    }

    // 如果路径包含文件扩展名，尝试作为静态文件处理
    if (hasFileExtension(relativePath)) {
      const sent = await trySendFile(fullPath, res);
      if (sent) return;

      // 静态文件不存在，返回 404
      res.statusCode = 404;
      res.end("Not Found");
      return;
    }

    // 如果路径不包含文件扩展名（前端路由，如 /web/dashboard, /web/threats）
    // 返回 index.html
    const handled = await handleFrontendRoute(res);
    if (handled) {
      return;
    }

    // index.html 不存在，返回 404
    res.statusCode = 404;
    res.end("Not Found");
    return;
  }

  // 其他情况，返回 404
  res.statusCode = 404;
  res.end("Not Found");
}