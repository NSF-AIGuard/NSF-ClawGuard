import * as path from "path";
import { fileURLToPath } from "url";


/**
 * 获取当前插件的安装目录
 * @returns string
 */
export function currentPluginRoot(): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  return path.join(__dirname, "..");
}
