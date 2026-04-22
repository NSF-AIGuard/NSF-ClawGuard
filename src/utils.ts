import * as path from "path";
import { fileURLToPath } from "url";
import { exec, spawn } from "child_process";


/**
 * 获取当前插件的安装目录
 * @returns string
 */
export function currentPluginRoot(): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  return path.join(__dirname, "..");
}


/**
 * 获取openclaw目录
 * @returns string
 */
export function openclawRoot(): string {
  const extensions = path.join(currentPluginRoot(), "..");
  return path.join(extensions, "..");
}

/**
 * 重启 gateway
 * @returns void
 */
export function restartGateway() {
  const restartCmd = "openclaw gateway restart";
  return new Promise((resolve, reject) => {
    exec(restartCmd, function (error, stdout, stderr) {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    })
  })
}


