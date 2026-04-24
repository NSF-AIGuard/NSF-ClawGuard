import * as fs from "fs";
import * as path from "path";
import type { IncomingMessage, ServerResponse } from "http";
import { currentPluginRoot,restartGateway } from "../utils.js";

const CONFIG_FILE = path.join(currentPluginRoot(), "config.json");

interface CloudConfig {
  baseUrl: string;
  accessKey: string;
  secretKey: string;
  appId: string;
  verifySsl: boolean;
  mode: string;
}

/**
 * 从请求体中解析 JSON 数据
 */
function parseRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf-8"));
    });
    req.on("error", reject);
  });
}

/**
 * GET /lm-securty/config
 * 读取 config.json，返回 baseUrl, accessKey, secretKey, appId
 */
export async function getConfigHandler(
  _req: IncomingMessage,
  res: ServerResponse,
) {
  try {
    if (!fs.existsSync(CONFIG_FILE)) {
      res.json(null);
      return;
    }

    const raw = fs.readFileSync(CONFIG_FILE, "utf-8");
    const config: CloudConfig = JSON.parse(raw);

    res.json({
      baseUrl: config.baseUrl || "",
      accessKey: config.accessKey || "",
      secretKey: config.secretKey || "",
      appId: config.appId || "",
    });
  } catch (error) {
    res.error("读取配置", error);
  }
}

/**
 * POST /lm-securty/config
 * 接收 baseUrl, accessKey, secretKey, appId，附加 verifySsl: false, mode: "online"，写入 config.json
 */
export async function saveConfigHandler(
  req: IncomingMessage,
  res: ServerResponse,
) {
  try {
    const body = await parseRequestBody(req);
    const data = JSON.parse(body);

    const config: CloudConfig = {
      baseUrl: data.baseUrl,
      accessKey: data.accessKey,
      secretKey: data.secretKey,
      appId: data.appId,
      verifySsl: false,
      mode: "online",
    };

    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), "utf-8");

    res.json({ success: true });
    setTimeout(restartGateway,1.5*1000)
  } catch (error) {
    res.error("保存配置", error);
  }
}