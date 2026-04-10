import axios from "axios";
import https from "https";
import crypto from "node:crypto";
import fs from "node:fs";
import FormData from 'form-data';
import { currentPluginRoot } from './utils.js'
import type { Axios, InternalAxiosRequestConfig, AxiosResponse } from "axios";
import type {
  IResponseBody,
  PluginLogger,
} from "./types.js";
import path from "node:path";

interface RequestOptions {
  baseUrl: string;
  secretKey: string;
  accessKey: string;
  appId?: string;
  verifySsl?: boolean;
  mode?: string;
}

class RequestManager {
  private instance: Axios | null = null;
  private _isRemoteEnabled = false;
  private secretKey = '';
  private accessKey = '';
  private appId = '';

  /** 是否启用了远端功能 */
  get isRemoteEnabled(): boolean {
    return this._isRemoteEnabled;
  }

  /**
   * 构造请求头认证参数
   */
  private buildHeaders(): Record<string, string | number> {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const message = "ai_guard" + timestamp;
    const signature = crypto
      .createHmac("sha256", this.secretKey)
      .update(message)
      .digest("hex");

    return {
      "X-Access-Key": this.accessKey,
      "X-Timestamp": timestamp,
      "X-Signature": signature,
    };
  }

  /**
   * 初始化请求实例（读取 config.json，创建 axios 实例，注册拦截器）
   * @param hackLogger 日志记录器
   * @returns Axios 实例或 null（远端未启用 / 配置读取失败时）
   */
  initialize(hackLogger: PluginLogger): Axios | null {
    if (this.instance !== null) {
      return this.instance;
    }

    const root = currentPluginRoot();
    const configFile = path.join(root, "config.json");
    try {
      const config = JSON.parse(
        fs.readFileSync(configFile, "utf8"),
      ) as RequestOptions;
      const { baseUrl, secretKey, accessKey, appId, verifySsl, mode } = config;

      // Only enable remote features when mode is "online"
      this._isRemoteEnabled = mode === "online";
      if (!this._isRemoteEnabled) {
        hackLogger.info(`[lm-security] mode="${mode}", 远端功能已禁用，仅使用本地安全检测`);
        return null;
      }

      this.secretKey = secretKey;
      this.accessKey = accessKey;
      this.appId = appId || '';

      this.instance = axios.create({
        baseURL: baseUrl,
        timeout: 10 * 1000,
        httpsAgent: !verifySsl
          ? new https.Agent({ rejectUnauthorized: false })
          : undefined,
        headers: {
          "Content-Type": "application/json",
        },
      });

      // 请求拦截器
      this.instance.interceptors.request.use((config: InternalAxiosRequestConfig) => {
        const headers = this.buildHeaders();
        Object.keys(headers).forEach((key) => {
          config.headers.set(key, headers[key]);
        });
        if (config.data instanceof FormData) {
          return config;
        }
        if (this.appId) {
          if (config.method === "post") {
            config.data.appId = this.appId;
          }
          if (config.method === "get") {
            config.params.appId = this.appId;
          }
        }
        return config;
      });

      // 响应拦截器
      this.instance.interceptors.response.use(
        (response: AxiosResponse<IResponseBody>) => {
          const body = response.data;
          if (body.errCode !== 200 && response.config.url !== "/api/v1/terminal/heartbeat") {
            const error = new Error(
              body.errMsg || "Request failed with not 200 errCode",
            );
            return Promise.reject(error);
          }
          return response;
        },
        (error) => Promise.reject(error),
      );

      return this.instance;
    } catch (error) {
      hackLogger.error(`Error reading config.json: ${error}`);
      return null;
    }
  }

  /**
   * 发送 GET 请求
   */
  async get<T = unknown>(
    url: string,
    config?: Omit<InternalAxiosRequestConfig, "method" | "url">,
  ): Promise<AxiosResponse<T>> {
    if (!this.instance) {
      throw new Error(
        "Axios instance not initialized. Call initialize first.",
      );
    }
    return this.instance.get<T>(url, config);
  }

  /**
   * 发送 POST 请求
   */
  async post<T = unknown, D = any>(
    url: string,
    data?: D,
    config?: Omit<InternalAxiosRequestConfig, "method" | "url" | "data">,
  ): Promise<AxiosResponse<T>> {
    if (!this.instance) {
      throw new Error(
        "Axios instance not initialized. Call initialize first.",
      );
    }
    return this.instance.post<T, AxiosResponse<T>, D>(url, data, config);
  }
}

const requestManager = new RequestManager();

export default requestManager;