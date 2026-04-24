import { http } from "@/utils/request";

export interface CloudConfig {
  baseUrl: string;
  accessKey: string;
  secretKey: string;
  appId: string;
}

/**
 * 获取云端配置
 */
export const getConfig = async (): Promise<CloudConfig | null> => {
  return http.get<CloudConfig | null>("/lm-securty/getConfig");
};

/**
 * 保存云端配置
 */
export const saveConfig = async (data: CloudConfig): Promise<void> => {
  return http.post<void>("/lm-securty/saveConfig", data);
};