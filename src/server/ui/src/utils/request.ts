import axios, {
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
  AxiosError,
} from "axios";
import { message } from "antd";

// 限制最多同时显示3条 message 提示
message.config({ maxCount: 3 });

// 创建 axios 实例
const service: AxiosInstance = axios.create({
  timeout: 5 * 1000,
  headers: {
    "Content-Type": "application/json",
  },
});

// 请求拦截器
service.interceptors.request.use(
  (config) => {
    // 可以在这里添加 token 等认证信息
    // const token = localStorage.getItem('token')
    // if (token) {
    //   config.headers.Authorization = `Bearer ${token}`
    // }
    return config;
  },
  (error: AxiosError) => {
    console.error("Request error:", error);
    return Promise.reject(error);
  },
);

// 响应拦截器
service.interceptors.response.use(
  (response: AxiosResponse) => {
    const res = response.data;

    // 这里可以根据后端的响应结构进行调整
    if (res.code !== undefined && res.code !== 0) {
      const errorMsg = res.message || "请求错误";
      message.error(errorMsg);
      return Promise.reject(new Error(errorMsg));
    }

    return res.data;
  },
  (error: AxiosError) => {
    let errorMsg = "请求失败";

    if (error.response) {
      switch (error.response.status) {
        case 401:
          errorMsg = "未授权，请重新登录";
          break;
        case 403:
          errorMsg = "拒绝访问";
          break;
        case 404:
          errorMsg = "请求资源不存在";
          break;
        case 500:
          errorMsg = "服务器内部错误";
          break;
        default:
          errorMsg = `请求错误(${error.response.status})`;
      }
    } else if (error.request) {
      errorMsg = "网络异常，请检查网络连接";
    } else {
      errorMsg = "请求配置错误";
    }

    message.error(errorMsg);
    return Promise.reject(error);
  },
);

// 封装请求方法
export const http = {
  get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return service.get(url, config);
  },

  post<T = any>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig,
  ): Promise<T> {
    return service.post(url, data, config);
  },

  put<T = any>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig,
  ): Promise<T> {
    return service.put(url, data, config);
  },

  delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return service.delete(url, config);
  },

  patch<T = any>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig,
  ): Promise<T> {
    return service.patch(url, data, config);
  },
};

export default service;
