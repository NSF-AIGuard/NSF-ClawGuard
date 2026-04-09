import type {
  OpenClawPluginHttpRouteHandler,
  OpenClawPluginHttpRouteParams,
  Logger,
} from "../types.js";
import type { IncomingMessage, ServerResponse } from "http";

// ═══════════════════════════════════════════════════════════════
// 模块增强 — 扩展 ServerResponse，全局可用 res.json() / res.error()
// 这样所有 handler 无需导入任何类型即可直接使用
// ═══════════════════════════════════════════════════════════════
declare module "http" {
  interface ServerResponse {
    /**
     * 发送 JSON 响应（HTTP 200）
     * 自动设置 Content-Type 和 Cache-Control 响应头
     * （由 jsonResponseMiddleware 中间件注入）
     */
    json: (data: unknown) => void;

    /**
     * 发送统一格式的错误响应（HTTP 500）
     * @param label - 错误描述前缀，如 "读取安全事件"
     * @param error - 错误对象
     * （由 jsonResponseMiddleware 中间件注入）
     */
    error: (label: string, error: unknown) => void;
  }
}

// ═══════════════════════════════════════════════════════════════
// 类型定义
// ═══════════════════════════════════════════════════════════════

/**
 * next 函数 — 调用后执行下一个中间件或最终 handler
 * 也可传入错误对象来中断链式调用: next(error)
 */
export type NextFunction = (err?: any) => void;

/**
 * Express 风格的中间件函数
 *
 * - 调用 next() 继续执行下一个中间件
 * - 调用 next(err) 中断链式调用并跳转到错误处理
 * - 不调用 next() 则中止链式执行（适合鉴权失败等场景）
 */
export type Middleware = (
  req: IncomingMessage,
  res: ServerResponse,
  next: NextFunction,
) => Promise<void> | void;

/**
 * 扩展的路由参数，增加可选的路由级中间件
 */
export interface RouteOptions {
  auth: OpenClawPluginHttpRouteParams["auth"];
  match?: OpenClawPluginHttpRouteParams["match"];
  replaceExisting?: OpenClawPluginHttpRouteParams["replaceExisting"];
  /** 路由级中间件，仅在匹配该路由时执行 */
  middleware?: Middleware[];
}

// ═══════════════════════════════════════════════════════════════
// 内部工具函数
// ═══════════════════════════════════════════════════════════════

const HTTP_REQUEST_METHODS = [
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "options",
  "head",
] as const;

type HandlerParams = Parameters<OpenClawPluginHttpRouteHandler>;

/**
 * 将中间件数组 + 最终 handler 组合成一个符合 OpenClawPluginHttpRouteHandler 的函数
 * 中间件按顺序执行，全部通过后执行 handler
 */
function composeMiddleware(
  middlewares: Middleware[],
  handler: OpenClawPluginHttpRouteHandler,
  logger: Logger,
  allowedMethod: string,
): (req: HandlerParams[0], res: HandlerParams[1]) => Promise<void> {
  return async (req: HandlerParams[0], res: HandlerParams[1]) => {
    try {
      const method = req.method?.toLowerCase();
      if (allowedMethod !== method) return;

      let index = 0;
      const stack = [...middlewares];

      const next: NextFunction = (err?: any) => {
        // 如果传入了错误，直接抛出中断链式调用
        if (err) {
          throw err;
        }
        // 执行下一个中间件
        if (index < stack.length) {
          const mw = stack[index++];
          // 捕获中间件同步返回的 Promise 以处理异常
          const result = mw(req, res, next);
          if (result instanceof Promise) {
            result.catch(next);
          }
        } else {
          // 所有中间件执行完毕，调用最终 handler
          const result = handler(req, res, logger);
          if (result instanceof Promise) {
            result.catch(next);
          }
        }
      };

      // 启动中间件链
      next();
    } catch (e) {
      // 静默处理，与原有行为一致
    }
  };
}

// ═══════════════════════════════════════════════════════════════
// Router 核心
// ═══════════════════════════════════════════════════════════════

/**
 * 创建一个 Express 风格的路由器实例
 *
 * @example
 * ```ts
 * const { app, routes } = createRouterApp(logger);
 *
 * // 注册全局中间件（所有路由都会经过）
 * app.use(corsMiddleware);
 * app.use(loggingMiddleware);
 *
 * // 注册路由（无中间件）
 * app.get("/api/events", handler, { auth: "plugin", match: "exact" });
 *
 * // 注册路由（带路由级中间件）
 * app.get("/api/admin", adminHandler, {
 *   auth: "plugin",
 *   match: "exact",
 *   middleware: [authCheckMiddleware, rateLimitMiddleware],
 * });
 * ```
 */
function createRouterApp(logger: Logger) {
  const routes: OpenClawPluginHttpRouteParams[] = [];

  /** 全局中间件列表 */
  const globalMiddlewares: Middleware[] = [];

  type TRouteHandler = (
    path: string,
    handler: OpenClawPluginHttpRouteHandler,
    opts: RouteOptions,
  ) => void;

  const app = {} as Record<
    (typeof HTTP_REQUEST_METHODS)[number],
    TRouteHandler
  > & {
    /** 注册全局中间件，所有路由匹配时都会执行 */
    use: (middleware: Middleware) => void;
  };

  // 注册 HTTP 方法路由
  HTTP_REQUEST_METHODS.forEach((method) => {
    app[method] = (
      path: string,
      handler: OpenClawPluginHttpRouteHandler,
      opts: RouteOptions,
    ) => {
      // 合并：全局中间件 + 路由级中间件
      const allMiddlewares = [...globalMiddlewares, ...(opts.middleware || [])];
      const composedHandler = composeMiddleware(
        allMiddlewares,
        handler,
        logger,
        method,
      );

      routes.push({
        path,
        handler: composedHandler,
        auth: opts.auth,
        match: opts.match,
        replaceExisting: opts.replaceExisting,
      });
    };
  });

  // 注册全局中间件方法
  app.use = (middleware: Middleware) => {
    globalMiddlewares.push(middleware);
  };

  return {
    routes,
    app,
  };
}

// ═══════════════════════════════════════════════════════════════
// JSON 响应增强 — 挂载到 res 上的便捷方法
// ═══════════════════════════════════════════════════════════════

/**
 * 增强版的 ServerResponse，自带 JSON 响应快捷方法
 *
 * 在全局中间件 jsonResponseMiddleware 中自动注入到 res 上，
 * 处理函数中可直接使用，无需额外导入任何工具函数。
 *
 * @example
 * ```ts
 * // 在 handler 中直接使用
 * async function myHandler(req, res: JsonResponse, logger) {
 *   const data = await fetchData();
 *   res.json(data);
 * }
 *
 * // 错误处理
 * try { ... } catch (error) {
 *   res.error("读取数据", error);
 * }
 * ```
 */
export interface JsonResponse extends ServerResponse {
  /**
   * 发送 JSON 响应（HTTP 200）
   * 自动设置 Content-Type 和 Cache-Control 响应头
   */
  json: (data: unknown) => void;

  /**
   * 发送统一格式的错误响应（HTTP 500）
   * @param label - 错误描述前缀，如 "读取安全事件"
   * @param error - 错误对象
   */
  error: (label: string, error: unknown) => void;
}

/**
 * JSON 响应增强中间件
 *
 * 在 res 上挂载 json() 和 error() 便捷方法。
 * 作为全局中间件注册一次即可，所有后续处理函数都可以使用。
 *
 * @example
 * ```ts
 * // 在 index.ts 中注册
 * app.use(jsonResponseMiddleware);
 *
 * // 之后在任意 handler 中直接使用
 * async (req, res: JsonResponse, logger) => {
 *   const data = await fetchData();
 *   res.json(data);
 * }
 * ```
 */
export const jsonResponseMiddleware: Middleware = (req, res, next) => {
  // 挂载 res.json() — 发送成功的 JSON 响应
  // 注意：响应头在此方法内部设置，不会影响其他未调用 json() 的路由（如静态资源）
  (res as JsonResponse).json = (data: unknown) => {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    res.statusCode = 200;
    res.end(JSON.stringify({ code: 0, data }));
  };

  // 挂载 res.error() — 发送统一格式的错误响应
  (res as JsonResponse).error = (label: string, error: unknown) => {
    console.error(`${label}失败:`, error);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    res.statusCode = 500;
    res.end(
      JSON.stringify({
        code: 500,
        error: `${label}失败`,
        message: error instanceof Error ? error.message : "未知错误",
      }),
    );
  };

  next();
};

export default createRouterApp;
