import staticHandler from "./static.js";
import { inspectHandler, securityEventStatsHandler } from "./inspect.js";
import {
  tokenUsageHandler,
  overview,
  toolCallHandler,
  gatewayAuthLogHandler,
} from "./audit.js";
import createRouterApp, { jsonResponseMiddleware } from "./router.js";
import type { OpenClawPluginApi } from "../types.js";

export default function registerHttpRoute(api: OpenClawPluginApi) {
  const logger = api.logger;
  const { app, routes } = createRouterApp(logger);

  // ── 注册全局中间件 ────────────────────────────────────
  // jsonResponseMiddleware: 给 res 挂载 json() / error() 便捷方法
  app.use(jsonResponseMiddleware);

  // ── 注册路由 ──────────────────────────────────────────
  app.get("/web", staticHandler, {
    auth: "plugin",
    match: "prefix",
  });
  app.get("/lm-securty/events", inspectHandler, {
    auth: "plugin",
    match: "exact",
  });

  app.get("/lm-securty/tokenUsage", tokenUsageHandler, {
    auth: "plugin",
    match: "exact",
  });
  app.get("/lm-securty/overview", overview, {
    auth: "plugin",
    match: "exact",
  });
  app.get("/lm-securty/toolCall", toolCallHandler, {
    auth: "plugin",
    match: "exact",
  });
  app.get("/lm-securty/gatewayAuthLogs", gatewayAuthLogHandler, {
    auth: "plugin",
    match: "exact",
  });
  app.get("/lm-securty/securityEventStats", securityEventStatsHandler, {
    auth: "plugin",
    match: "exact",
  });
  routes.forEach((route) => {
    api.registerHttpRoute(route);
  });
}
// export default routes;
