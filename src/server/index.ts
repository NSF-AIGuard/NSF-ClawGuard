import staticHandler from "./static.js";
import { inspectHandler, securityEventStatsHandler, eventStatsHandler, riskDistributionHandler } from "./inspect.js";
import {
  tokenUsageHandler,
  overview,
  toolCallHandler,
  gatewayAuthLogHandler,
} from "./audit.js";
import { getConfigHandler, saveConfigHandler } from "./config.js";
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
  app.get("/lm-securty/eventStats", eventStatsHandler, {
    auth: "plugin",
    match: "exact",
  });
  app.get("/lm-securty/riskDistribution", riskDistributionHandler, {
    auth: "plugin",
    match: "exact",
  });
  // 不支持restful 格式的api,openclaw 框架本身限制
  app.get("/lm-securty/getConfig", getConfigHandler, {
    auth: "plugin",
    match: "exact",
  });
  app.post("/lm-securty/saveConfig", saveConfigHandler, {
    auth: "plugin",
    match: "exact",
  });
  routes.forEach((route) => {
    api.registerHttpRoute(route);
  });
}
// export default routes;
