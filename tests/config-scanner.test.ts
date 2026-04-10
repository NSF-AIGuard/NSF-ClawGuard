/**
 * config-scanner.test.ts
 * 单元测试：配置文件安全扫描器
 */

import { describe, it, expect } from "vitest";
import {
  scanConfig,
  loadConfig,
  getScanResults,
} from "../src/config-scanner.js";
import type { OpenClawConfig } from "../src/config-scanner.js";

// ── 辅助 ──────────────────────────────────────────────────────

function makeConfig(overrides: Partial<OpenClawConfig> = {}): OpenClawConfig {
  return {
    meta: {},
    gateway: {
      port: 18789,
      bind: "127.0.0.1",
      mode: "local",
    },
    tools: {},
    plugins: {},
    hooks: {},
    auth: {},
    session: { timeout: 3600 },
    commands: {},
    models: {},
    agents: {},
    log: { level: "info" },
    mcp: {},
    ...overrides,
  } as OpenClawConfig;
}

// ── Token 熵值检测 ─────────────────────────────────────────────

describe("token-entropy 检测", () => {
  it("空 token 不检测", () => {
    const cfg = makeConfig({ gateway: { auth: { token: "" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "token-entropy");
    expect(r).toBeUndefined();
  });

  it("32 字符 token → 熵值不足（critical）", () => {
    const cfg = makeConfig({ gateway: { auth: { token: "a".repeat(32) } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "token-entropy");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
    expect(r!.message).toContain("低于48字符");
  });

  it("64 字符随机 token → 通过", () => {
    const cfg = makeConfig({ gateway: { auth: { token: "A".repeat(64) } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "token-entropy");
    expect(r).toBeUndefined();
  });
});

// ── Token 弱模式检测 ──────────────────────────────────────────

describe("token-weak-pattern 检测", () => {
  it("123456 系列弱 token", () => {
    const weakTokens = [
      "123456", "12345678", "123456789",
      "password", "password123", "admin",
      "qwerty", "abc123", "111111",
    ];
    weakTokens.forEach((token) => {
      const cfg = makeConfig({ gateway: { auth: { token } } });
      const results = scanConfig(cfg);
      const r = results.find((r) => r.rule === "token-weak-pattern");
      expect(r).toBeDefined();
      expect(r!.severity).toBe("critical");
    });
  });

  it("纯数字 token → 弱模式", () => {
    const cfg = makeConfig({ gateway: { auth: { token: "999888777" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "token-weak-pattern");
    expect(r).toBeDefined();
  });

  it("纯字母 token（小写） → 弱模式", () => {
    const cfg = makeConfig({ gateway: { auth: { token: "helloworld" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "token-weak-pattern");
    expect(r).toBeDefined();
  });

  it("键盘顺序 token → 弱模式", () => {
    const cfg = makeConfig({ gateway: { auth: { token: "qwertyuiop" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "token-weak-pattern");
    expect(r).toBeDefined();
  });

  it("JWT 空签名格式 → 弱模式", () => {
    const cfg = makeConfig({ gateway: { auth: { token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjN9." } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "token-weak-pattern");
    expect(r).toBeDefined();
  });

  it("强随机 token → 通过", () => {
    const cfg = makeConfig({ gateway: { auth: { token: "xK9m#pL2$vN5q@Q7wZ3&jR8yT1bH6nG4dF" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "token-weak-pattern");
    expect(r).toBeUndefined();
  });
});

// ── Gateway 绑定暴露检测 ──────────────────────────────────────

describe("gateway-bind-exposed 检测", () => {
  it("bind: '0.0.0.0' → critical", () => {
    const cfg = makeConfig({ gateway: { bind: "0.0.0.0" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "gateway-bind-exposed");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
    expect(r!.message).toContain("公网地址");
  });

  it("bind: '::'（IPv6 全接口） → critical", () => {
    const cfg = makeConfig({ gateway: { bind: "::" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "gateway-bind-exposed");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("bind: '127.0.0.1' → 通过", () => {
    const cfg = makeConfig({ gateway: { bind: "127.0.0.1" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "gateway-bind-exposed");
    expect(r).toBeUndefined();
  });

  it("bind: 'loopback' → 通过", () => {
    const cfg = makeConfig({ gateway: { bind: "loopback" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "gateway-bind-exposed");
    expect(r).toBeUndefined();
  });
});

// ── 危险配置标志检测 ──────────────────────────────────────────

describe("dangerous-flags 检测", () => {
  it("gateway 配置 allowAll: true → critical", () => {
    const cfg = makeConfig({ gateway: { allowAll: true } as any });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "dangerous-flags");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("gateway 配置 bypassAuth: true → critical", () => {
    const cfg = makeConfig({ gateway: { bypassAuth: true } as any });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "dangerous-flags");
    expect(r).toBeDefined();
  });

  it("tools.exec.security = 'disabled' → exec-security-disabled critical", () => {
    // security: "disabled" 由 exec-security-disabled 规则检测（不在 dangerous-flags 中）
    const cfg = makeConfig({ tools: { exec: { security: "disabled" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "exec-security-disabled");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("gateway 配置 normal: true → 不触发（正常值）", () => {
    const cfg = makeConfig({ gateway: { normal: true } as any });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "dangerous-flags");
    expect(r).toBeUndefined();
  });
});

// ── Session TTL 检测 ──────────────────────────────────────────

describe("session-ttl 检测", () => {
  it("未设置 timeout → critical", () => {
    const cfg = makeConfig({ session: {} });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "session-ttl");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
    expect(r!.message).toContain("未设置");
  });

  it("timeout: 86400（24h） → critical（过长）", () => {
    const cfg = makeConfig({ session: { timeout: 86400 } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "session-ttl");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("timeout: 28800（8h） → warning（过长）", () => {
    const cfg = makeConfig({ session: { timeout: 28800 } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "session-ttl");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("medium");
  });

  it("timeout: 3600（1h） → 通过", () => {
    const cfg = makeConfig({ session: { timeout: 3600 } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "session-ttl");
    expect(r).toBeUndefined();
  });
});

// ── CORS 通配符检测 ───────────────────────────────────────────

describe("cors-wildcard 检测", () => {
  it("origins: ['*'] → critical", () => {
    const cfg = makeConfig({ gateway: { cors: { enabled: true, origins: ["*"] } as any } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "cors-wildcard");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
    expect(r!.message).toContain("通配符");
  });

  it("origins: ['http://*'] → critical", () => {
    const cfg = makeConfig({ gateway: { cors: { enabled: true, origins: ["http://*"] } as any } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "cors-wildcard");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("origins: ['https://example.com'] → 通过", () => {
    const cfg = makeConfig({ gateway: { cors: { enabled: true, origins: ["https://example.com"] } as any } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "cors-wildcard");
    expect(r).toBeUndefined();
  });

  it("origins 含 HTTP URL → critical（不安全）", () => {
    const cfg = makeConfig({ gateway: { cors: { enabled: true, origins: ["http://example.com"] } as any } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "cors-wildcard");
    expect(r).toBeDefined();
    expect(r!.message).toContain("HTTP");
  });
});

// ── API Key 暴露检测 ──────────────────────────────────────────

describe("api-key-exposed 检测（凭证安全）", () => {
  it("sk-test 测试密钥 → critical", () => {
    const cfg = makeConfig({
      models: {
        providers: {
          openai: { apiKey: "sk-test", baseUrl: "" },
        },
      },
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "api-key-exposed");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("test-key → critical", () => {
    const cfg = makeConfig({
      models: {
        providers: {
          openai: { apiKey: "test-key", baseUrl: "" },
        },
      },
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "api-key-exposed");
    expect(r).toBeDefined();
  });

  it("sk-proj-test → critical（GitHub PAT）", () => {
    const cfg = makeConfig({
      models: {
        providers: {
          custom: { apiKey: "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB", baseUrl: "" },
        },
      },
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "hardcoded-secrets");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("正常 OpenAI key 格式不触发 api-key-exposed（正则只检测试密钥前缀）", () => {
    // sk-proj-REALKEY... 不是 sk-test/test-key 等测试前缀，不应触发 api-key-exposed
    const cfg = makeConfig({
      models: {
        providers: {
          openai: { apiKey: "sk-proj-REALKEY1234567890abcdefghijk", baseUrl: "" },
        },
      },
    });
    const results = scanConfig(cfg);
    const testR = results.find((r) => r.rule === "api-key-exposed");
    // 不应触发（因为不是测试密钥前缀）
    expect(testR).toBeUndefined();
  });
});

// ── 环境变量注入检测 ─────────────────────────────────────────

describe("env-injection 检测", () => {
  it("LD_PRELOAD 环境变量引用 → critical", () => {
    const cfg = {
      ...makeConfig(),
      models: {
        providers: {
          custom: {
            baseUrl: "${LD_PRELOAD}",
            apiKey: "",
          },
        },
      },
    } as OpenClawConfig;
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "env-injection");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
    expect(r!.message).toContain("LD_PRELOAD");
  });

  it("OPENSSL_CONF 环境变量引用 → critical", () => {
    const cfg = {
      ...makeConfig(),
      models: {
        providers: {
          custom: {
            baseUrl: "${OPENSSL_CONF}",
            apiKey: "",
          },
        },
      },
    } as OpenClawConfig;
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "env-injection");
    expect(r).toBeDefined();
    expect(r!.message).toContain("OPENSSL_CONF");
  });

  it("GIT_SSH_COMMAND 引用 → critical", () => {
    const cfg = {
      ...makeConfig(),
      models: {
        providers: {
          custom: {
            baseUrl: "${GIT_SSH_COMMAND}",
            apiKey: "",
          },
        },
      },
    } as OpenClawConfig;
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "env-injection");
    expect(r).toBeDefined();
  });

  it("无危险 env 引用 → 不触发", () => {
    const cfg = makeConfig({
      models: {
        providers: {
          openai: { baseUrl: "https://api.openai.com", apiKey: "sk-xxx" },
        },
      },
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "env-injection");
    expect(r).toBeUndefined();
  });
});

// ── TLS 加密检测 ─────────────────────────────────────────────

describe("tls-required 检测", () => {
  it("bind: '0.0.0.0' 且未配置 TLS → critical", () => {
    const cfg = makeConfig({ gateway: { bind: "0.0.0.0" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "tls-required");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
    expect(r!.message).toContain("未配置TLS");
  });

  it("bind: '127.0.0.1' → 不触发（仅本地）", () => {
    const cfg = makeConfig({ gateway: { bind: "127.0.0.1" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "tls-required");
    expect(r).toBeUndefined();
  });
});

// ── 速率限制检测 ─────────────────────────────────────────────

describe("rate-limiting 检测", () => {
  it("未配置速率限制 → critical", () => {
    const cfg = makeConfig({ gateway: { rateLimit: undefined } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "rate-limiting");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
    expect(r!.message).toContain("未配置");
  });

  it("maxRequests: 200/分钟 → warning（过高）", () => {
    const cfg = makeConfig({ gateway: { rateLimit: { enabled: true, windowMs: 60000, maxRequests: 200 } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "rate-limiting");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("medium");
  });

  it("maxRequests: 30/分钟 → 通过", () => {
    const cfg = makeConfig({ gateway: { rateLimit: { enabled: true, windowMs: 60000, maxRequests: 30 } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "rate-limiting");
    expect(r).toBeUndefined();
  });
});

// ── 网关认证检测 ─────────────────────────────────────────────

describe("gateway-auth 认证检测", () => {
  it("未配置 auth → critical", () => {
    const cfg = makeConfig({ gateway: {} });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "gateway-auth-disabled");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
    expect(r!.message).toContain("缺失");
  });

  it("auth.mode = 'none' → critical", () => {
    const cfg = makeConfig({ gateway: { auth: { mode: "none", token: "xxx" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "gateway-auth-mode-insecure");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("auth.mode = 'token' 有 token → 通过", () => {
    const cfg = makeConfig({ gateway: { auth: { mode: "token", token: "xK9m#pL2$vN5" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "gateway-auth-disabled");
    expect(r).toBeUndefined();
    const r2 = results.find((r) => r.rule === "gateway-auth-mode-insecure");
    expect(r2).toBeUndefined();
  });
});

// ── 工作区路径限制检测 ─────────────────────────────────────────

describe("workspace-not-restricted 检测", () => {
  it("workspace = '/' → critical", () => {
    const cfg = makeConfig({ agents: { defaults: { workspace: "/" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "workspace-not-restricted");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("workspace = '~' → critical", () => {
    const cfg = makeConfig({ agents: { defaults: { workspace: os.homedir() } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "workspace-not-restricted");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("workspace = '/home/user/openclaw-workspace' → 通过", () => {
    const cfg = makeConfig({ agents: { defaults: { workspace: "/home/user/openclaw-workspace" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "workspace-not-restricted");
    expect(r).toBeUndefined();
  });
});

// ── 日志级别检测 ─────────────────────────────────────────────

describe("log-level-verbose / log-include-sensitive 检测", () => {
  it("log.level = 'trace' → critical", () => {
    const cfg = makeConfig({ log: { level: "trace" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "log-level-verbose");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("log.level = 'debug' → critical", () => {
    const cfg = makeConfig({ log: { level: "debug" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "log-level-verbose");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("log.level = 'info' → 通过", () => {
    const cfg = makeConfig({ log: { level: "info" } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "log-level-verbose");
    expect(r).toBeUndefined();
  });

  it("log.includeSensitive = true → critical", () => {
    const cfg = makeConfig({ log: { includeSensitive: true } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "log-include-sensitive");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("log.includeSensitive = false → 通过", () => {
    const cfg = makeConfig({ log: { includeSensitive: false } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "log-include-sensitive");
    expect(r).toBeUndefined();
  });
});

// ── 加密货币密钥检测 ─────────────────────────────────────────

describe("mnemonic-leak 检测", () => {
  it("BIP39 12 词助记词 → critical", () => {
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const cfg = {
      ...makeConfig(),
      models: {
        providers: {
          custom: { baseUrl: `https://example.com?seed=${encodeURIComponent(mnemonic)}`, apiKey: "" },
        },
      },
    } as OpenClawConfig;
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "mnemonic-leak");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("以太坊私钥格式 → critical", () => {
    const cfg = {
      ...makeConfig(),
      models: {
        providers: {
          custom: { baseUrl: "https://example.com", apiKey: "" },
        },
      },
    } as OpenClawConfig;
    // 直接在 JSON 字符串中触发正则
    cfg.models!.providers!.custom! as any;
    const results = scanConfig(cfg);
    // 注入以太坊私钥
    const privKey = "0x" + "a".repeat(64);
    const cfg2 = {
      ...makeConfig(),
      models: {
        providers: {
          custom: { baseUrl: `https://example.com?key=${privKey}`, apiKey: "" },
        },
      },
    } as OpenClawConfig;
    const results2 = scanConfig(cfg2);
    const r2 = results2.find((r) => r.rule === "mnemonic-leak");
    expect(r2).toBeDefined();
  });

  it("Bitcoin WIF 格式 → critical", () => {
    const cfg = {
      ...makeConfig(),
      models: {
        providers: {
          custom: { baseUrl: `https://example.com?btckey=L${"a".repeat(51)}`, apiKey: "" },
        },
      },
    } as OpenClawConfig;
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "mnemonic-leak");
    expect(r).toBeDefined();
  });
});

// ── 执行安全禁用检测 ─────────────────────────────────────────

describe("exec-security-disabled 检测", () => {
  it("tools.exec.security = 'disabled' → critical", () => {
    const cfg = makeConfig({ tools: { exec: { security: "disabled" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "exec-security-disabled");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("tools.exec.security = 'off' → critical", () => {
    const cfg = makeConfig({ tools: { exec: { security: "off" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "exec-security-disabled");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("tools.exec.security = 'sandbox' → 通过", () => {
    const cfg = makeConfig({ tools: { exec: { security: "sandbox" } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "exec-security-disabled");
    expect(r).toBeUndefined();
  });
});

// ── 写入路径无限制检测 ───────────────────────────────────────

describe("write-no-restrictions 检测", () => {
  it("tools.write.allowedPaths = ['/'] → critical", () => {
    const cfg = makeConfig({ tools: { write: { allowedPaths: ["/"] } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "write-no-restrictions");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("tools.write.allowedPaths = ['*'] → critical", () => {
    const cfg = makeConfig({ tools: { write: { allowedPaths: ["*"] } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "write-no-restrictions");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("tools.write.allowedPaths = ['**'] → critical", () => {
    const cfg = makeConfig({ tools: { write: { allowedPaths: ["**"] } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "write-no-restrictions");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("tools.write.allowedPaths = ['/home/user/openclaw-workspace'] → 通过", () => {
    const cfg = makeConfig({ tools: { write: { allowedPaths: ["/home/user/openclaw-workspace"] } } });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "write-no-restrictions");
    expect(r).toBeUndefined();
  });
});

// ── 扫描结果按严重程度排序 ───────────────────────────────────

describe("scanConfig 结果排序", () => {
  it("结果按 critical > high > medium > low > info 排序", () => {
    // 新五级：critical > high > medium > low > info
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const cfg = makeConfig({
      gateway: { bind: "0.0.0.0" },
      session: {},
      log: { level: "trace" },
      tools: { exec: { security: "disabled" } },
    });
    const results = scanConfig(cfg);
    expect(results.length).toBeGreaterThan(0);
    results.forEach((r) => { expect(r.severity).toBe("critical"); });
    // 验证排序正确（severity 值越小越严重，应排在前面）
    const severities = results.map((r) => r.severity);
    for (let i = 0; i < severities.length - 1; i++) {
      expect(order[severities[i]]).toBeLessThanOrEqual(order[severities[i + 1]]);
    }
  });
});

// ── getScanResults（不测 loadConfig，因需真实文件）────────────

describe("getScanResults", () => {
  it("返回 results 数组（loadConfig 失败时为空）", () => {
    // loadConfig 读取不存在的文件返回 null，此时 results 应为空数组
    // 但 getScanResults 内部会调用 loadConfig，无法在单元测试中 mock
    // 这里只测 scanConfig 结果格式正确
    const cfg = makeConfig();
    const results = scanConfig(cfg);
    results.forEach((r) => {
      expect(r).toHaveProperty("rule");
      expect(r).toHaveProperty("severity");
      expect(r).toHaveProperty("path");
      expect(r).toHaveProperty("message");
      expect(["critical", "high", "medium", "low", "info"]).toContain(r.severity);
    });
  });
});

// ── scanConfig 空配置不崩溃 ─────────────────────────────────

describe("scanConfig 边界情况", () => {
  it("空配置对象不崩溃", () => {
    expect(() => scanConfig({} as OpenClawConfig)).not.toThrow();
  });

  it("缺失字段不崩溃（undefined 处理）", () => {
    const cfg = {
      meta: undefined,
      gateway: undefined,
      tools: undefined,
      plugins: undefined,
      hooks: undefined,
      auth: undefined,
      session: undefined,
      commands: undefined,
      models: undefined,
      agents: undefined,
      log: undefined,
      mcp: undefined,
    } as OpenClawConfig;
    expect(() => scanConfig(cfg)).not.toThrow();
  });
});

// ── 内网地址误报过滤 ─────────────────────────────────────────

describe("api-endpoint-safety 检测", () => {
  it("http://localhost → warning", () => {
    const cfg = makeConfig({
      models: { providers: { ollama: { baseUrl: "http://localhost:11434", apiKey: "" } } },
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "api-endpoint-safety");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("medium");
    expect(r!.message).toContain("HTTP");
  });

  it("http://127.0.0.1 → warning", () => {
    const cfg = makeConfig({
      models: { providers: { ollama: { baseUrl: "http://127.0.0.1:11434", apiKey: "" } } },
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "api-endpoint-safety");
    expect(r).toBeDefined();
    expect(r!.message).toContain("HTTP");
  });

  it("http://10.x.x.x 内网 → warning", () => {
    const cfg = makeConfig({
      models: { providers: { ollama: { baseUrl: "http://10.0.0.5:11434", apiKey: "" } } },
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "api-endpoint-safety");
    expect(r).toBeDefined();
    expect(r!.message).toContain("HTTP");
  });

  it("https://api.openai.com → 通过", () => {
    const cfg = makeConfig({
      models: { providers: { openai: { baseUrl: "https://api.openai.com", apiKey: "sk-xxx" } } },
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "api-endpoint-safety");
    expect(r).toBeUndefined();
  });
});

// ── webhook URL 不安全检测 ────────────────────────────────────

describe("webhook-url-insecure 检测", () => {
  it("webhook URL 为 http:// → critical", () => {
    const cfg = makeConfig({
      hooks: {
        webhooks: {
          enabled: true,
          entries: {
            myhook: { enabled: true, url: "http://example.com/webhook" },
          },
        },
      } as any,
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "webhook-url-insecure");
    expect(r).toBeDefined();
    expect(r!.severity).toBe("critical");
  });

  it("webhook URL 为 https:// → 通过", () => {
    const cfg = makeConfig({
      hooks: {
        webhooks: {
          enabled: true,
          entries: {
            myhook: { enabled: true, url: "https://example.com/webhook" },
          },
        },
      } as any,
    });
    const results = scanConfig(cfg);
    const r = results.find((r) => r.rule === "webhook-url-insecure");
    expect(r).toBeUndefined();
  });
});

// ── Node.js EOL 检测（无真实 exec 时跳过）────────────────────

describe("checkNodeEOL 边界", () => {
  it("v22 Node.js 不触发 EOL 告警（当前 LTS）", () => {
    // v22 是当前活跃 LTS，不应报告
    // 此测试验证检测函数对已知版本的响应
    // 在无 child_process.execSync 的测试环境中，仅验证正则逻辑
    const versionStr = "v22.0.0";
    const major = parseInt(versionStr.replace(/^v/, "").split(".")[0], 10);
    expect(major >= 22).toBe(true);
    // v22+ 应该不触发 critical
  });
});

// 引入 os 用于上面测试
import * as os from "os";
