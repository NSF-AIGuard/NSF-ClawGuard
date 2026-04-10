# NSF-ClawGuard

[English](https://github.com/NSF-AIGuard/NSF-ClawGuard/blob/main/README.md) | [中文](https://github.com/NSF-AIGuard/NSF-ClawGuard/blob/main/README-CN.md)

一款适用于 [OpenClaw 的](https://github.com/openclaw)实时安全监控插件，能够智能识别风险并提供应对方案。

<p align="center">
  <a href="https://github.com/NSF-AIGuard/NSF-ClawGuard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/Node.js-%3E%3D18-green.svg" alt="Node.js >= 18" />
  <img src="https://img.shields.io/badge/TypeScript-5.9-blue.svg" alt="TypeScript" />
</p>

NSF-ClawGuard 是一款适用于 [OpenClaw](https://github.com/openclaw) 和 [ClawdBot](https://github.com/openclaw) 的全方位实时安全监控插件。提供多层安全防护能力，包括配置文件扫描、运行时命令监控、Skill 代码分析、内容安全审查以及基于 Web 的安全仪表盘。

> **English documentation** please see [README.md](./README.md)

---

## ✨ 核心特性

### 🔍 多层安全扫描
- **配置文件安全扫描** — 对 `~/.openclaw/openclaw.json` 进行静态分析，内置 30+ 条安全规则，覆盖令牌安全、网络安全、会话安全、数据保护、插件安全、执行安全和速率限制等领域
- **SOUL.md 提示注入检测** — 识别 SOUL.md 配置文件中的提示注入攻击
- **Skill 代码静态扫描** — 对已安装的 Skill 进行深度分析，覆盖 SSRF、提示注入、远程代码执行、凭证窃取、敏感路径访问和危险函数组合
- **npm 依赖漏洞审计** — 检测项目依赖中的已知漏洞
- **Node.js 生命周期检测** — 在运行不受支持的 Node.js 版本时发出警告

### 🛡️ 运行时防护
- **命令安全监控** — 在执行前拦截和检查危险 Shell 命令（反弹 Shell、文件破坏、权限提升、凭证窃取、进程注入等）
- **内容安全审查** — 通过本地规则或远程 API 监控用户输入和 AI 输出中的恶意内容
- **工具调用审计** — 记录所有工具调用（`exec`、`write`、`edit`）的耗时、参数和执行状态
- **Gateway 认证监控** — 实时监控 Gateway WebSocket 认证事件，支持暴力破解检测

### 📊 可观测性
- **Web 安全仪表盘** — 基于 React 的安全仪表盘，包含事件总览、威胁分布图、Token 用量统计和 Gateway 认证日志
- **Token 用量追踪** — 按会话/模型记录 AI 模型 Token 消耗，包括缓存命中指标
- **SQLite 事件存储** — 所有安全事件持久化到本地 SQLite 数据库（`data/lm-security.db`），支持索引查询
- **违规事件上报** — 自动将安全违规事件上报至远程服务器（可配置）

### 🔧 其他能力
- **CLI 命令** — `nsf-clawguard check`、`nsf-clawguard config-scan`、`nsf-clawguard config-scan-full`
- **端口扫描** — 发现并探测监听在 `0.0.0.0` 上的暴露服务
- **心跳机制** — 定期健康检查，支持插件吊销检测

---

## 🏗️ 项目架构

```
NSF-ClawGuard/
├── index.ts                     # 插件入口 & 事件钩子注册
├── src/
│   ├── api.ts                   # 远程 API：违规上报、心跳、内容检测
│   ├── command-security.ts      # 80+ 条危险命令模式检测规则
│   ├── config-scanner.ts        # 30+ 条配置安全扫描规则
│   ├── skill-scanner.ts         # 8 大类 Skill 代码静态分析
│   ├── database.ts              # SQLite 数据库 (sql.js) 含 4 张数据表
│   ├── event-store.ts           # 统一事件存储 & 分类映射
│   ├── logger.ts                # 带前缀的日志封装
│   ├── request.ts               # HTTP 客户端 (HMAC 认证)
│   ├── constants.ts             # 共享常量
│   ├── types.ts                 # TypeScript 类型定义
│   ├── utils.ts                 # 工具函数
│   ├── cli/
│   │   └── index.ts             # CLI 命令注册
│   ├── scan-port/
│   │   └── index.ts             # 网络端口扫描器（跨平台）
│   └── server/
│       ├── index.ts             # HTTP 路由注册
│       ├── inspect.ts           # 安全事件 & 统计 API 处理器
│       ├── audit.ts             # Token 用量 & 工具调用 API 处理器
│       ├── router.ts            # 轻量级 HTTP 路由器
│       ├── static.ts            # Web UI 静态文件服务
│       ├── utils.ts             # 服务器工具函数
│       └── ui/                  # React 仪表盘 (Vite + Ant Design)
├── tests/                       # 单元测试 (Vitest)
├── scripts/
│   └── build.js                 # 完整构建脚本（UI + 主包）
├── openclaw.plugin.json         # OpenClaw 插件清单
├── clawdbot.plugin.json         # ClawdBot 插件清单
├── tsup.config.ts               # 构建配置
├── tsconfig.json                # TypeScript 配置
└── vitest.config.ts             # 测试配置
```

---

## 📦 安装

```bash
# 安装依赖
npm install

# 构建插件
npm run build

# 完整构建（包含 Web 仪表盘）
npm run build:full
```

---

## 🚀 开发

```bash
# 构建
npm run build

# 运行测试
npm test

# 测试监听模式
npm run test:watch

# 生成覆盖率报告
npm run test:coverage

# 完整构建（UI + 主包）
npm run build:full
```

---

## 🔐 安全扫描详情

### 配置扫描器（30+ 规则）

对 `~/.openclaw/openclaw.json` 进行 7 大安全域扫描：

| 安全域 | 规则数 | 示例 |
|--------|--------|------|
| **令牌安全** | 3 条 | 熵值检测（< 48 字符）、弱模式检测（200+ 模式）、硬编码 API Key |
| **网络安全** | 7 条 | Gateway 绑定暴露、TLS 加密要求、CORS 通配符、API 端点安全、代理信任配置 |
| **会话安全** | 3 条 | 会话 TTL 检测、认证模式验证、会话隔离 |
| **数据保护** | 3 条 | 工作区限制、详细日志级别、日志包含敏感信息 |
| **插件安全** | 3 条 | 插件白名单、来源验证、内部钩子 |
| **执行安全** | 6 条 | 执行安全配置、写入路径限制、拒绝命令列表、MCP 信任配置 |
| **速率限制** | 1 条 | 速率限制配置与阈值验证 |

### Skill 扫描器（8 大类）

对所有已安装的 Skill 进行静态安全分析：

1. **SSRF 检测** — 检测 `fetch()`、`axios`、`http.get()` 中的用户可控 URL、URL 拼接和模板字符串
2. **提示注入检测** — 检测通过字符串拼接、模板字面量或消息数组操作将用户输入拼接到 LLM 提示词中
3. **RCE / 危险调用** — 检测 `child_process`、`eval()`、`vm.runInNewContext`、`__import__`、PHP/Ruby/Java 危险函数
4. **凭证窃取** — 检测访问 `process.env` 密钥、AWS/SSH/GitHub 路径、密钥字段名和凭证文件写入
5. **敏感路径访问** — 检测对 `.ssh/`、`.gnupg/`、`/etc/passwd`、`.aws/`、`.kube/`、`.git/`、Docker 配置等的访问
6. **危险函数组合** — 检测高风险组合：`child_process + fetch`、`eval + fetch`、`writeFile + exec` 等
7. **元数据质量** — 检查缺失或不完整的 `package.json` 字段（description、author 等）
8. **安装钩子风险** — 检测危险 npm scripts，如 `curl | bash`

### 命令安全监控（80+ 模式）

实时拦截工具调用，覆盖：

- **反弹 Shell** — `bash -i`、`nc -e`、`socat`、`awk`、`python -c`、`perl -e`、`php -r`、`ruby -e`
- **系统破坏** — `rm -rf /`、`mkfs`、`dd`、块设备重定向
- **凭证窃取** — `procdump`、`comsvcs.dll`、`reg save`、`Sqldumper`
- **权限提升** — `BadPotato`、`JuicyPotato`、`SweetPotato`、`EfsPotato`
- **下载执行链** — `curl | bash`、`wget | sh`、`base64 | bash`
- **进程注入** — `gdb -p`、`ptrace`、`strace -p`
- **内核模块** — `insmod`、`modprobe`、`rmmod`
- **编码混淆** — Base64 解码管道、通过 `rev` 反转命令
- **注册表操作** — `REG ADD/DELETE/SAVE`、`wevtutil` 日志操作
- **Cron 注入** — `echo | crontab`、管道到 `crontab -`

---

## 🪝 插件钩子

| 钩子 | 触发时机 | 执行动作 |
|------|----------|----------|
| `message_received` | 用户发送消息 | 对输入内容进行安全审查 |
| `agent_end` | AI Agent 完成响应 | 对输出内容进行安全审查 |
| `before_tool_call` | 工具执行前 | 对 `exec`、`write`、`edit` 进行命令安全检查 |
| `after_tool_call` | 工具执行后 | 记录工具调用的耗时和结果 |
| `llm_output` | LLM 响应接收时 | 记录 Token 使用量指标 |

---

## 💾 数据存储

所有事件存储在本地 SQLite 数据库（`<插件根目录>/data/lm-security.db`）：

| 数据表 | 用途 | 关键字段 |
|--------|------|----------|
| `security_events` | 所有安全发现 | category, sub_category, threat_level, event_time |
| `token_usage` | AI Token 消耗记录 | session_key, model, input/output/total tokens |
| `tool_call` | 工具调用记录 | tool_name, params, result, duration_ms |
| `gateway_auth_logs` | Gateway 认证事件 | event_type, conn_id, remote_ip, client |

---

## 🖥️ Web 安全仪表盘

访问安全仪表盘：**http://localhost:18789/web**（其中 `18789` 为 Control UI 界面访问端口）

### 页面截图

**事件概览** — 安全事件汇总、威胁分布图表、7 天趋势和端侧安全通过率：

![事件概览](https://raw.githubusercontent.com/NSF-AIGuard/NSF-ClawGuard/main/screenshot/overview.png)

**Token 消耗** — 按会话和模型的 Token 用量统计，含输入/输出明细：

![Token 消耗](https://raw.githubusercontent.com/NSF-AIGuard/NSF-ClawGuard/main/screenshot/consumption.png)

**工具调用** — 工具调用历史记录，含参数、结果和耗时详情：

![工具调用](https://raw.githubusercontent.com/NSF-AIGuard/NSF-ClawGuard/main/screenshot/tool.png)

### 仪表盘页面

| 页面 | 描述 |
|------|------|
| **总览** | 安全事件汇总、威胁分布和近期活动 |
| **安全事件** | 可筛选的安全发现列表，含威胁等级 |
| **Token 用量** | 按会话和模型的 Token 消耗趋势 |
| **工具调用** | 详细的工具调用历史及耗时 |
| **Gateway 认证** | 认证事件日志及连接详情 |

### API 接口

| 接口 | 描述 |
|------|------|
| `GET /lm-securty/overview` | 仪表盘总览统计 |
| `GET /lm-securty/events` | 安全事件列表 |
| `GET /lm-securty/securityEventStats` | 7 天事件趋势图数据 |
| `GET /lm-securty/tokenUsage` | Token 用量记录 |
| `GET /lm-securty/toolCall` | 工具调用记录 |
| `GET /lm-securty/gatewayAuthLogs` | Gateway 认证日志 |

---

## ⚙️ 配置说明

### 插件清单

插件通过 `openclaw.plugin.json` 进行配置：

```json
{
  "id": "nsf-clawguard",
  "name": "nsf-clawguard",
  "description": "Real-time monitoring of the security status on the client side, intelligently identifying risks and providing handling solutions",
  "version": "1.0.0",
  "configSchema": {
    "type": "object",
    "properties": {
      "mcpPaths": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Paths to MCP config files to monitor"
      }
    }
  }
}
```

### 远程 API 配置

在插件根目录下创建 `config.json`：

```json
{
  "baseUrl": "https://your-security-server.example.com",
  "secretKey": "your-hmac-secret-key",
  "accessKey": "your-access-key",
  "appId": "your-app-id",
  "verifySsl": true,
  "mode": "online"
}
```

- 设置 `mode` 为 `"online"` 可启用远程 API 功能（违规上报、内容检测、心跳）
- 设置 `mode` 为其他值则运行在**离线模式** — 仅使用本地安全检测

---

## 🖱️ CLI 命令

```bash
# 上传并扫描 Skills/插件
nsf-clawguard check

# 扫描配置安全问题（仅显示失败项）
nsf-clawguard config-scan

# 完整配置扫描（显示所有规则状态）
nsf-clawguard config-scan-full

# JSON 格式输出
nsf-clawguard config-scan --json
nsf-clawguard config-scan-full --json
```

---

## 🧪 测试

```bash
# 运行所有测试
npm test

# 监听模式
npm run test:watch

# 生成覆盖率报告
npm run test:coverage
```

测试使用 [Vitest](https://vitest.dev/) 和 V8 覆盖率提供器。测试文件位于 `tests/` 目录。

---

## 🤝 参与贡献

1. Fork 本仓库
2. 创建功能分支（`git checkout -b feature/amazing-feature`）
3. 提交更改（`git commit -m 'Add amazing feature'`）
4. 推送到分支（`git push origin feature/amazing-feature`）
5. 发起 Pull Request

---

## 📄 许可证

MIT 许可证 — 版权所有 (c) 2026 NSFOCUS Technologies Group Co., Ltd. 详情请参阅 [LICENSE](./LICENSE) 文件。