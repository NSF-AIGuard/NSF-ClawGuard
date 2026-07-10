# 故障排除指南

本文档帮助用户解决 NSF-ClawGuard 的常见问题。

## Web UI 无法访问

### 问题描述

用户尝试访问 `http://localhost:<port>/lm-security` 或其他路径时，页面跳转到 OpenClaw 的聊天界面，而不是安全监控仪表板。

### 解决方案

**正确的 Web UI 访问地址**：

```
http://localhost:<port>/web
```

其中 `<port>` 是 OpenClaw 配置的控制面板端口（默认通常是 18789）。

### 常见错误

| 错误路径 | 说明 | 正确路径 |
|---------|------|---------|
| `/lm-security` | 这是 API 端点前缀，不是 Web UI 路径 | `/web` |
| `/lm-securty/overview` | 这是 API 接口，返回 JSON 数据 | `/web` |
| `/dashboard` | 不存在此路径 | `/web` |

### 排查步骤

1. **确认端口号**：
   - 检查 OpenClaw 配置文件中的 `control_ui.port` 设置
   - 默认端口通常是 18789

2. **确认插件已加载**：
   - 查看 OpenClaw 启动日志，确认 NSF-ClawGuard 插件已成功加载
   - 日志中应显示类似 `Plugin loaded: nsf-clawguard` 的信息

3. **检查端口监听**：
   ```bash
   # Linux/Mac
   netstat -an | grep <port>
   
   # Windows
   netstat -an | findstr <port>
   ```

4. **尝试直接访问 API**：
   ```bash
   curl http://localhost:<port>/lm-securty/overview
   ```
   如果 API 返回 JSON 数据，说明插件正常运行，问题在于 Web UI 路径。

### 示例

假设 OpenClaw 配置的控制面板端口是 18789：

```bash
# 正确的 Web UI 访问方式
open http://localhost:18789/web

# 错误的访问方式（会跳转到聊天界面）
open http://localhost:18789/lm-security
```

## 插件未加载

### 问题描述

OpenClaw 启动后，Web UI 无法访问，API 端点返回 404。

### 解决方案

1. **检查插件配置**：
   - 确认 `openclaw.plugin.json` 文件存在于正确位置
   - 确认插件目录结构完整

2. **查看启动日志**：
   - 检查 OpenClaw 启动日志中是否有插件加载错误
   - 常见错误包括：依赖缺失、端口冲突、权限问题

3. **手动加载插件**：
   ```bash
   # 在 OpenClaw 目录中
   npm install
   npm run build
   ```

4. **重启 OpenClaw**：
   - 完全关闭 OpenClaw 进程
   - 重新启动并观察日志输出

## 数据库问题

### 问题描述

安全事件无法保存，或查询历史记录时出错。

### 解决方案

1. **检查数据库文件**：
   - 数据库位于 `<pluginRoot>/data/lm-security.db`
   - 确认文件存在且有读写权限

2. **重建数据库**：
   - 备份现有数据库文件
   - 删除原文件，重启 OpenClaw 会自动创建新数据库

3. **检查磁盘空间**：
   - 确认磁盘有足够空间存储数据库文件

## 其他问题

如果遇到本文档未覆盖的问题，请：

1. 查看 [GitHub Issues](https://github.com/NSF-AIGuard/NSF-ClawGuard/issues) 是否有相关讨论
2. 提交新的 Issue，附上：
   - OpenClaw 版本
   - 操作系统
   - 错误日志
   - 复现步骤
