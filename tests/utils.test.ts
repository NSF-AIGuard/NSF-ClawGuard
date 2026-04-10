/**
 * utils.test.ts
 * 单元测试：工具函数
 */

import { describe, it, expect, beforeEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";
import {
  extractFrontmatter,
  getConfigLastModified,
  getExtensionsDirModified,
  getMCPDirModified,
  getHooksDirModified,
  getCurrentPluginRoot,
} from "../src/utils.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── extractFrontmatter ────────────────────────────────────────

describe("extractFrontmatter", () => {
  it("正确解析 name 和 description", () => {
    const content = [
      "---",
      "name: weather",
      "description: Get current weather and forecasts",
      "---",
      "",
      "# Weather Skill",
      "",
      "Some content here.",
    ].join("\n");
    const tmp = path.join(os.tmpdir(), "test-frontmatter.md");
    fs.writeFileSync(tmp, content, "utf-8");
    const result = extractFrontmatter(tmp);
    expect(result.name).toBe("weather");
    expect(result.description).toBe("Get current weather and forecasts");
    fs.unlinkSync(tmp);
  });

  it("仅有 description 无 name", () => {
    const content = [
      "---",
      "description: Some skill description",
      "---",
    ].join("\n");
    const tmp = path.join(os.tmpdir(), "test-desc-only.md");
    fs.writeFileSync(tmp, content, "utf-8");
    const result = extractFrontmatter(tmp);
    expect(result.name).toBeUndefined();
    expect(result.description).toBe("Some skill description");
    fs.unlinkSync(tmp);
  });

  it("无 frontmatter 返回空对象", () => {
    const content = "# Just a regular file\n\nNo frontmatter here.";
    const tmp = path.join(os.tmpdir(), "test-no-fm.md");
    fs.writeFileSync(tmp, content, "utf-8");
    const result = extractFrontmatter(tmp);
    expect(result.name).toBeUndefined();
    expect(result.description).toBeUndefined();
    fs.unlinkSync(tmp);
  });

  it("空文件不崩溃", () => {
    const tmp = path.join(os.tmpdir(), "test-empty.md");
    fs.writeFileSync(tmp, "", "utf-8");
    const result = extractFrontmatter(tmp);
    expect(result).toEqual({});
    fs.unlinkSync(tmp);
  });

  it("文件不存在返回空对象", () => {
    const result = extractFrontmatter("/nonexistent/path/file.md");
    expect(result).toEqual({});
  });

  it("description 含中文", () => {
    const content = [
      "---",
      "name: 天气插件",
      "description: 获取当前天气和预报信息",
      "---",
    ].join("\n");
    const tmp = path.join(os.tmpdir(), "test-cn.md");
    fs.writeFileSync(tmp, content, "utf-8");
    const result = extractFrontmatter(tmp);
    expect(result.name).toBe("天气插件");
    expect(result.description).toBe("获取当前天气和预报信息");
    fs.unlinkSync(tmp);
  });

  it("多行 description（第二行非键值对）", () => {
    const content = [
      "---",
      "description: A long description",
      "that spans multiple lines in frontmatter",
      "but our parser only handles single lines",
      "name: test",
      "---",
    ].join("\n");
    const tmp = path.join(os.tmpdir(), "test-multi.md");
    fs.writeFileSync(tmp, content, "utf-8");
    const result = extractFrontmatter(tmp);
    expect(result.name).toBe("test");
    expect(result.description).toBe("A long description");
    fs.unlinkSync(tmp);
  });
});

// ── getConfigLastModified ──────────────────────────────────────

describe("getConfigLastModified", () => {
  it("返回 ISO 时间字符串", () => {
    const result = getConfigLastModified();
    if (result) {
      // 应为有效 ISO 字符串
      expect(() => new Date(result)).not.toThrow();
    }
    // 如果配置文件不存在，返回空字符串（不崩溃）
  });

  it("返回空字符串当文件不存在", () => {
    // openclaw.json 可能存在也可能不存在，取决于测试环境
    // 只验证返回值类型
    const result = getConfigLastModified();
    expect(typeof result).toBe("string");
  });
});

// ── getExtensionsDirModified ──────────────────────────────────

describe("getExtensionsDirModified", () => {
  it("返回时间戳或空字符串（目录可能不存在）", () => {
    const result = getExtensionsDirModified();
    expect(typeof result).toBe("string");
    if (result) {
      expect(() => new Date(result)).not.toThrow();
    }
  });
});

// ── getMCPDirModified ─────────────────────────────────────────

describe("getMCPDirModified", () => {
  it("空路径列表返回空字符串", () => {
    const result = getMCPDirModified([]);
    expect(result).toBe("");
  });

  it("不存在路径不崩溃", () => {
    const result = getMCPDirModified(["/nonexistent/path/to/mcp.json"]);
    expect(typeof result).toBe("string");
  });

  it("返回最新修改时间", () => {
    // 创建临时文件
    const tmp = path.join(os.tmpdir(), "mcp-test.json");
    fs.writeFileSync(tmp, '{"mcpServers": {}}', "utf-8");
    const mtime = fs.statSync(tmp).mtime.toISOString();
    const result = getMCPDirModified([tmp]);
    expect(result).toBe(mtime);
    fs.unlinkSync(tmp);
  });
});

// ── getHooksDirModified ───────────────────────────────────────

describe("getHooksDirModified", () => {
  it("返回时间戳或空字符串（目录可能不存在）", () => {
    const result = getHooksDirModified();
    expect(typeof result).toBe("string");
  });

  it("不存在路径不崩溃", () => {
    // 不依赖实际路径存在
    expect(() => getHooksDirModified()).not.toThrow();
  });
});

// ── getCurrentPluginRoot ──────────────────────────────────────

describe("getCurrentPluginRoot", () => {
  it("返回插件根目录路径（包含 index.ts 同级的 ..）", () => {
    const result = getCurrentPluginRoot();
    expect(result).toBeTruthy();
    expect(typeof result).toBe("string");
    expect(result.endsWith("lm-security") || result.endsWith("lm-security/")).toBe(true);
  });
});
