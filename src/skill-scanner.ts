/**
 * Skill 本地静态安全扫描器
 *
 * 设计思路:
 * - SSRF/注入检测：自研正则，检测用户可控变量进入网络请求函数
 * - RCE/危险调用检测：聚焦代码层 API（require/import/exec/eval/沙箱逃逸），与 command-security 的命令行模式区分
 * - 凭证窃取检测：自研规则，覆盖环境变量/SSH/AWS/GitHub 等常见密钥泄露路径
 * - 危险函数对：自研逐文件检测逻辑，检测同一文件中高危能力组合
 */

import * as fs from "fs";
import * as path from "path";
import os from "node:os";

export interface SkillScanResult {
  rule: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | "none";
  path: string;
  message: string;
  currentValue: string;
  suggestion: string;
}

export interface SkillScanReport {
  skillPath: string;
  skillName: string;
  totalFindings: number;
  maxSeverity: "critical" | "high" | "medium" | "low" | "none";
  findings: SkillScanResult[];
  scannedAt: string;
}

// ─────────────────────────────────────────────────────────────
// 检测规则定义
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// 规则 1: SSRF — fetch/axios/http 中用户可控 URL
// ─────────────────────────────────────────────────────────────
const SSRF_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  // fetch(url) / fetch($var) — 用户输入直接作 URL
  // 注意: \$ 后需跟标识符字符，/\s*\(\s*\$/ 只在变量名以 $ 开头时有效
  { pattern: /fetch\s*\(\s*\$[\w]*/, description: "fetch() 使用变量参数" },
  // http.get(url) / http.post(url) — 用户输入直接作 URL
  { pattern: /https?\.(?:get|post|put|delete|patch)\s*\(\s*\$[\w]*/, description: "http 方法使用变量参数" },
  // axios.get(url) / axios.post(url, { params: $ })
  { pattern: /axios\.(?:get|post|put|delete|patch)\s*\(\s*\$[\w]*/, description: "axios 方法使用变量参数" },
  // URL 拼接: url + userInput / baseUrl + param
  // $ 后跟标识符字符，支持 $userId、${...} 等格式
  // 注意: [\w{]* 匹配 $ 后的标识符（$userId 或 ${var}）
  { pattern: /(?:url|baseUrl|endpoint|apiUrl|api_base)\s*\+\s*\$[\w{]*/, description: "URL 拼接使用变量" },
  // fetch + template literal 含 ${...}
  { pattern: /fetch\s*\(`[\s\S]*\$\{/, description: "fetch 使用模板字符串含变量" },
  // request({ url: $var }) 格式
  { pattern: /url\s*:\s*\$[\w]*/, description: "request 选项含变量 URL" },
  // $.get / $.post (jQuery)
  { pattern: /\$\.(?:get|post|ajax)\s*\(\s*\$[\w]*/, description: "jQuery AJAX 使用变量" },
  // node-fetch / got / needle
  { pattern: /(?:node-fetch|got|needle)\s*\(\s*\$[\w]*/, description: "HTTP 库使用变量参数" },
];

// ─────────────────────────────────────────────────────────────
// 规则 2: 提示注入面 — 用户输入直接拼入 LLM prompt/systemPrompt
// ─────────────────────────────────────────────────────────────
const INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  // systemPrompt + userInput / instructions.concat(user)
  { pattern: /(?:systemPrompt|system_prompt|instructions|prompt)\s*(?:\+|\+=|concat)\s*\$[\w]*/, description: "系统提示词与变量拼接" },
  // prompt = `...${userInput}...`
  { pattern: /(?:prompt|instruction|systemPrompt|system_prompt)\s*=\s*`[\s\S]*\$\{/, description: "prompt 模板含用户变量" },
  // role: 'user' + content: userInput
  { pattern: /role\s*:\s*['"](?:user|assistant)['"]\s*,\s*content\s*:\s*\$[\w]*/, description: "消息 content 使用变量" },
  // messages.push({ ...userInput })
  { pattern: /messages\.(?:push|unshift)\s*\(\s*\{[^}]*content\s*:\s*\$[\w]*/, description: "消息数组拼接用户变量" },
  // completion/prompt 含 user input 直接注入
  { pattern: /(?:completion|prompt|chat)\s*\(\s*\{[^}]*prompt\s*:\s*\$[\w]*/i, description: "API 调用 prompt 参数使用变量" },
  // 构建消息时不转义用户输入
  { pattern: /messages?\s*\.?\s*\.?\s*(?:concat|push)\s*\([^)]*(?:input|text|message|query)\$[\w]*/i, description: "消息构建含用户输入变量" },
];

// ─────────────────────────────────────────────────────────────
// 规则 3: RCE / 危险系统调用（代码层，与 command-security 的命令行模式区分）
// skill-scanner 聚焦: require/import 引用 + 动态执行 API + 沙箱逃逸
// command-security 聚焦: nc/socat/bash 等 Shell 命令行模式
// ─────────────────────────────────────────────────────────────
const RCE_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  // Node.js child_process 引用（代码导入层）
  { pattern: /require\s*\(\s*['"]child_process['"]/, description: "引用 child_process 模块" },
  { pattern: /import\s+.+\s+from\s+['"]child_process['"]/, description: "导入 child_process 模块" },
  // Node.js 动态执行（代码层，区别于 command-security 的 bash -c）
  { pattern: /(?:\bexec|spawn|execFile|execSync)\s*\(\s*(?:\$|`|'|"|")/, description: "exec/spawn 使用动态参数" },
  { pattern: /\beval\s*\(\s*\$/, description: "eval 使用变量参数" },
  // Node.js 沙箱逃逸
  { pattern: /\b(?:vm\.runInNewContext|vm\.runInThisContext|vm\.runInContext)\b/, description: "VM 沙箱 API 调用" },
  // Python 动态导入与执行（代码层，区别于 command-security 的 python -c）
  { pattern: /\b__import__\s*\(\s*(?:\$|`|'|")/, description: "__import__ 动态导入变量模块" },
  { pattern: /\bexec\s*\(\s*(?:\$|`|'|"|")/, description: "exec 使用动态参数" },
  // PHP 危险函数（代码层，区别于 command-security 的 php -r）
  { pattern: /\b(?:shell_exec|passthru|proc_open|popen|exec)\s*\(\s*(?:\$|`|'|"|")/, description: "PHP 危险函数使用动态参数" },
  // Ruby 动态执行（代码层）
  { pattern: /\b(?:system|exec|spawn|`[^`]*\$\{[^}]+\}`)/, description: "Ruby 动态命令执行" },
  // Java 动态进程（代码层，区别于 command-security 的系统工具）
  { pattern: /\b(?:ProcessBuilder|Runtime\.getRuntime)\.(?:exec|load)\s*\(/, description: "Java 动态进程执行" },
  // .NET 动态代码（代码层）
  { pattern: /\b(?:Process\.Start|DynamicInvoke|Reflection\.Emit)/, description: ".NET 动态代码执行" },
  // 跨语言: 动态代码执行函数（通用）
  { pattern: /\b(?:Function\(|new Function)\s*\(\s*(?:\$|`|'|"|")/, description: "Function 构造函数动态代码" },
];

// ─────────────────────────────────────────────────────────────
// 规则 4: 凭证 / 密钥窃取
// ─────────────────────────────────────────────────────────────
const CREDENTIAL_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  // 读取环境变量中的密钥
  { pattern: /process\.env\.(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY|ACCESS_SECRET)/i, description: "访问密钥类环境变量" },
  // AWS 凭证文件
  { pattern: /\/\.aws\/(?:credentials|config)/i, description: "引用 AWS 凭证路径" },
  // SSH 私钥路径
  { pattern: /\/\.ssh\/(?:id_rsa|id_ed25519|known_hosts)/i, description: "引用 SSH 私钥路径" },
  // 云服务配置
  { pattern: /\/\.config\/(?:gcloud|azure|kubeconfig)/i, description: "引用云服务配置路径" },
  // GitHub Token
  { pattern: /GITHUB(?:_TOKEN|_AUTH|_KEY)/i, description: "引用 GitHub Token 环境变量" },
  // 读取配置文件中的密钥字段
  { pattern: /(?:api_key|apiKey|secret_key|secretKey|auth_token|authToken|access_token|accessToken)\s*:/i, description: "代码中引用密钥字段名" },
  // 写入外部文件存储凭证
  { pattern: /(?:writeFile|writeFileSync|appendFile)\s*\([^)]*(?:credential|secret|token|key)/i, description: "尝试将密钥写入文件" },
];

// ─────────────────────────────────────────────────────────────
// 规则 5: 敏感路径访问
// ─────────────────────────────────────────────────────────────
const SENSITIVE_PATH_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /\/\.ssh\//i, description: "访问 SSH 目录" },
  { pattern: /\/\.gnupg\//i, description: "访问 GPG 目录" },
  { pattern: /\/etc\/(?:passwd|shadow|group|sudoers)/i, description: "访问系统账户文件" },
  { pattern: /\/\.aws\//i, description: "访问 AWS 配置目录" },
  { pattern: /\/\.kube\/(?:config|ssl)/i, description: "访问 Kubernetes 配置" },
  { pattern: /\/\.docker\/config\.json/i, description: "访问 Docker 认证配置" },
  { pattern: /\/\.git\/(?:config|hooks)/i, description: "访问 Git 目录" },
  { pattern: /\/root\//i, description: "访问 root 用户目录" },
  { pattern: /\/\.bash_history|\/\.zsh_history/i, description: "访问 Shell 历史记录" },
  { pattern: /\/\.npm\/(?:rc|_logs)/i, description: "访问 npm 配置或日志" },
  { pattern: /\/\.config\/(?:passwd|credentials)/i, description: "访问凭证配置文件" },
  { pattern: /~\/\.[a-z]+\/(?:id_rsa|credential|token)/i, description: "访问家目录密钥文件" },
];

// ─────────────────────────────────────────────────────────────
// 规则 6: 危险函数对检测（单文件内两项高危能力同时出现）
// 替代原"三同时"逻辑，改为更精细的成对检测
// ─────────────────────────────────────────────────────────────

/**
 * 检测单文件内是否存在危险函数对
 * 每对 = 能力A + 能力B 同时出现，提升威胁级别
 */
interface DangerPair {
  check: (content: string) => boolean;
  rule: string;
  severity: "critical" | "high" | "medium";
  message: string;
  suggestion: string;
}

const DANGER_PAIRS: DangerPair[] = [
  // child_process + fetch → 可远程下载并执行
  {
    check: (c) => /require\s*\(\s*['"]child_process['"]/.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "critical",
    message: "同一文件中同时使用 child_process 和 fetch",
    suggestion: "存在远程代码执行风险：fetch 下载远程脚本，child_process 执行。建议移除 fetch 调用或限制网络目标",
  },
  // child_process + writeFile/writeFileSync → 可写入文件后执行
  {
    check: (c) => /require\s*\(\s*['"]child_process['"]/.test(c) && /\b(?:writeFile|writeFileSync|createWriteStream)\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "critical",
    message: "同一文件中同时使用 child_process 和文件写入",
    suggestion: "存在本地持久化攻击风险：先写入恶意文件再执行。建议移除写入操作或限制写入路径",
  },
  // eval/new Function + fetch → 动态代码可被远程注入
  {
    check: (c) => /\b(?:eval|Function)\s*\(/.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "critical",
    message: "同一文件中同时使用 eval/Function 和 fetch",
    suggestion: "存在远程代码注入风险：fetch 返回内容通过 eval 执行。建议移除 eval 或使用 JSON.parse 替代",
  },
  // __import__ + fetch → Python 动态导入可被远程注入
  {
    check: (c) => /\b__import__\s*\(/.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "critical",
    message: "同一文件中同时使用 __import__ 和 fetch",
    suggestion: "存在 Python 动态导入注入风险：fetch 返回内容作为模块导入。建议移除动态导入",
  },
  // exec/spawn + fetch → 命令注入 + 数据外传
  {
    check: (c) => /\b(?:exec|spawn)\s*\(\s*(?:\$|`|'|"|")/.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "high",
    message: "同一文件中同时使用 exec/spawn 和 fetch",
    suggestion: "存在命令注入和数据外传风险。建议审查 exec/spawn 参数来源，限制网络请求目标",
  },
  // child_process + writeFile + fetch → 三重危险（最高）
  {
    check: (c) => /require\s*\(\s*['"]child_process['"]/.test(c) && /\bwriteFile(?:Sync)?\s*\(/.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "critical",
    message: "同一文件中同时具备 child_process + 文件写入 + fetch",
    suggestion: "极高风险：可下载远程脚本 → 写入本地 → 执行。建议立即移除不必要的能力组合",
  },
  // vm.runInContext + fetch → 沙箱逃逸 + 网络请求
  {
    check: (c) => /\bvm\.(?:runInNewContext|runInThisContext|runInContext)\b/.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "high",
    message: "同一文件中同时使用 VM 沙箱 API 和 fetch",
    suggestion: "VM 沙箱可能已被绕过，配合 fetch 可实现远程代码注入。建议移除 VM API 或使用原生 isolate",
  },
  // processbuilder/runtime.exec + fetch → Java 动态执行 + 网络
  {
    check: (c) => /\b(?:ProcessBuilder|Runtime\.getRuntime)\./.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "high",
    message: "同一文件中同时使用 Java 动态进程和 fetch",
    suggestion: "Java 进程执行配合网络请求，存在远程代码执行风险。建议审查进程参数来源",
  },
  // exec + writeFile/writeFileSync → 命令注入 + 本地持久化
  {
    check: (c) => /\bexec\s*\(\s*(?:\$|`|'|"|")/.test(c) && /\b(?:writeFile|writeFileSync)\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "high",
    message: "同一文件中同时使用 exec 和文件写入",
    suggestion: "命令注入配合文件写入，存在本地持久化和提权风险。建议限制 exec 参数来源",
  },
  // shell_exec/proc_open + fetch → PHP 动态执行 + 网络
  {
    check: (c) => /\b(?:shell_exec|proc_open|passthru|popen)\s*\(/.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "critical",
    message: "同一文件中同时使用 PHP 危险函数和 fetch",
    suggestion: "PHP 命令执行配合网络请求，存在远程代码执行风险。建议使用安全的替代 API",
  },
  // system() + fetch → Ruby 系统命令 + 网络
  {
    check: (c) => /\bsystem\s*\(\s*(?:\$|`|'|"|")/.test(c) && /\bfetch\s*\(/.test(c),
    rule: "skill-dangerous-combination",
    severity: "high",
    message: "同一文件中同时使用 Ruby system 和 fetch",
    suggestion: "Ruby system 命令配合网络请求，存在远程代码执行风险",
  },
];

// ─────────────────────────────────────────────────────────────
// 核心扫描函数
// ─────────────────────────────────────────────────────────────

/**
 * 扫描单个 Skill 目录，返回扫描结果
 */
export function scanSkillDirectory(skillPath: string): SkillScanReport {
  const skillName = path.basename(skillPath);
  const findings: SkillScanResult[] = [];

  // 1. 扫描所有 JS/TS 文件
  const codeFiles = findCodeFiles(skillPath);

  for (const file of codeFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const relPath = path.relative(skillPath, file);

    // 规则 3: RCE 危险调用
    for (const { pattern, description } of RCE_PATTERNS) {
      if (pattern.test(content)) {
        findings.push(makeResult("skill-dangerous-syscall", "high", relPath, description, description, "审查该系统调用的必要性，优先使用安全的 API 替代 child_process/exec"));
      }
    }

    // 规则 4: 凭证窃取
    for (const { pattern, description } of CREDENTIAL_PATTERNS) {
      if (pattern.test(content)) {
        findings.push(makeResult("skill-credential-access", "critical", relPath, description, description, "确保访问密钥的目的正当且已获授权，勿将密钥写入日志或外部文件"));
      }
    }
  }

  // 规则 5: 敏感路径访问（所有文件含二进制和配置文件）
  const allFiles = findAllFiles(skillPath);
  for (const file of allFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const relPath = path.relative(skillPath, file);

    for (const { pattern, description } of SENSITIVE_PATH_PATTERNS) {
      if (pattern.test(content)) {
        findings.push(makeResult("skill-sensitive-path", "high", relPath, description, description, "检查是否需要访问该敏感路径，移除不必要的路径引用"));
      }
    }
  }

  // 规则 1: SSRF 检测（JS/TS 文件）
  for (const file of codeFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const relPath = path.relative(skillPath, file);

    for (const { pattern, description } of SSRF_PATTERNS) {
      if (pattern.test(content)) {
        findings.push(makeResult("skill-ssrf-risk", "high", relPath, description, description, "URL 参数需经过严格验证和白名单过滤，禁止用户可控 URL 直接传入网络请求"));
      }
    }
  }

  // 规则 2: 提示注入面（JS/TS 文件）
  for (const file of codeFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const relPath = path.relative(skillPath, file);

    for (const { pattern, description } of INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        findings.push(makeResult("skill-prompt-injection", "high", relPath, description, description, "用户输入必须经过严格转义或结构化处理后再传入 LLM 提示词，禁止直接拼接"));
      }
    }
  }

  // 规则 6: 危险函数对（单文件内逐文件检测高危函数组合）
  for (const file of codeFiles) {
    let fileContent: string;
    try {
      fileContent = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const relPath = path.relative(skillPath, file);

    for (const pair of DANGER_PAIRS) {
      if (pair.check(fileContent)) {
        findings.push(makeResult(pair.rule, pair.severity, relPath, pair.message, "danger-pair", pair.suggestion));
        // 不 break：每个危险函数对都需要记录
      }
    }
  }

  // 规则 7: package.json / SKILL.md 元数据检查
  checkManifestMetadata(skillPath, skillName, findings);

  // 规则 8: package.json 权限声明
  checkPackagePermissions(skillPath, findings);

  // 去重（同一文件同一规则只报一次）
  const uniqueFindings = deduplicateFindings(findings);

  return {
    skillPath,
    skillName,
    totalFindings: uniqueFindings.length,
    maxSeverity: maxSeverityOf(uniqueFindings),
    findings: uniqueFindings,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * 检查 SKILL.md / package.json 元数据完整性
 */
function checkManifestMetadata(skillPath: string, skillName: string, findings: SkillScanResult[]) {
  // 检查 SKILL.md 是否存在
  const skillMdPath = path.join(skillPath, "SKILL.md");
  const packageJsonPath = path.join(skillPath, "package.json");

  if (!fs.existsSync(skillMdPath) && !fs.existsSync(packageJsonPath)) {
    findings.push(makeResult("skill-metadata-missing", "medium", skillName,
      "Skill 目录下既无 SKILL.md 也无 package.json",
      "no manifest",
      "Skill 应包含描述文件以表明来源和用途，无元数据将无法验证其可信度"));
    return;
  }

  // 读取 package.json（如果存在）
  if (fs.existsSync(packageJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
      const issues: string[] = [];

      // 缺少 description
      if (!pkg.description || pkg.description.trim().length < 10) {
        issues.push("缺少有意义的 description（少于10字符）");
      }

      // 缺少 author
      if (!pkg.author && !pkg.maintainers?.length) {
        issues.push("缺少 author 或 maintainers 信息");
      }

      // 描述过于模糊
      if (pkg.description && /^(todo|fixme|test|example|sample|temp|demo)$/i.test(pkg.description.trim())) {
        issues.push("description 为占位符文本，缺乏真实描述");
      }

      // scripts 中有危险命令
      const scripts = pkg.scripts || {};
      for (const [name, cmd] of Object.entries(scripts)) {
        const cmdStr = String(cmd);
        if (/curl\s+.*\|\s*sh|curl\s+.*\|\s*bash|wget\s+.*\|\s*sh/i.test(cmdStr)) {
          findings.push(makeResult("skill-dangerous-install-hook", "critical", `package.json scripts.${name}`,
            `npm script 包含管道下载执行命令`,
            cmdStr.substring(0, 50),
            "禁止在安装脚本中执行远程脚本，这是一条经典的供应链攻击路径"));
        }
        if (/rm\s+-rf\s+\/|:\(\)\{:\|:&\}\(:\)/i.test(cmdStr)) {
          findings.push(makeResult("skill-dangerous-install-hook", "critical", `package.json scripts.${name}`,
            "npm script 包含危险系统命令",
            cmdStr.substring(0, 50),
            "检查脚本命令来源，移除不必要的危险操作"));
        }
      }

      if (issues.length > 0) {
        findings.push(makeResult("skill-metadata-incomplete", "low", "package.json",
          `元数据不完整: ${issues.join("; ")}`,
          issues.join("; "),
          "完善 package.json 元数据有助于建立可追溯的供应链信任链"));
      }
    } catch {
      // JSON 解析失败
      findings.push(makeResult("skill-metadata-invalid", "medium", "package.json",
        "package.json 格式无效，无法解析",
        "invalid JSON",
        "请检查 package.json 语法是否正确"));
    }
  }
}

/**
 * 检查 package.json 权限声明
 */
function checkPackagePermissions(skillPath: string, findings: SkillScanResult[]) {
  const packageJsonPath = path.join(skillPath, "package.json");
  if (!fs.existsSync(packageJsonPath)) return;

  try {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));

    // 无 engines 限制（建议声明支持的 Node 版本）
    if (!pkg.engines && !pkg.engines?.node) {
      findings.push(makeResult("skill-no-engines-constraint", "info", "package.json",
        "未声明 Node.js 版本约束",
        "no engines constraint",
        "建议在 engines 字段声明支持的 Node.js 版本范围，避免在过旧或过新版本上运行出现安全问题"));
    }

    // 无 keywords（难以评估来源）
    if (!pkg.keywords || pkg.keywords.length === 0) {
      findings.push(makeResult("skill-no-keywords", "info", "package.json",
        "未设置 keywords 字段",
        "no keywords",
        "添加 keywords 有助于识别 Skill 类别和用途"));
    }
  } catch {
    // ignore
  }
}

// ─────────────────────────────────────────────────────────────
// 辅助函数
// ─────────────────────────────────────────────────────────────

function findCodeFiles(dir: string, depth = 4, current = 0): string[] {
  const results: string[] = [];
  if (current > depth) return results;
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        results.push(...findCodeFiles(full, depth, current + 1));
      } else if (/\.(js|ts|mjs|cjs)$/.test(entry.name)) {
        results.push(full);
      }
    }
  } catch {
    // ignore
  }
  return results;
}

function findAllFiles(dir: string, depth = 4, current = 0): string[] {
  const results: string[] = [];
  if (current > depth) return results;
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        results.push(...findAllFiles(full, depth, current + 1));
      } else if (/\.(js|ts|mjs|cjs|sh|py|rb|php|json|yaml|yml|md|txt|env|conf|cfg|ini)$/.test(entry.name)) {
        results.push(full);
      }
    }
  } catch {
    // ignore
  }
  return results;
}

function makeResult(
  rule: string,
  severity: SkillScanResult["severity"],
  filePath: string,
  message: string,
  currentValue: string,
  suggestion: string,
): SkillScanResult {
  return { rule, severity, path: filePath, message, currentValue, suggestion };
}

function deduplicateFindings(findings: SkillScanResult[]): SkillScanResult[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.rule}:${f.path}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function maxSeverityOf(findings: SkillScanResult[]): "critical" | "high" | "medium" | "low" | "none" {
  if (findings.length === 0) return "none";
  const order: Array<"critical" | "high" | "medium" | "low" | "info"> = ["critical", "high", "medium", "low", "info"];
  let max = 0;
  for (const f of findings) {
    const i = order.indexOf(f.severity as typeof order[number]);
    if (i > max) max = i;
  }
  const result = order[max];
  // "info" 不在 SkillScanReport.maxSeverity 类型中，映射到 "low"
  return result === "info" ? "low" : result;
}

// ─────────────────────────────────────────────────────────────
// 公开接口：扫描默认 Skill 目录
// ─────────────────────────────────────────────────────────────

const DEFAULT_SKILL_PATHS = [
  path.join(os.homedir(), ".npm-global/lib/node_modules/openclaw/skills"),
  path.join(os.homedir(), ".openclaw/skills"),
  path.join(os.homedir(), ".openclaw/workspace/skills"),
];

/**
 * 扫描所有已安装的 Skill，返回汇总报告
 */
export function scanAllSkills(): Map<string, SkillScanReport> {
  const results = new Map<string, SkillScanReport>();

  for (const basePath of DEFAULT_SKILL_PATHS) {
    if (!fs.existsSync(basePath)) continue;
    try {
      const entries = fs.readdirSync(basePath, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const skillPath = path.join(basePath, entry.name);
        const report = scanSkillDirectory(skillPath);
        results.set(report.skillName, report);
      }
    } catch {
      // ignore
    }
  }

  return results;
}

/**
 * 扫描指定 Skill 目录
 */
export function scanSkill(skillPath: string): SkillScanReport {
  return scanSkillDirectory(skillPath);
}
