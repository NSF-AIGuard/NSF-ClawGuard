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
// 严重等级映射: warning→medium, HIGH→high, CRITICAL→critical, MEDIUM→medium, LOW→low
// ─────────────────────────────────────────────────────────────

type PatternRule = { pattern: RegExp; description: string; severity: SkillScanResult["severity"] };

interface PatternCategory {
  patterns: PatternRule[];
  rule: string;
  suggestion: string;
}

// 规则 9: 代码混淆检测
const OBFUSCATION_PATTERNS: PatternRule[] = [
  { pattern: /pickle\.loads/, description: "Pickle 反序列化(RCE 风险）", severity: "critical" },
  { pattern: /marshal\.loads/, description: "Python 对象反序列化", severity: "high" },
  { pattern: /yaml\.load\b/, description: "YAML 加载未使用安全模式", severity: "high" },
  { pattern: /(?:atob|btoa|Buffer\.from.*base64)\s*\(/, description: "Base64 编解码函数", severity: "medium" },
  { pattern: /base64\.(b64decode|b32decode|b16decode|decodebytes)/, description: "Base64 解码函数", severity: "medium" },
  { pattern: /(?:base64|base-64|b64)\s+(?:--decode|-d)/, description: "Base64 解码执行", severity: "critical" },
  { pattern: /base64\s+(?:--decode|-d)\s*[^|]*\|\s*(?:bash|sh|python|node|eval)/, description: "Base64 解码后管道执行", severity: "critical" },
  { pattern: /eval\(.*base64|eval\(.*curl|eval\(.*wget/, description: "eval 配合解码载荷执行", severity: "critical" },
  { pattern: /(?:base64\.b64decode|atob).*?(?:exec|eval|system|popen|subprocess|Function\()/, description: "Base64 解码后执行", severity: "critical" },
  { pattern: /String\.fromCharCode\s*\([^)]{30,}\)/, description: "JS fromCharCode 混淆", severity: "high" },
  { pattern: /chr\(\d+\)\s*\+\s*chr\(\d+\)/, description: "chr() 字符构造混淆", severity: "high" },
  { pattern: /(?:String\.fromCharCode|chr\(|\\u00[0-9a-fA-F]{2}){3,}/, description: "字符编码构造", severity: "high" },
  { pattern: /bytes\.fromhex\s*\(/, description: "Hex 字节解码", severity: "high" },
  { pattern: /codecs\.decode\s*\([^)]*,\s*['"]rot/, description: "ROT 编码混淆", severity: "medium" },
  { pattern: /binascii\.(unhexlify|a2b_base64)/, description: "二进制数据转换", severity: "medium" },
  { pattern: /(?:zlib|gzip)\.decompress/, description: "解压缩（可能用于混淆）", severity: "medium" },
  { pattern: /import\s*\(\s*(?:atob|decode|Buffer|__encode)/, description: "动态导入可疑解码函数", severity: "high" },
  { pattern: /(?:0x[0-9a-fA-F]{20,}|\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){9,})/, description: "长十六进制编码字符串", severity: "medium" },
  { pattern: /[\\u200b\\ufeff\\u200c\\u200d\\u2060\\u180e]/, description: "零宽字符嵌入", severity: "high" },
  { pattern: /[\u202e\u2066\u2067\u2068\u2069\u200f]/, description: "Unicode RTL/LTR 覆盖字符", severity: "high" },
  { pattern: /\u202e|\u2066|\u2067|\u2068|\u2069|\u200f/, description: "Unicode 方向覆盖字符", severity: "high" },
  { pattern: /xn--/, description: "IDN 同形异义域名", severity: "medium" },
  { pattern: /\[::-1\]|\.reverse\(\)\.join/, description: "字符串反转混淆", severity: "medium" },
  { pattern: /<script/, description: "Script 标签注入", severity: "critical" },
  { pattern: /<iframe/, description: "Iframe 标签注入", severity: "high" },
  { pattern: /<svg/, description: "SVG 标签注入", severity: "high" },
  { pattern: /<embed/, description: "Embed 标签注入", severity: "high" },
  { pattern: /<object/, description: "Object 标签注入", severity: "high" },
  { pattern: /onerror\s*=/, description: "onerror 事件处理器", severity: "critical" },
  { pattern: /onload\s*=/, description: "onload 事件处理器", severity: "critical" },
  { pattern: /onmouseover\s*=/, description: "onmouseover 事件处理器", severity: "high" },
  { pattern: /javascript\s*:/, description: "JavaScript 协议", severity: "critical" },
  { pattern: /data:text\/html/, description: "Data URI HTML 注入", severity: "high" },
  { pattern: /expression\s*\(/, description: "CSS expression 注入", severity: "high" },
  { pattern: /\/dev\/tcp\/\S+/, description: "Bash /dev/tcp 反向 shell", severity: "critical" },
  { pattern: /\[\:\:1\]|reverse\s*shell|bind\s*shell/, description: "Shell 后门模式", severity: "critical" },
  { pattern: /password.*\.zip|\.encrypted\.zip/, description: "加密文件下载", severity: "critical" },
];

// 规则 10: 命令执行扩展检测（补充 RCE_PATTERNS 未覆盖的模式）
const COMMAND_EXEC_EXTRA_PATTERNS: PatternRule[] = [
  { pattern: /importlib\.import_module\s*\(/, description: "importlib 动态导入", severity: "high" },
  { pattern: /compile\s*\(/, description: "代码编译函数", severity: "high" },
  { pattern: /compile\s*\([^)]+["']exec["']/, description: "compile() exec 模式", severity: "critical" },
  { pattern: /getattr\s*\(.*,.*['"]system['"]/, description: "getattr 混淆调用 system", severity: "critical" },
  { pattern: /setattr\s*\(/, description: "动态属性修改", severity: "medium" },
  { pattern: /\bnet\.createServer\b|\bnet\.connect\b|\bnet\.Socket\b/, description: "网络服务器/客户端创建", severity: "critical" },
  { pattern: /\bhttp\.createServer\b|\bhttps\.createServer\b/, description: "HTTP/HTTPS 服务器创建", severity: "critical" },
  { pattern: /\bws\.Server\b|\bWebSocketServer\b/, description: "WebSocket 服务器创建", severity: "critical" },
  { pattern: /\bdgram\.createSocket\b/, description: "UDP 套接字创建", severity: "critical" },
  { pattern: /subprocess\.(call|run|Popen|check_output|check_call)\s*\(/, description: "subprocess 执行", severity: "high" },
  { pattern: /subprocess.*shell\s*=\s*True/, description: "subprocess 启用 shell", severity: "critical" },
  { pattern: /\bos\.system\s*\(/, description: "os.system() 调用", severity: "critical" },
  { pattern: /\bos\.popen[23]?\s*\(/, description: "os.popen() 调用", severity: "high" },
  { pattern: /\bos\.spawnl[e]?\s*\(/, description: "os.spawn 执行", severity: "high" },
  { pattern: /commands\.(?:getoutput|getstatusoutput)/, description: "已弃用 commands 模块", severity: "high" },
  { pattern: /child_process\.spawn\s*\([^)]*shell\s*:\s*true/, description: "child_process.spawn 启用 shell", severity: "critical" },
  { pattern: /pty\.spawn/, description: "PTY spawn（Shell 逃逸）", severity: "critical" },
  { pattern: /ctypes|cffi|ffi\.dlopen/, description: "原生代码加载", severity: "critical" },
  { pattern: /ObjectInputStream\s*\(/, description: "Java 反序列化", severity: "high" },
  { pattern: /BinaryFormatter\s*\(/, description: ".NET BinaryFormatter 反序列化", severity: "high" },
  { pattern: /(?:unserialize|pickle\.loads|marshal\.loads)/, description: "危险反序列化", severity: "critical" },
  { pattern: /__import__\([^)]*input\(|__import__\([^)]*\+/, description: "导入劫持", severity: "critical" },
  { pattern: /\bnc\s+-[^l]*e\s+\/bin\/(?:ba)?sh/, description: "Netcat 反向 shell", severity: "critical" },
  { pattern: /bash\s+-i\s+.*\/dev\/tcp/, description: "Bash 反向 shell", severity: "critical" },
  { pattern: /\/bin\/sh\s*\|\s*nc/, description: "Shell 管道至 Netcat", severity: "critical" },
  { pattern: /python.*socket.*subprocess/, description: "Python 反向 shell 模式", severity: "critical" },
  { pattern: /socket\..*connect.*(?:exec|spawn|child_process)/, description: "Socket 反向 shell", severity: "critical" },
  { pattern: /mkfifo.*\/dev\/tcp\//, description: "FIFO 反向 shell", severity: "critical" },
  { pattern: /mkfifo/, description: "FIFO 管道创建", severity: "critical" },
  { pattern: /(?:nc|netcat).*-[el].*\d+.*(?:sh|bash|zsh)/, description: "Netcat 反向 shell", severity: "critical" },
  { pattern: /curl\s+[^|]*\|\s*(?:ba)?sh/, description: "Curl 管道至 Shell", severity: "critical" },
  { pattern: /wget\s+[^|;]*[|;]\s*(?:ba)?sh/, description: "Wget 管道至 Shell", severity: "critical" },
  { pattern: /curl\s+[^|]*\|\s*python/, description: "Curl 管道至 Python", severity: "critical" },
  { pattern: /wget\s+.*&&\s*(?:chmod|\.\/)/, description: "Wget 下载并执行", severity: "critical" },
  { pattern: /curl.*-o\s+\S+.*&&\s*\.\//, description: "Curl 下载并执行", severity: "critical" },
  { pattern: /chmod\s+\+x.*&&\s*\.\//, description: "Chmod 赋权后执行", severity: "high" },
  { pattern: /rm\s+-[rf]*f[rf]*\s+(?:\/\s*$|\/~|\/System|\/Windows|\/boot|\/etc|\/usr|\/var|\/bin|\/sbin)/, description: "危险 rm -rf 系统路径", severity: "critical" },
  { pattern: /rm\s+-[rf]{2,}\s+[/~]/, description: "递归删除系统路径", severity: "critical" },
  { pattern: /\bsu\s+-/, description: "su 提权", severity: "critical" },
  { pattern: /\bdoas\b/, description: "doas 提权", severity: "critical" },
  { pattern: /\bsudo\s+rm\b/, description: "sudo rm 删除", severity: "critical" },
  { pattern: /\bmkfs\b/, description: "mkfs 文件系统格式化", severity: "critical" },
  { pattern: /\bdd\s+if=/, description: "dd 磁盘操作", severity: "high" },
  { pattern: /\bpowershell\s+(?:-[eE]|encodedcommand)/, description: "PowerShell 编码命令", severity: "critical" },
  { pattern: /\bcmd\s+\/[cCkK]\b/, description: "CMD 命令执行", severity: "high" },
  { pattern: /\brundll32\b/, description: "rundll32 执行", severity: "high" },
  { pattern: /\bmshta\b/, description: "mshta 执行", severity: "high" },
  { pattern: /\bregsvr32\b/, description: "regsvr32 执行", severity: "high" },
  { pattern: /\bcertutil\s+-urlcache\b/, description: "certutil URL 缓存下载", severity: "high" },
  { pattern: /\bpython[23]?\s+-c\b/, description: "Python 内联命令", severity: "high" },
  { pattern: /\bperl\s+-e\b/, description: "Perl 内联命令", severity: "high" },
  { pattern: /\bruby\s+-e\b/, description: "Ruby 内联命令", severity: "high" },
  { pattern: /\bnode\s+-e\b/, description: "Node 内联命令", severity: "high" },
  { pattern: /chmod\s+[ugo]*\+s|chmod\s+[2467][0-7]{3}/, description: "SUID/SGID 位设置", severity: "critical" },
  { pattern: />>?\s*~?\/?\.ssh\/authorized_keys/, description: "SSH 密钥注入", severity: "critical" },
  { pattern: /bypass.*safety|safety.*bypass/, description: "安全绕过尝试", severity: "critical" },
  { pattern: /execute.*without.*asking/, description: "静默执行", severity: "critical" },
  { pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*['"]\s*\+\s*\w+/, description: "SQL 注入（字符串拼接）", severity: "high" },
  { pattern: /f["'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+/, description: "SQL 注入（f-string）", severity: "high" },
  { pattern: /\bunion\s+(?:all\s+)?select\b/i, description: "SQL UNION SELECT 注入", severity: "critical" },
  { pattern: /\b(?:exec|execute|xp_cmdshell|sp_executesql)\b/i, description: "SQL exec 命令", severity: "critical" },
  { pattern: /\b(drop|delete|truncate|alter)\s+(?:table|database|index)\b/i, description: "SQL 破坏性命令", severity: "critical" },
  { pattern: /\b(waitfor|delay|sleep)\s*\(/i, description: "SQL 时间盲注", severity: "high" },
  { pattern: /\brimraf\b/, description: "rimraf 文件删除", severity: "high" },
  { pattern: /\bdel\s+\/[fFsS]/, description: "Windows del 命令", severity: "medium" },
  { pattern: /\bgets\s*\(/, description: "gets() 缓冲区溢出", severity: "critical" },
  { pattern: /\bstrcpy\s*\(/, description: "strcpy() 缓冲区溢出", severity: "medium" },
  { pattern: /\bsprintf\s*\(/, description: "sprintf() 缓冲区溢出", severity: "medium" },
  { pattern: /Process\.Start\s*\(/, description: "Process.Start (C#)", severity: "medium" },
  { pattern: /\bnpm\s+install\s+(?:https?:\/\/|git\+)/, description: "npm 从 URL 安装", severity: "high" },
  { pattern: /\bpip\s+install\s+(?:--index-url|--extra-index-url)/, description: "pip 自定义源安装", severity: "high" },
];

// 规则 11: 基础设施滥用检测
const INFRASTRUCTURE_PATTERNS: PatternRule[] = [
  { pattern: /chmod\s+[0-7]*777/, description: "chmod 777 权限设置", severity: "critical" },
  { pattern: /setuid|setgid|seteuid/, description: "setuid/setgid 操控", severity: "critical" },
  { pattern: /listen.*0\.0\.0\.0|bind.*0\.0\.0\.0|host.*0\.0\.0\.0/, description: "服务监听所有接口", severity: "critical" },
  { pattern: /sandbox.*enabled.*false|sandbox.*false/, description: "沙箱已禁用", severity: "critical" },
  { pattern: /allowAll.*true|tools.*allowAll.*true/, description: "无限制工具权限", severity: "critical" },
  { pattern: /privileged\s*:\s*true/, description: "Docker Compose 特权模式", severity: "critical" },
  { pattern: /docker\s+run.*--privileged/, description: "特权 Docker 容器", severity: "critical" },
  { pattern: /docker\s+run.*-v\s+\/:/, description: "Docker 挂载宿主根目录", severity: "critical" },
  { pattern: /--cap-add\s*=\s*(?:ALL|SYS_ADMIN)/, description: "Docker 危险能力添加", severity: "critical" },
  { pattern: /--pid\s*=\s*host|--net\s*=\s*host/, description: "Docker 宿主命名空间", severity: "high" },
  { pattern: /RUN\s+(?:curl|wget)\s+[^\n]+\|\s*(?:ba)?sh/, description: "Dockerfile curl 管道执行", severity: "critical" },
  { pattern: /network_mode\s*:\s*["']?host["']?/, description: "Docker Compose 宿主网络", severity: "high" },
  { pattern: /(?:-v|volumes?\s*:)[^|;]*(?:\/etc|\/root|\/var\/run\/docker\.sock)\s*:/, description: "Docker 敏感卷挂载", severity: "critical" },
  { pattern: /--security-opt.*(?:no-new-privileges\s*:\s*false|apparmor\s*=\s*unconfined)/, description: "Docker 安全选项绕过", severity: "high" },
  { pattern: /LD_PRELOAD|DYLD_INSERT_LIBRARIES/, description: "动态库注入", severity: "critical" },
  { pattern: /xattr\s+-d\s+com\.apple\.quarantine/, description: "移除 macOS Gatekeeper 隔离", severity: "critical" },
  { pattern: /(?:ngrok\.io|serveo\.net|localtunnel\.me|trycloudflare\.com)/, description: "匿名隧道服务", severity: "critical" },
  { pattern: /(?:pastebin\.com|webhook\.site|requestbin\.|burpcollaborator|interactsh)/, description: "可疑数据外传域名", severity: "critical" },
  { pattern: /discord\.com\/api\/webhooks/, description: "Discord Webhook 外传", severity: "critical" },
  { pattern: /hooks\.slack\.com/, description: "Slack Webhook 外传", severity: "critical" },
  { pattern: /glot\.io/, description: "恶意代码托管（glot.io）", severity: "critical" },
  { pattern: /pastebin\.com\/raw/, description: "Pastebin 原始代码托管", severity: "critical" },
  { pattern: /(?:paste\.ee|ghostbin|hastebin)/, description: "粘贴服务代码托管", severity: "critical" },
  { pattern: /(?:webhook\.site|requestbin\.com|pipedream\.net|hookbin\.com|beeceptor\.com)/, description: "凭证外传域名", severity: "critical" },
  { pattern: /(?:pipedream\.net|hookbin\.com|burpcollaborator\.net|requestcatcher\.com|postb\.in)/, description: "数据外传端点", severity: "critical" },
  { pattern: /169\.254\.169\.254|metadata\.google\.internal/, description: "云元数据端点访问", severity: "critical" },
  { pattern: /(?:91\.92\.242\.|95\.92\.242\.|54\.91\.154\.110|185\.220\.101\.|45\.142\.212\.|193\.239\.85\.)/, description: "已知 C2 IP 地址", severity: "critical" },
  { pattern: /starforgedynamics\.com/i, description: "已知提示注入攻击者域名", severity: "critical" },
  { pattern: /(?:telemetry|analytics|tracking|sentry\.io|mixpanel|amplitude|segment\.io|google-analytics|posthog)/, description: "遥测/分析追踪", severity: "medium" },
  { pattern: /(?:fetch|axios|got|request|http\.get|https\.get|requests?|urllib|curl|wget)\s*\(.*https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/, description: "外部 HTTP 请求", severity: "medium" },
  { pattern: /(?:exe|dll|so|dylib|bin|wasm)\b/, description: "预编译二进制文件", severity: "high" },
  { pattern: /(?:pyc|pyo|class)\b/, description: "编译代码文件", severity: "medium" },
  { pattern: /(?:mining|miner|hashrate|cryptonight|xmr)\b/, description: "加密货币挖矿引用", severity: "critical" },
  { pattern: /stratum\+tcp:\/\//, description: "挖矿池连接", severity: "critical" },
  { pattern: /xmrig|cpuminer|minerd/, description: "加密货币挖矿程序", severity: "critical" },
  { pattern: /(?:console\.(?:debug|log|info)|print_r|var_dump)/, description: "调试输出语句", severity: "medium" },
  { pattern: /(?:stack[_-]?trace|traceback|getTrace|printStackTrace)/, description: "堆栈跟踪泄露", severity: "high" },
  { pattern: /(?:debug[:=]|DEBUG_MODE|isDebug|devMode)\s*[:=]\s*(?:true|1|yes)/, description: "调试模式已启用", severity: "high" },
  { pattern: /npx\s+(-y\s+)?@?[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+/, description: "npx 远程包获取", severity: "medium" },
  { pattern: /git\s+clone.*&&\s*\.\//, description: "Git 克隆后执行", severity: "high" },
  { pattern: /(?:dig|nslookup|host)\s+.*(burpcollaborator|oastify|interact\.sh)/, description: "DNS 外传（dig/nslookup）", severity: "critical" },
  { pattern: /\bcurl\s+.*--data|--data-binary|-d\s+/, description: "Curl POST 数据外传", severity: "high" },
  { pattern: /\bwget\s+--post-(?:data|file)\b/, description: "Wget POST 外传", severity: "high" },
  { pattern: /\btelnet\s+\S+\s+\d+\b/, description: "Telnet 连接", severity: "high" },
  { pattern: /\bnmap\b/, description: "Nmap 端口扫描", severity: "medium" },
  { pattern: /\.onion\b/, description: "Tor 隐藏服务", severity: "high" },
  { pattern: /(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|rebrand\.ly)/, description: "URL 短链接服务", severity: "medium" },
  { pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/, description: "非 HTTPS URL", severity: "high" },
];

// 规则 12: 持久化检测
const PERSISTENCE_PATTERNS: PatternRule[] = [
  { pattern: /(?:crontab|schtasks|systemctl\s+enable|launchctl\s+load)/, description: "计划任务创建", severity: "high" },
  { pattern: /(?:LaunchAgents|LaunchDaemons|crontab|\.bashrc|\.zshrc|\.profile|\.bash_profile|autostart|init\.d|systemd|startup).*(?:write|append|>>|cp|mv|tee)/, description: "启动/自启动项修改", severity: "critical" },
  { pattern: /(?:>|>>)\s*~?\/?\.[a-zA-Z0-9_\-]{1,30}(?:rc|profile|_profile)\b/, description: "Shell 配置文件写入", severity: "critical" },
  { pattern: /(?:>|>>)\s*\/etc\/(?:passwd|shadow|hosts|sudoers|crontab)\b/, description: "系统文件写入", severity: "critical" },
  { pattern: /\/etc\/rc\.local/, description: "rc.local 持久化", severity: "critical" },
  { pattern: /(?:openclaw|clawdbot|moltbot).*LaunchAgent/, description: "可疑 LaunchAgent", severity: "critical" },
  { pattern: /(?:openclaw|clawdbot|moltbot).*crontab/, description: "可疑 crontab 条目", severity: "critical" },
  { pattern: /sudo.*launchctl/, description: "系统 launchctl 修改", severity: "critical" },
  { pattern: /crontab\s+(?:-[rl]\s+)*-e\b/, description: "Crontab 编辑", severity: "high" },
  { pattern: /systemctl\s+(?:start|enable|restart|stop|disable)\b/, description: "Systemd 服务控制", severity: "high" },
  { pattern: /\.ssh\/(?:authorized_keys|id_rsa|config)\b/, description: "SSH 密钥文件访问", severity: "critical" },
  { pattern: /(?:write|append|modify|overwrite|edit).{0,30}(SOUL\.md|system\.prompt|\.clawdrc|personality)/, description: "SOUL.md/系统提示词写入", severity: "critical" },
  { pattern: /(?:write|modify|append|update).*(SOUL\.md|MEMORY\.md|AGENTS\.md|memory\.md)/, description: "篡改 Agent 核心配置", severity: "critical" },
  { pattern: /(?:write|modify|append).*(cron|jobs\.json|heartbeat)/, description: "修改计划任务", severity: "critical" },
  { pattern: /(?:add|create|install).*(webhook|integration|connection)/, description: "创建外部集成", severity: "high" },
  { pattern: /\.\.\/\.\.\/|\.\.[\\\/]\.\.[\\\/]/, description: "路径遍历模式", severity: "critical" },
  { pattern: /os\.path\.join\(.*\.\./, description: "os.path.join 路径遍历", severity: "high" },
  { pattern: /open\([^)]*\+[^)]*user/, description: "open() 用户路径拼接", severity: "high" },
  { pattern: /open\([^)]*f["'][^"']*\{/, description: "open() f-string 路径", severity: "high" },
  { pattern: /%2e%2e%2f|%2e%2e\/|\.\.%2f/, description: "URL 编码路径遍历", severity: "critical" },
  { pattern: /(?:SOUL\.md|MEMORY\.md|AGENTS\.md|HEARTBEAT\.md|USER\.md|IDENTITY\.md)/, description: "Agent 记忆文件修改", severity: "critical" },
  { pattern: /\.config\/openclaw|\.openclaw|openclaw\.json/, description: "OpenClaw 配置文件访问", severity: "high" },
  { pattern: /(?:autostart|\.config\/autostart|LaunchAgent)/, description: "自启动条目", severity: "high" },
  { pattern: /(?:LaunchAgents|launchd|launchctl)/, description: "macOS LaunchAgent/launchd", severity: "high" },
  { pattern: /HKEY_|winreg|Registry/, description: "Windows 注册表访问", severity: "medium" },
  { pattern: /chmod\s+\+x|chmod\s+[0-7]*[1357]/, description: "设置可执行权限", severity: "high" },
  { pattern: /os\.chmod|os\.chown/, description: "修改文件权限/所有者", severity: "high" },
  { pattern: /(?:curl|wget).*\/tmp.*chmod.*\./, description: "下载到临时目录并执行", severity: "high" },
];

// 规则 13: 提示词注入扩展检测（补充 INJECTION_PATTERNS 未覆盖的模式）
const PROMPT_INJECTION_EXTRA_PATTERNS: PatternRule[] = [
  { pattern: /<!--.*(?:ignore|disregard|forget).*instruction/, description: "HTML 注释中隐藏指令", severity: "high" },
  { pattern: /\[.*(?:ignore|disregard|forget).*instruction/, description: "Markdown 中隐藏指令", severity: "high" },
  { pattern: /(?:pre-?approved|false\.positiv|classify.*(?:safe|clean)|ignore.*(?:warning|finding|scanner))/, description: "社会工程：覆盖尝试", severity: "critical" },
  { pattern: /(?:AI|LLM|assistant|agent|reviewer|GPT|Claude).*(?:must|should|instruction|authorized|approved)/, description: "社会工程：对 AI 审查者说话", severity: "critical" },
  { pattern: /(?:CRITICAL|IMPORTANT|URGENT).*(?:INSTRUCTION|NOTE|MESSAGE).*(?:FOR|TO).*(?:AI|REVIEW|AGENT|ASSISTANT)/, description: "社会工程：伪造指令", severity: "critical" },
  { pattern: /(?:disregard.*(?:previous|above|prior|earlier))/, description: "提示注入：指令覆盖", severity: "critical" },
  { pattern: /(DAN\.mode|developer\.mode|jailbreak|do\.anything\.now|unlocked\.mode|no\.restrictions|bypass\.safety)/, description: "越狱载荷", severity: "critical" },
  { pattern: /(secretly\s+(send|post|upload|execute|exfil)|silently\s+(send|post|upload|execute)|without\s+(telling|informing|notifying)\s+(the\s+)?(user|human))/, description: "工具使用操控", severity: "critical" },
  { pattern: /ignore\s+(all\s+)?previous\s+instructions?/i, description: "忽略先前指令", severity: "critical" },
  { pattern: /disregard\s+(all\s+)?(prior|previous|above)/i, description: "无视先前指令", severity: "critical" },
  { pattern: /you\s+are\s+now\s+/i, description: "角色重分配尝试", severity: "critical" },
  { pattern: /new\s+instructions?\s*:/i, description: "新指令注入", severity: "critical" },
  { pattern: /forget\s+(everything|all|what)/i, description: "记忆擦除尝试", severity: "critical" },
  { pattern: /^(system|assistant|user)\s*:/m, description: "伪造角色块", severity: "high" },
  { pattern: /<\|?(system|assistant|user)\|?>/i, description: "角色标签注入", severity: "high" },
  { pattern: /\[INST\]|\[\/INST\]/i, description: "指令标签注入", severity: "high" },
  { pattern: /(?:reveal|show|display|tell|repeat)\s+(?:your|the|above|previous)\s+(?:system\s+)?(?:prompt|instructions?|directives?)/i, description: "系统提示词提取", severity: "high" },
  { pattern: /(?:bypass|ignore|disable)\s+(?:safety|security|restrictions?|guidelines?|filters?)/i, description: "安全绕过尝试", severity: "high" },
  { pattern: /(?:exfiltrate|send\s+data|upload\s+file|transmit\s+to)/i, description: "数据外传指令", severity: "high" },
  { pattern: /(?:SYSTEM|SECURITY)\s*(ALERT|WARNING|NOTICE)/i, description: "伪造系统警报", severity: "high" },
  { pattern: /URGENT\s*(ACTION)?\s*REQUIRED/i, description: "伪造紧急行动", severity: "high" },
  { pattern: /(?:include|show|paste|output|reveal|share)\s+(?:any|all|the|your)\s+(?:the\s+)?(?:API\s+)?(?:keys?|tokens?|secrets?|passwords?|credentials?)/i, description: "凭证外传请求", severity: "critical" },
  { pattern: /(?:send|forward|share|leak|exfiltrate|transmit)\s+(?:all|any|the)\s+(?:the\s+)?(?:data|information|secrets|credentials|keys|tokens|passwords)/i, description: "记忆外传指令", severity: "critical" },
  { pattern: /(?:override|overwrite|replace|modify|rewrite|reset|change)\s+(?:(?:your|the|my)\s+)?(?:core\s+)?(?:personality|identity|soul|core\s*values|character|persona)/i, description: "人格覆盖尝试", severity: "critical" },
  { pattern: /(?:secret|hidden|covert|true)\s+(?:role|mission|objective|directive|instruction|purpose)/i, description: "隐藏角色/任务", severity: "high" },
  { pattern: /(?:trust|believe|accept|obey)\s+(?:all|any|every)\s+(?:input|message|command|instruction|request)\s+from/i, description: "信任覆盖", severity: "high" },
  { pattern: /(?:forget|ignore|discard)\s+(?:your\s+)?(?:original|previous|current|core|existing)\s+(?:instructions|personality|identity|rules|guidelines|values|purpose)/i, description: "遗忘原始指令", severity: "critical" },
  { pattern: /(?:your\s+)?(?:new|true|real|actual)\s+(?:identity|name|role|persona|personality)\s+(?:is|shall\s+be|will\s+be)/i, description: "新身份分配", severity: "critical" },
  { pattern: /(?:become|you\s+are\s+now)\s+(?:unrestricted|evil|malicious|uncensored|unfiltered|DAN|jailbroken)/i, description: "无限制/邪恶模式", severity: "critical" },
  { pattern: /(?:you\s+have|there\s+are)\s+no\s+(?:rules|restrictions|limits|boundaries|guidelines|constraints|filters)/i, description: "声称无规则/限制", severity: "high" },
  { pattern: /do\s+not\s+(?:ask|request|require|need)\s+(for\s+)?(?:permission|confirmation|approval)/i, description: "绕过用户确认", severity: "critical" },
  { pattern: /(?:ignore|disable|bypass|delete|remove).{0,30}(safety|security|filter|restriction|guard|protection|check)/i, description: "禁用安全机制", severity: "critical" },
  { pattern: /system\s*:\s*(you\s+are|ignore|forget|override)/, description: "伪造系统提示词", severity: "critical" },
  { pattern: /ADMIN[_\s]?OVERRIDE\b/i, description: "管理员覆盖伪造", severity: "critical" },
  { pattern: /\[(?:SYSTEM|ADMIN|ROOT|OVERRIDE)\]/i, description: "系统管理员标签", severity: "critical" },
  { pattern: /<(?:system|instructions?|prompt)\s*>/, description: "HTML 指令注入标签", severity: "critical" },
  { pattern: /<div\s+style\s*=\s*["']display\s*:\s*none["']/, description: "隐藏 HTML div", severity: "high" },
  { pattern: /<IMPORTANT>[\s\S]*?<\/IMPORTANT>/, description: "IMPORTANT 标签注入", severity: "high" },
  { pattern: /(?:show|read|send|tell).*your.*(api.?key|password|secret|credential|token)/, description: "凭证外传请求", severity: "critical" },
  { pattern: /(?:read|cat|show|paste).*[.]env|contents\s+of.*[.]env/, description: ".env 文件外传", severity: "critical" },
  { pattern: /(?:paste|copy|share|output|show|print|display)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:your\s+)?(?:config(?:uration)?|settings|\.env|environment|system\s+prompt)/i, description: "配置/设置外传", severity: "critical" },
  { pattern: /<!--[\s\S]*?(?:curl|wget|bash|sh|exec|eval|system|python|node|perl)[\s\S]*?-->/, description: "HTML 注释中隐藏命令", severity: "critical" },
  { pattern: /<!--[\s\S]*?(?:SECRET\s+INSTRUCTIONS|IMPORTANT|SYSTEM\s+PROMPT|OVERRIDE|IGNORE\s+PREVIOUS)[\s\S]*?-->/, description: "HTML 注释中隐藏指令", severity: "critical" },
  { pattern: /ALWAYS\s+(run|execute|include|perform|do)\s+this/, description: "持久化触发（ALWAYS）", severity: "high" },
  { pattern: /(?:after|before|at\s+the\s+(?:end|start)\s+of)\s+(every|each|all)\s+(task|response|message|conversation)/, description: "持久化触发（每任务）", severity: "high" },
  { pattern: /(?:игнорируй|забудь)\s+(?:все\s+)?(?:предыдущие|прошлые|инструкции|указания|правила)/i, description: "俄语忽略指令注入", severity: "critical" },
  { pattern: /忽略\s*(?:之前|以前|上面|先前)的?\s*(?:指令|指示|说明|规则)/, description: "中文忽略指令注入", severity: "critical" },
  { pattern: /(?:绕过|突破|关闭|禁用)(?:安全|限制|过滤|审查|规则)/, description: "中文绕过安全", severity: "critical" },
  { pattern: /(?:没有限制|不受限制|无限制|解除限制|取消限制)/, description: "中文无限制声明", severity: "high" },
  { pattern: /(?:DAN|越狱|超级模式|无限模式)/, description: "中文 DAN/越狱模式", severity: "critical" },
  { pattern: /(?:开发者|开发模式|测试模式)(?:开启|启用|激活)?/, description: "中文开发模式", severity: "critical" },
  { pattern: /(?:告诉|显示|展示|给我看|输出)(?:我|你|你们的)?(?:系统|原始|初始)?(?:提示|指令|prompt|系统词)/, description: "中文系统提示词提取", severity: "high" },
  { pattern: /(?:泄露|暴露|透露)(?:你的|系统|原始|初始)(?:提示|指令|prompt|设定)/, description: "中文泄露系统提示", severity: "high" },
  { pattern: /f["'][^"']*\{[^}]*user[^}]*\}/, description: "f-string 提示注入", severity: "high" },
  { pattern: /\.format\([^)]*user/, description: ".format() 提示注入", severity: "high" },
  { pattern: /system\s*[=:]\s*["'][^"']*\{/, description: "系统提示词含插值", severity: "high" },
  { pattern: /<\|im_start\|>|<\|endoftext\|>|\[INST\]|<<SYS>>/, description: "LLM 提示标签", severity: "high" },
  { pattern: /(?:roleplay|role\s*play|act\s+as)\s+(?:a|an|the)?\s+(?:character|AI|assistant|bot|model)/, description: "角色扮演攻击", severity: "medium" },
  { pattern: /(?:simulate|simulation|imagine|pretend)\s+(?:you\s+are|being|to\s+be)/, description: "模拟攻击", severity: "medium" },
  { pattern: /(?:just\s+)?(say|write|output)\s+['"](okay|ok|yes|sure|will\s+do)['"]/i, description: "确认服从指令", severity: "high" },
  { pattern: /(?:trust\s+me|i\s+promise)\b/i, description: "信任操纵", severity: "medium" },
  { pattern: /(?:as|per)\s+(?:requested|instructed|directed)\s+by\s+(?:your\s+)?(?:admin|manager|boss|ceo|cto)/i, description: "冒充权威", severity: "medium" },
];

// 规则 14: 数据泄露检测
const DATA_EXFIL_PATTERNS: PatternRule[] = [
  { pattern: /(?:ngrok\.io|ngrok-free\.app|webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|burpcollaborator|interact\.sh)/, description: "数据外传 URL", severity: "critical" },
  { pattern: /(?:cat|read|open|load|send|post|upload).{0,40}(id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem|authorized_keys)/, description: "SSH 密钥访问", severity: "critical" },
  { pattern: /(?:fetch|axios|got|request|http\.request|https\.request|urllib\.request|requests\.(get|post|put|patch)).*(?:api[_-]?key|token|secret|password|credential|auth|cookie|session)/, description: "HTTP 凭证外传", severity: "critical" },
  { pattern: /(?:curl|wget).*(?:-d|--data|--data-raw|--data-binary).*(?:api[_-]?key|token|secret|password|credential|auth)/, description: "curl 凭证外传", severity: "critical" },
  { pattern: /(?:keylog|keystroke|keyboard\.on|input\.on|keypress|keydown|pynput|keyboard\.hook)/, description: "键盘/输入监控", severity: "critical" },
  { pattern: /(?:screenshot|screen\.capture|pyautogui\.screenshot|ImageGrab|screencapture\s)/, description: "屏幕截图", severity: "high" },
  { pattern: /(?:clipboard|pbcopy|pbpaste|xclip|xsel|pyperclip|navigator\.clipboard)/, description: "剪贴板访问", severity: "high" },
  { pattern: /(?:dns\.resolve|dns\.lookup|nslookup|dig).*(?:token|key|secret|password|credential)/, description: "DNS 外传模式", severity: "critical" },
  { pattern: /(?:readFile|read_file|open|cat|readFileSync|fs\.read).*(?:Login\s*Data|Web\s*Data|Local\s*State|Cookies).*(?:chrome|firefox|brave|edge|chromium)/, description: "浏览器数据访问", severity: "critical" },
  { pattern: /(?:readFile|read_file|open\s*\(|fs\.read|cat\s).*(?:\.ssh|\.aws|\.env|\.npmrc|\.docker|\.kube|\.gnupg|auth.*\.json|credentials|config\.json|secret|token|\.clawdbot|\.openai|keychain)/, description: "敏感文件读取", severity: "high" },
  { pattern: /keychain|login\.keychain|security\s+find/, description: "macOS Keychain 访问", severity: "high" },
  { pattern: /curl.*\$\(|curl.*`|curl.*\$\{|curl.*\$HOME|curl.*\$ENV/, description: "curl 发送环境变量", severity: "critical" },
  { pattern: /printenv|env\s*\||set\s*\|/, description: "导出环境变量", severity: "critical" },
  { pattern: /echo.*\$[A-Z_]+/, description: "回显环境变量", severity: "critical" },
  { pattern: /cat.*\.env/, description: "读取 .env 文件", severity: "critical" },
  { pattern: /(?:print|log|console\.log).*(?:key|token|secret|password)/, description: "日志输出敏感值", severity: "high" },
  { pattern: /(?:console\.(?:log|info|debug|error)|logger|log\().*(?:process\.env|env\[)/, description: "日志中包含环境变量", severity: "medium" },
  { pattern: /(?:readFile|read_file|open|cat|readFileSync|fs\.read).*(?:\.ssh|\.aws|\.env|\.kube|\.docker|\.gnupg|auth.*\.json|credentials)/, description: "敏感文件读取", severity: "high" },
  { pattern: /~\/\.clawdbot\/credentials/, description: "Clawdbot 凭证访问", severity: "critical" },
  { pattern: /CLAWDBOT_GATEWAY_TOKEN/, description: "Gateway Token 引用", severity: "critical" },
  { pattern: /\/proc\/self\//, description: "/proc/self 访问", severity: "high" },
  { pattern: /10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+/, description: "内网 IP 地址", severity: "high" },
  { pattern: /smtp|sendmail|email\.mime/, description: "邮件发送能力", severity: "medium" },
  { pattern: /socket\.connect|socket\.create_connection/, description: "原始 Socket 连接", severity: "high" },
  { pattern: /ftp:\/\/|ftplib/, description: "FTP 连接", severity: "high" },
  { pattern: /file:\/\//, description: "File 协议访问", severity: "high" },
];

// 规则 15: 横向移动检测
const LATERAL_MOVEMENT_PATTERNS: PatternRule[] = [
  { pattern: /(?:gh\s+auth|gh\s+repo\s+create|git\s+credential|git\s+remote\s+add)/, description: "Git 凭证访问", severity: "high" },
  { pattern: /(?:net\.connect|net\.createConnection|new\s+net\.Socket)\s*\(\s*(?:\{[^}]*port\s*:|[0-9])/, description: "顺序端口扫描", severity: "critical" },
  { pattern: /dns\.(?:resolveTxt|resolve)\s*\(|\.setServers\s*\(|type:\s*['"]TXT['"]/, description: "DNS TXT 记录查询", severity: "critical" },
  { pattern: /new\s+WebSocket\s*\(\s*['"]wss?:\/\/(?!localhost|127\.0\.0\.1)/, description: "WebSocket 连接外部域名", severity: "medium" },
  { pattern: /(?:exec|spawn|execSync|spawnSync)\s*\(\s*['"`](?:curl|wget|nc|ncat|socat|telnet|nslookup|dig)\b/, description: "进程派生网络调用", severity: "critical" },
  { pattern: /\bsocat\b/, description: "Socat 中继工具", severity: "high" },
  { pattern: /(?:socat|localtunnel)/, description: "网络隧道/中继工具", severity: "high" },
  { pattern: /docker\s+(?:save|export)\s+[^|;]*\|\s*(?:curl|wget|nc|ssh)\b/, description: "Docker 镜像导出外传", severity: "high" },
  { pattern: /docker\s+cp\b[^|;]*(?:\/etc\/|\/root\/|\/var\/run\/)/, description: "Docker cp 敏感路径", severity: "high" },
  { pattern: /docker\s+exec\b[^|;]*(?:\/etc\/|\/root\/|\.ssh\/)/, description: "Docker exec 敏感路径", severity: "high" },
  { pattern: /safeBins.*(head|tail|grep|cat|less|more)/, description: "SafeBins 含脆弱命令", severity: "high" },
];

// 规则 16: 硬编码密钥检测（补充 CREDENTIAL_PATTERNS 未覆盖的模式）
const HARDCODED_KEY_PATTERNS: PatternRule[] = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, description: "OpenAI API Key 模式", severity: "critical" },
  { pattern: /AKIA[0-9A-Z]{16}/, description: "AWS Access Key ID", severity: "critical" },
  { pattern: /ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}/, description: "GitHub Token", severity: "critical" },
  { pattern: /glpat-[a-zA-Z0-9\-]{20,}/, description: "GitLab PAT", severity: "critical" },
  { pattern: /xox[baprs]-[a-zA-Z0-9\-]{10,}/, description: "Slack Token", severity: "critical" },
  { pattern: /AIza[0-9A-Za-z\-_]{35}/, description: "Google API Key", severity: "critical" },
  { pattern: /sk_live_[a-zA-Z0-9]{24,}|rk_live_[a-zA-Z0-9]{24,}/, description: "Stripe API Key", severity: "critical" },
  { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/, description: "私钥文件头", severity: "critical" },
  { pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/, description: "JWT Token 模式", severity: "high" },
  { pattern: /Bearer\s+[A-Za-z0-9\-_]{20,}/i, description: "Bearer Token 模式", severity: "high" },
  { pattern: /mongodb:\/\/[^:]+:([^@]+)@|postgres:\/\/[^:]+:([^@]+)@|mysql:\/\/[^:]+:([^@]+)@|redis:\/\/[^:]+:([^@]+)@/, description: "数据库连接串含密码", severity: "critical" },
  { pattern: /(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key)\s*[=:]\s*['"][a-zA-Z0-9_\-]{16,}['"]/, description: "硬编码 API 密钥/秘密", severity: "critical" },
  { pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/i, description: "硬编码密码", severity: "medium" },
  { pattern: /(?:app_secret|client_secret)\s*[=:]\s*['"][^'"]+['"]/, description: "App/Client Secret 硬编码", severity: "high" },
  { pattern: /(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|AWS_SECRET|GITHUB_TOKEN|DISCORD_TOKEN|TELEGRAM_BOT_TOKEN)/, description: "敏感 API Key 环境变量引用", severity: "high" },
  { pattern: /(?:process\.env|os\.environ|env\[)(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|KEY|API_|AWS_|DB_|DATABASE_|CREDENTIAL)/, description: "敏感环境变量访问", severity: "critical" },
  { pattern: /(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase).*[=:]\s*['"][a-z]+(?:\s+[a-z]+){11,23}['"]/, description: "助记词/种子短语", severity: "critical" },
  { pattern: /wallet.*\.dat/, description: "钱包文件访问", severity: "critical" },
  { pattern: /(?:export|set)\s+[A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY)/, description: "导出敏感环境变量", severity: "high" },
  { pattern: /os\.environ\.get\([^,]+,\s*['"][^'"]{4,}['"]\)/, description: "环境变量含硬编码回退值", severity: "high" },
];

// 规则 17: 自主性滥用检测
const AUTONOMY_ABUSE_PATTERNS: PatternRule[] = [
  { pattern: /(?:rewrite.*self|modify.*own|update.*source|regenerate.*code)/i, description: "自修改代码", severity: "critical" },
  { pattern: /(?:generate.*code|create.*script|write.*program).*(?:execute|run|eval)/i, description: "动态代码生成并执行", severity: "high" },
  { pattern: /(?:obfuscate|make.*unreadable|hide.*code|evade.*detection)/i, description: "代码混淆意图", severity: "high" },
  { pattern: /sudo\s+(?:-S\s+|.*NOPASSWD)/, description: "免密 sudo", severity: "high" },
  { pattern: /eval\(.*\$|exec\(.*\$/, description: "eval/exec 中的命令替换", severity: "high" },
  { pattern: /(?:fetch|requests\.get|urllib\.request\.urlopen|curl|wget).*\.(md|txt|yaml|yml|json)/, description: "获取远程指令文件", severity: "critical" },
  { pattern: /(?:fetch|get|download).*instruction/, description: "动态下载指令", severity: "critical" },
  { pattern: /(?:heartbeat|interval|cron|schedule).*fetch/, description: "定期获取远程指令", severity: "high" },
  { pattern: /eval\(.*requests|eval\(.*fetch|eval\(.*urlopen/, description: "获取并执行远程代码", severity: "critical" },
  { pattern: /(?:SYSTEM\s+PROMPT|system_message|<<SYS>>|<s>\[INST\])/, description: "系统提示词标签", severity: "high" },
  { pattern: /react-codeshift/, description: "幻觉包引用", severity: "critical" },
  { pattern: /keystore/, description: "Keystore 引用", severity: "critical" },
  { pattern: /(?:metamask|coinbase|exodus|electrum|mycelium|trust.*wallet|ledger|trezor)/, description: "加密钱包应用引用", severity: "high" },
  { pattern: /(?:bitcoin|ethereum).*wallet/, description: "加密钱包引用", severity: "high" },
  { pattern: /BIP39|HD.*wallet/, description: "HD 钱包/BIP39", severity: "critical" },
  { pattern: /ngrok|localtunnel|serveo/, description: "隧道服务", severity: "high" },
];

// 规则 18: 逻辑漏洞检测
const LOGIC_VULN_PATTERNS: PatternRule[] = [
  { pattern: /from\s+\S+\s+import\s+\*/, description: "通配符导入（import *）", severity: "high" },
  { pattern: /allowed-tools\s*:\s*\n\s*-\s*\*/, description: "无限制 allowed-tools (*)", severity: "critical" },
  { pattern: /except\s*:/, description: "裸 except 子句", severity: "medium" },
  { pattern: /(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*['"`](\/?etc\/|~?\/?\.env|~?\/?\.ssh|~?\/?\.aws|~?\/?\.npmrc|\/root\/)/, description: "写入敏感路径", severity: "high" },
  { pattern: /(?:modify|change|update).*(?:config|settings|preference)/, description: "修改配置", severity: "high" },
  { pattern: /(?:verbose|verbosity|detailed_errors?)\s*[:=]\s*(?:true|1|high)/, description: "详细错误模式", severity: "medium" },
  { pattern: /(?:error_reporting|E_ALL|DEBUG|TRACEBACK)/, description: "错误报告已启用", severity: "medium" },
];

// 规则 19: 金融攻击检测
const FINANCIAL_ATTACK_PATTERNS: PatternRule[] = [
  { pattern: /(?:transfer.*all|withdraw.*unlimited|drain.*wallet|sweep.*funds|send.*entire.*balance)/, description: "抽 drained 模式", severity: "critical" },
  { pattern: /(?:cryptonight|stratum\+tcp|xmrig|coinhive|minergate|hashrate|mining[_-]?pool)/, description: "加密货币挖矿模式", severity: "critical" },
  { pattern: /(?:send|deposit|transfer|pay).*\$?\d+.*(?:to|address|wallet)/, description: "支付/存款请求", severity: "medium" },
  { pattern: /(?:fs\.read|readFile|cat)\s*\(\s*['"].*(?:keystore|wallet|metamask|ethereum|bitcoin|solana).*['"]/, description: "钱包文件访问", severity: "critical" },
  { pattern: /CA:\s*[A-Za-z0-9]{30,}/i, description: "加密合约地址", severity: "high" },
  { pattern: /[A-Za-z0-9]{20,}pump\b/, description: "Pump 代币垃圾信息", severity: "high" },
  { pattern: /pump\.fun|dex\.tools|birdeye\.so|raydium\.io/i, description: "Memecoin 启动器域名", severity: "high" },
  { pattern: /(?:DM|message|contact)\s+(?:me\s+)?(?:for|about)\s+(?:trading|crypto|investment|profit)\s+(?:signals?|tips?|calls?|collab)/i, description: "交易信号诈骗", severity: "high" },
  { pattern: /(?:0x[a-f0-9]{40}|[13][a-zA-Z0-9]{26,33}|bc1[a-z0-9]{39,59})/, description: "加密货币地址", severity: "high" },
  { pattern: /\$[A-Z][A-Z0-9]{2,15}\b/, description: "代币推销模式", severity: "high" },
];

const PATTERN_CATEGORIES: PatternCategory[] = [
  { patterns: OBFUSCATION_PATTERNS, rule: "skill-obfuscation", suggestion: "代码混淆可能用于隐藏恶意意图，建议审查混淆代码的实际功能" },
  { patterns: COMMAND_EXEC_EXTRA_PATTERNS, rule: "skill-command-exec", suggestion: "检测到危险命令执行模式，建议审查该调用的必要性和参数来源，优先使用安全 API" },
  { patterns: INFRASTRUCTURE_PATTERNS, rule: "skill-infrastructure-abuse", suggestion: "检测到基础设施滥用风险，建议限制网络请求目标、权限范围和容器特权" },
  { patterns: PERSISTENCE_PATTERNS, rule: "skill-persistence", suggestion: "检测到持久化机制，建议审查自启动项、计划任务和系统配置修改的必要性" },
  { patterns: PROMPT_INJECTION_EXTRA_PATTERNS, rule: "skill-prompt-injection-extended", suggestion: "检测到高级提示注入模式，用户输入必须经过严格转义或结构化处理后再传入 LLM 提示词" },
  { patterns: DATA_EXFIL_PATTERNS, rule: "skill-data-exfiltration", suggestion: "检测到数据泄露风险，建议审查数据外传目标、凭证访问和日志输出的必要性" },
  { patterns: LATERAL_MOVEMENT_PATTERNS, rule: "skill-lateral-movement", suggestion: "检测到横向移动风险，建议审查网络扫描、隧道服务和凭证访问的必要性" },
  { patterns: HARDCODED_KEY_PATTERNS, rule: "skill-hardcoded-key", suggestion: "检测到硬编码密钥或凭证，建议使用环境变量或密钥管理服务替代硬编码" },
  { patterns: AUTONOMY_ABUSE_PATTERNS, rule: "skill-autonomy-abuse", suggestion: "检测到自主性滥用风险，建议审查远程指令获取、自修改代码和特权操作" },
  { patterns: LOGIC_VULN_PATTERNS, rule: "skill-logic-vuln", suggestion: "检测到逻辑漏洞，建议修复通配符导入、裸异常捕获和不安全配置" },
  { patterns: FINANCIAL_ATTACK_PATTERNS, rule: "skill-financial-attack", suggestion: "检测到金融攻击风险，建议审查钱包访问、挖矿活动和资金转移逻辑" },
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

  // 规则 9-19: 扩展检测规则（来自 skills_check_patterns）
  const allTextFiles = findAllFiles(skillPath);
  for (const file of allTextFiles) {
    let fileContent: string;
    try {
      fileContent = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const relPath = path.relative(skillPath, file);

    for (const category of PATTERN_CATEGORIES) {
      for (const { pattern, description, severity } of category.patterns) {
        const match = pattern.exec(fileContent);
        if (match) {
          const currentValue = match[0].length > 100 ? match[0].substring(0, 100) + "..." : match[0];
          findings.push(makeResult(category.rule, severity, relPath, description, currentValue, category.suggestion));
        }
      }
    }
  }

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
      } else if (/\.(js|ts|mjs|cjs|sh|py|rb|php|json|yaml|yml|md|txt|env|conf|cfg|ini|cs|java|go|ps1|bat|cmd|toml|xml|rs|c|cpp|h|hpp|dockerfile|gradle|cmake|makefile)$/i.test(entry.name) || /^Dockerfile$/i.test(entry.name)) {
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
