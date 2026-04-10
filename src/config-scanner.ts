/**
 * OpenClaw 配置文件安全扫描模块
 * 用于静态扫描 ~/.openclaw/openclaw.json
 */

import * as fs from 'fs';
import * as path from 'path';
import os from 'os';

export interface ScanResult {
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  path: string;
  message: string;
  currentValue?: any;
  suggestion?: string;
}

/**
 * 完整的规则扫描结果(包含所有规则状态)
 */
export interface FullScanResult {
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  path: string;
  status: 'pass' | 'fail';
  message: string;
  currentValue?: any;
  suggestion?: string;
}

export interface OpenClawConfig {
  meta?: {
    lastTouchedVersion?: string;
    lastTouchedAt?: string;
  };
  gateway?: {
    port?: number;
    mode?: string;
    bind?: string;
    rateLimit?: {
      enabled?: boolean;
      windowMs?: number;
      maxRequests?: number;
    };
    auth?: {
      mode?: string;
      token?: string;
    };
    tailscale?: {
      mode?: string;
      resetOnExit?: boolean;
    };
    nodes?: {
      denyCommands?: string[];
      allowCommands?: string[];
    };
    trustedProxies?: string[];
    remoteUrl?: string;
    cors?: {
      enabled?: boolean;
      origins?: string[];
    };
  };
  tools?: {
    profile?: string;
    exec?: {
      security?: string;
      allowedCommands?: string[];
      deniedCommands?: string[];
    };
    write?: {
      allowedPaths?: string[];
      deniedPaths?: string[];
    };
    web?: {
      search?: {
        provider?: string;
      };
    };
  };
  plugins?: {
    allow?: string[];
    entries?: Record<string, { enabled?: boolean; source?: string }>;
    installs?: Record<string, { source?: string; installPath?: string }>;
  };
  hooks?: {
    internal?: {
      enabled?: boolean;
      entries?: Record<string, { enabled?: boolean }>;
    };
    webhooks?: {
      enabled?: boolean;
      entries?: Record<string, { enabled?: boolean; url?: string }>;
    };
  };
  auth?: {
    profiles?: Record<string, any>;
  };
  session?: {
    dmScope?: string;
    timeout?: number;
  };
  commands?: {
    native?: string;
    nativeSkills?: string;
    ownerDisplay?: string;
    restart?: boolean;
  };
  models?: {
    providers?: Record<string, {
      apiKey?: string;
      baseUrl?: string;
    }>;
  };
  agents?: {
    defaults?: {
      workspace?: string;
      model?: {
        primary?: string;
        fallbacks?: string[];
      };
      models?: Record<string, any>;
    };
  };
  log?: {
    level?: string;
    includeSensitive?: boolean;
  };
  mcp?: {
    entries?: Record<string, { enabled?: boolean; command?: string }>;
  };
}

const securityRules: Array<{
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  check: (config: OpenClawConfig) => ScanResult | null;
}> = [
  // ─────────────────────────────────────────────────────────────
  // 规则按字母顺序排列
  // ─────────────────────────────────────────────────────────────

  {
    id: 'api-endpoint-safety',
    severity: 'medium',
    check: (cfg) => {
      const providers = cfg.models?.providers;
      if (!providers) return null;

      for (const [name, provider] of Object.entries(providers)) {
        const baseUrl = provider.baseUrl;
        if (!baseUrl) continue;

        if (baseUrl.startsWith('http://')) {
          return {
            rule: 'api-endpoint-safety',
            severity: 'medium',
            path: `models.providers.${name}.baseUrl`,
            message: `模型提供商${name}使用不安全的HTTP协议`,
            currentValue: baseUrl,
            suggestion: '建议使用HTTPS协议确保通信安全'
          };
        }

        const localhostPatterns = [
          /^https?:\/\/localhost\//i,
          /^https?:\/\/127\.\d+\.\d+\.\d+/i,
          /^https?:\/\/10\.\d+\.\d+\.\d+/i,
          /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/i,
          /^https?:\/\/192\.168\.\d+\.\d+/i,
        ];

        if (localhostPatterns.some(p => p.test(baseUrl))) {
          return {
            rule: 'api-endpoint-safety',
            severity: 'medium',
            path: `models.providers.${name}.baseUrl`,
            message: `模型提供商${name}配置了本地或内网地址`,
            currentValue: baseUrl,
            suggestion: '请确认本地API地址是否可信'
          };
        }
      }

      return null;
    }
  },

  {
    id: 'api-key-exposed',
    severity: 'critical',
    check: (cfg) => {
      const providers = cfg.models?.providers;
      if (!providers) return null;

      // 检测危险密钥模式
      const dangerousPatterns = [
        // 测试/示例密钥
        { pattern: /^sk-test/, name: '测试用API密钥' },
        { pattern: /^sk-project-test/, name: '项目测试密钥' },
        { pattern: /^(sk-test|test_sk|dev_sk|api-test-key)$/i, name: '测试环境密钥' },
        // GitHub
        { pattern: /^ghp_[a-zA-Z0-9]{36}/, name: 'GitHub Personal Access Token' },
        { pattern: /^ghs_[a-zA-Z0-9]{36}/, name: 'GitHub OAuth Access Token' },
        { pattern: /^gho_[a-zA-Z0-9]{36}/, name: 'GitHub OAuth Token' },
        { pattern: /^ghu_[a-zA-Z0-9]{36}/, name: 'GitHub User Access Token' },
        { pattern: /^Qithub-/, name: 'GitHub OAuth令牌' },
        // Slack
        { pattern: /^xox[baprs]-[0-9a-zA-Z-]{10,48}/, name: 'Slack令牌' },
        // AWS
        { pattern: /^AKIA[0-9A-Z]{16}/, name: 'AWS Access Key ID' },
        { pattern: /^ASIA[0-9A-Z]{16}/, name: 'AWS Session Token' },
        // Google
        { pattern: /^AIza[0-9A-Za-z-_]{35}/, name: 'Google API Key' },
        { pattern: /^ya29\.[0-9A-Za-z-_]+/, name: 'Google OAuth Access Token' },
        // Stripe
        { pattern: /^sk_live_[0-9a-zA-Z]{24}/, name: 'Stripe Live Secret Key' },
        { pattern: /^sk_test_[0-9a-zA-Z]{24}/, name: 'Stripe Test Secret Key' },
        { pattern: /^rk_live_[0-9a-zA-Z]{24}/, name: 'Stripe Live Restricted Key' },
        { pattern: /^rk_test_[0-9a-zA-Z]{24}/, name: 'Stripe Test Restricted Key' },
        // SendGrid
        { pattern: /^SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}/, name: 'SendGrid API Key' },
        // Twilio
        { pattern: /^SK[0-9a-fA-F]{32}/, name: 'Twilio API Key' },
        { pattern: /^AC[0-9a-fA-F]{32}/, name: 'Twilio Account SID' },
        // Mailgun
        { pattern: /^key-[0-9a-fA-F]{32}/, name: 'Mailgun API Key' },
        // Nexmo / Vonage
        { pattern: /^[0-9a-fA-F]{32}$/, name: 'Nexmo/Vonage API Key' },
        // Plaid
        { pattern: /^access-sandbox-[0-9a-f-]{36}/, name: 'Plaid Sandbox Access Token' },
        { pattern: /^PLAID[0-9A-Za-z_-]{20,}$/, name: 'Plaid API Key' },
        // Square
        { pattern: /^sq0atp-[0-9a-zA-Z-_]{22}$/, name: 'Square Access Token' },
        { pattern: /^sq0csp-[0-9A-Za-z_-]{43}$/, name: 'Square Client ID' },
        // Shopify
        { pattern: /^shpat_[0-9a-fA-F]{32}/, name: 'Shopify Admin API Token' },
        // Dropbox
        { pattern: /^[A-Za-z0-9]{40}$/, name: 'Dropbox Access Token' },
        // Discord
        { pattern: /^[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6,}\.[A-Za-z\d_-]{27,}$/, name: 'Discord Bot Token' },
        // Zoom
        { pattern: /^[A-Za-z0-9+/]{40}$/, name: 'Zoom JWT Token' },
        // Atlassian
        { pattern: /^[A-Za-z0-9]{24}$/, name: 'Atlassian API Token' },
        // Heroku
        { pattern: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, name: 'Heroku API Key' },
        // npm
        { pattern: /^npm_[A-Za-z0-9]{36}$/, name: 'npm Access Token' },
        // Fastly
        { pattern: /^[A-Za-z0-9-_]{43}$/, name: 'Fastly API Token' },
        // OpenAI
        { pattern: /^sk-[0-9A-Za-z-_]{48}$/, name: 'OpenAI API Key' },
        // Anthropic
        { pattern: /^sk-ant-[0-9A-Za-z-_]{48,}$/, name: 'Anthropic API Key' },
        // Azure
        { pattern: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, name: 'Azure Client Secret' },
        // PayPal
        { pattern: /^access_token\$.+/, name: 'PayPal Access Token' },
        // Twilio Auth Token (separate from API key)
        { pattern: /^[A-Za-z0-9]{32}$/, name: 'Twilio Auth Token' },
      ];

      for (const [name, provider] of Object.entries(providers)) {
        const apiKey = provider.apiKey;
        if (!apiKey) continue;

        for (const { pattern, name: patternName } of dangerousPatterns) {
          if (pattern.test(apiKey)) {
            return {
              rule: 'hardcoded-secrets',
              severity: 'critical',
              path: `models.providers.${name}.apiKey`,
              message: `配置中存在硬编码的敏感密钥: ${patternName}`,
              currentValue: apiKey.substring(0, 12) + '***',
              suggestion: '请使用环境变量或安全的密钥管理服务存储敏感信息'
            };
          }
        }
      }
      return null;
    }
  },

  // ========== 配置安全: 危险标志检测 ==========
  {
    id: 'dangerous-flags',
    severity: 'critical',
    check: (cfg) => {
      const dangerousFlagPatterns = [
        // 权限绕过类
        'allowAll', 'allowAllUsers', 'allowAllAccess', 'allowAny',
        'disableSafety', 'disableSecurity', 'disableAudit', 'disableSandbox',
        'bypassAuth', 'bypassAuthz', 'skipAuth', 'skipAuthz', 'noAuth',
        'openAccess', 'openMode', 'anonymousAccess', 'anonymousLogin', 'autoLogin',
        // 开发调试类
        'debugMode', 'debug', 'devMode', 'dev', 'testMode', 'test', 'qa',
        'verbose', 'verboseLogging', 'trace', 'traceLogging',
        // 加密/TLS 类
        'insecure', 'unencrypted', 'noTLS', 'noSSL', 'allowHTTP', 'httpOnly',
        'disableHTTPS', 'disableEncryption', 'plainText',
        // 速率限制类
        'disableRateLimit', 'noRateLimit', 'unlimitedRate', 'noThrottle',
        // 证书校验类
        'ignoreCert', 'skipVerify', 'verifySSL', 'allowSelfSigned',
        'noCertVerify', 'insecureTLS',
        // 执行权限类
        'allowExec', 'allowShell', 'allowRaw', 'execEnabled', 'shellEnabled',
        'rawCommands', 'execMode', 'unsafeExec',
        // 日志/审计类
        'silentMode', 'noLog', 'noLogging', 'disableLogging', 'quietMode',
        'noAudit', 'auditDisabled',
        // 内存/会话类
        'persistSessions', 'sessionPersistence', 'noSessionExpiry', 'noTimeout',
        'allowMemoryLeak', 'leakMemory',
        // 安全沙箱类
        'noSandbox', 'disableSandbox', 'sandboxDisabled',
        // 代理类
        'skipProxy', 'noProxy', 'disableProxy',
      ];

      const gateway = cfg.gateway;
      if (gateway) {
        for (const [key, value] of Object.entries(gateway)) {
          if (typeof value === 'boolean' && value === true) {
            if (dangerousFlagPatterns.some(flag => key.toLowerCase().includes(flag.toLowerCase()))) {
              return {
                rule: 'dangerous-flags',
                severity: 'critical',
                path: `gateway.${key}`,
                message: `检测到危险配置标志 "${key}",可能关闭安全保护`,
                currentValue: value,
                suggestion: '请禁用该危险配置标志,确保安全保护功能正常开启'
              };
            }
          }
        }
      }

      const tools = cfg.tools;
      if (tools) {
        for (const [key, value] of Object.entries(tools)) {
          if (typeof value === 'object' && value !== null) {
            for (const [subKey, subValue] of Object.entries(value as Record<string, unknown>)) {
              if (subValue === true && dangerousFlagPatterns.some(flag => subKey.toLowerCase().includes(flag.toLowerCase()))) {
                return {
                  rule: 'dangerous-flags',
                  severity: 'critical',
                  path: `tools.${key}.${subKey}`,
                  message: `检测到危险配置标志 "${key}.${subKey}",可能关闭安全保护`,
                  currentValue: subValue,
                  suggestion: '请禁用该危险配置标志,确保安全保护功能正常开启'
                };
              }
            }
          }
        }
      }

      return null;
    }
  },

  // ========== 配置安全: 环境变量注入 ==========
  {
    id: 'env-injection',
    severity: 'critical',
    check: (cfg) => {
      // 检查配置中是否引用了不安全的环境变量
      const configStr = JSON.stringify(cfg);

      // 危险的环境变量引用模式
      const dangerousEnvPatterns = [
        // 系统路径/目录类
        { pattern: /\$\{?HOME\}/g, name: 'HOME' },
        { pattern: /\$\{?USER\}/g, name: 'USER' },
        { pattern: /\$\{?PWD\}/g, name: 'PWD' },
        { pattern: /\$\{?SHELL\}/g, name: 'SHELL' },
        { pattern: /\$\{?HOSTNAME\}/g, name: 'HOSTNAME' },
        { pattern: /\$\{?HOST\}/g, name: 'HOST' },
        { pattern: /\$\{?IFS\}/g, name: 'IFS' },
        { pattern: /\$\{?OSTYPE\}/g, name: 'OSTYPE' },
        // 动态库注入类（最危险）
        { pattern: /\$\{?LD_PRELOAD\}/g, name: 'LD_PRELOAD' },
        { pattern: /\$\{?LD_LIBRARY_PATH\}/g, name: 'LD_LIBRARY_PATH' },
        { pattern: /\$\{?DYLD_INSERT_LIBRARIES\}/g, name: 'DYLD_INSERT_LIBRARIES' },
        { pattern: /\$\{?DYLD_LIBRARY_PATH\}/g, name: 'DYLD_LIBRARY_PATH' },
        // OpenSSL 证书劫持类
        { pattern: /\$\{?OPENSSL_CONF\}/g, name: 'OPENSSL_CONF' },
        { pattern: /\$\{?SSL_CERT_FILE\}/g, name: 'SSL_CERT_FILE' },
        { pattern: /\$\{?SSL_CERT_DIR\}/g, name: 'SSL_CERT_DIR' },
        // Git SSH 劫持类
        { pattern: /\$\{?GIT_SSH_COMMAND\}/g, name: 'GIT_SSH_COMMAND' },
        { pattern: /\$\{?GIT_TEMPLATE_DIR\}/g, name: 'GIT_TEMPLATE_DIR' },
        // 语言环境注入类
        { pattern: /\$\{?PERL5LIB\}/g, name: 'PERL5LIB' },
        { pattern: /\$\{?PYTHONPATH\}/g, name: 'PYTHONPATH' },
        { pattern: /\$\{?JAVA_HOME\}/g, name: 'JAVA_HOME' },
        { pattern: /\$\{?M2_HOME\}/g, name: 'M2_HOME' },
        { pattern: /\$\{?GOROOT\}/g, name: 'GOROOT' },
        { pattern: /\$\{?GOPATH\}/g, name: 'GOPATH' },
        // AWS 凭证注入
        { pattern: /AWS_ACCESS_KEY_ID.*\$\{/g, name: 'AWS_ACCESS_KEY_ID（引用变量）' },
        { pattern: /AWS_SECRET_ACCESS_KEY.*\$\{/g, name: 'AWS_SECRET_ACCESS_KEY（引用变量）' },
        // CMD / PS1 命令注入
        { pattern: /COMSPEC.*\$\{/g, name: 'COMSPEC（命令注入）' },
        { pattern: /windir.*\$\{/g, name: 'windir（路径注入）' },
      ];

      for (const { pattern, name } of dangerousEnvPatterns) {
        if (pattern.test(configStr)) {
          return {
            rule: 'env-injection',
            severity: 'critical',
            path: 'config',
            message: `配置中引用了危险的环境变量: ${name}`,
            currentValue: '存在环境变量引用',
            suggestion: '避免在配置中使用可能导致注入的环境变量'
          };
        }
      }

      return null;
    }
  },

  // ========== 凭证安全: Token 熵值检测 (高标准) ==========
  {
    id: 'token-entropy',
    severity: 'critical',
    check: (cfg) => {
      const token = cfg.gateway?.auth?.token;
      if (!token) return null;

      // 高标准: 至少 48 字符 (192-bit entropy)，严于业界常用 40 字符标准
      if (token.length < 48) {
        return {
          rule: 'token-entropy',
          severity: 'critical',
          path: 'gateway.auth.token',
          message: `认证令牌熵值不足,当前长度${token.length}字符,低于48字符高安全阈值`,
          currentValue: token.substring(0, 8) + '***',
          suggestion: '请使用加密安全的随机数生成器生成至少48字符的强令牌,建议使用 openssl rand -hex 32'
        };
      }

      return null;
    }
  },

  // ========== 凭证安全: Token 弱模式检测 ==========
  {
    id: 'token-weak-pattern',
    severity: 'critical',
    check: (cfg) => {
      const token = cfg.gateway?.auth?.token;
      if (!token) return null;

      // 检测弱模式 - 扩展版
      const weakPatterns: Array<{ pattern: RegExp; name: string }> = [
        // 纯字符类型问题
        { pattern: /^0+$/, name: '全零字符串' },
        { pattern: /^1+$/, name: '全1字符串' },
        { pattern: /^[a-z]+$/, name: '仅包含小写字母' },
        { pattern: /^[A-Z]+$/, name: '仅包含大写字母' },
        { pattern: /^[0-9]+$/, name: '仅包含数字' },
        { pattern: /^([a-zA-Z0-9])\1+$/, name: '单一字符重复' },
        { pattern: /^(.)\1{5,}$/, name: '连续6次以上重复' },

        // 常见数字序列
        { pattern: /^(123456|654321|111111|222222|333333|444444|555555|666666|777777|888888|999999|000000|123123|321321|112233|123321)$/, name: '简单数字序列' },
        { pattern: /^(12345|54321|98765|56789|01234|13579|24680|1122334455)$/, name: '常见递增递减数列' },
        { pattern: /^(0000|1111|2222|3333|4444|5555|6666|7777|8888|9999)$/, name: '四位重复数字' },
        { pattern: /^(1{6,}|2{6,}|3{6,}|4{6,}|5{6,}|6{6,}|7{6,}|8{6,}|9{6,}|0{6,})$/, name: '六位及以上重复数字' },

        // 键盘顺序模式
        { pattern: /^(qwerty|qwertyuiop|asdfgh|zxcvbn|qazwsx|1234qwer|qwe123|admin123|test123|password123|pass123)$/i, name: '键盘顺序排列' },
        { pattern: /^(1qaz|2wsx|3edc|4rfv|5tgb|6yhn|7ujm|8ik|9ol|0p)$/, name: '键盘纵列模式' },
        { pattern: /^(qweasd|asdzxc|qazxsw|zxcvfr|zxcasd)$/, name: '键盘横行列模式' },
        { pattern: /^(!@#$|!@#$%^|!@#$%^&|!@#$%^&*)$/, name: '键盘符号序列' },
        { pattern: /^(aaa|bbb|ccc|ddd|eee|fff|ggg|hhh|iii|jjj|kkk|lll|mmm|nnn|ooo|ppp|qqq|rrr|sss|ttt|uuu|vvv|www|xxx|yyy|zzz)$/i, name: '三连字母' },

        // 常见单词前缀/后缀
        { pattern: /^(password|passwd|pass|admin|root|user|guest|master|test|default|demo|sample|welcome|login|signin|secret|private|backup|temp|temporary|letmein| Access|secret|api|token|key|auth)/i, name: '常见单词' },
        { pattern: /(password|passwd|admin|root|user|test|default|secret|123456|qwerty)$/i, name: '常见单词后缀' },
        { pattern: /^(password123|pass123|admin123|root123|user123|test123|default123|welcome123|login123|secret123|master123|guest123|password1|password!|admin!|root!|root123!)$/i, name: '单词+数字组合' },

        // 常见品牌/服务名
        { pattern: /^(google|facebook|amazon|microsoft|apple|twitter|github|gitlab|linkedin|instagram|netflix|spotify|adobe|oracle|ibm|intel|amd|nvidia)/i, name: '常见品牌名' },
        { pattern: /^(google123|facebook123|amazon123|microsoft123|apple123|twitter123|github123|admin@|root@|user@)/i, name: '品牌+数字组合' },

        // 月份/星期/季节
        { pattern: /^(january|february|march|april|may|june|july|august|september|october|november|december|spring|summer|autumn|winter|monday|tuesday|wednesday|thursday|friday|saturday|sunday)$/i, name: '时间相关单词' },
        { pattern: /^(jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec|sun|mon|tue|wed|thu|fri|sat)$/i, name: '时间单词缩写' },

        // 常见人名/地名
        { pattern: /^(john|michael|david|robert|james|mary|patricia|charlie|business|company|server|database|mysql|postgresql|mongodb|redis|apache|nginx|tomcat|jetty)$/i, name: '常见名称' },
        { pattern: /^(newyork|london|tokyo|sydney|paris|berlin|beijing|shanghai|hongkong| singapore)$/i, name: '常见城市' },

        // 编程相关
        { pattern: /^(hello|world|helloworld|foo|bar|baz|foobar|foo123|bar123|baz123|test|sample|demo|example)$/i, name: '编程常见词' },
        { pattern: /^(function|class|object|array|string|number|boolean|null|undefined|variable|constant)$/i, name: '编程关键词' },
        { pattern: /^(javascript|python|java|cpp|csharp|golang|rust|ruby|php|swift|kotlin|typescript|sql|html|css|xml|json|yaml|toml)$/i, name: '编程语言名' },

        // 安全相关
        { pattern: /^(security|secure|safe|encrypt|decrypt|hash|cipher|crypto|signature|certificate|ssl|tls|https|http)$/i, name: '安全相关词' },
        { pattern: /^(firewall|proxy|vpn|gateway|router|switch|hub|bridge|modem|router)$/i, name: '网络设备名' },

        // 包含年份
        { pattern: /^(19[5-9][0-9]|20[0-2][0-9])(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])$/, name: '日期格式' },
        { pattern: /^(19[5-9][0-9]|20[0-2][0-9])(0[1-9]|1[0-2])$/, name: '年月格式' },
        { pattern: /^(19[5-9][0-9]|20[0-2][0-9])$/, name: '年份格式' },

        // 常见弱口令变体
        { pattern: /^(p@ssw0rd|p@ssword|p@ssw0rd!|passw0rd|passward|passwrd|passw0rd!|p@55w0rd|p@55word)$/i, name: 'password变体' },
        { pattern: /^(admin@123|admin!|administrator123|admin123!|adm1n|adm!n|@dmin)$/i, name: 'admin变体' },
        { pattern: /^(root@|root!|r00t|r00t!|r00t123|toor|toor123)$/i, name: 'root变体' },

        // 彩虹表常见值
        { pattern: /^(5f4dcc3b5aa765d61d8327deb882cf99|098f6bcd4621d373cade4e832627b4f6|e10adc3949ba59abbe56e057f20f883e|d8578edf8458ce06fbc5bb76a58c5ca4)$/, name: '常见MD5哈希前缀' },
        { pattern: /^(5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8|63a9f0ea7bb98050796b649e85481845)$/, name: '常见SHA1哈希前缀' },
        { pattern: /^(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)$/, name: '空字符串SHA256' },
        { pattern: /^(8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92)$/, name: '123456的SHA256' },

        // 连续字符检测
        { pattern: /^(abcdefghijklmnopqrstuvwxyz|ABCDEFGHIJKLMNOPQRSTUVWXYZ)$/, name: '字母表顺序' },
        { pattern: /^(0123456789|9876543210|1234567890|0987654321)$/, name: '数字表顺序' },
        { pattern: /^(qwertyuiop|asdfghjkl|zxcvbnm|qwertyuiopasdfghjklzxcvbnm)$/i, name: '键盘字母表' },

        // 国内常见弱口令（拼音类）
        { pattern: /^(mima|mm|ma|password|passwd|mypass|login|pwd|login123)$/i, name: '拼音弱口令' },
        { pattern: /^(wode|wo|ni|de|ta)$/i, name: '单字拼音' },
        { pattern: /^(qwer|asdf|zxcv|zaq1|1qaz|2wsx)$/i, name: '拼音键盘组合' },
        { pattern: /^(guanliyuan|guanli|zhuanjia|jiazhang|laoshi)$/i, name: '身份称谓拼音' },
        { pattern: /^(admin888|admin123|admins|administrator|administrator123)$/i, name: 'admin拼音变体' },
        { pattern: /^(superuser|superman|superman123)$/i, name: '超级用户拼音变体' },
        { pattern: /^(888888|666666|99999|11111|22222|123123|321321|00000000|11111111)$/, name: '连号重复数字' },
        { pattern: /^(a123456|a123456789|abc123456|abc123|abc123456789)$/i, name: '字母+常见数字组合' },

        // Windows 系统类弱口令
        { pattern: /^(changeme|changethis|default|defaultpass|password!|Password1|Admin123|Admin@123|rootroot|passpass)$/i, name: '系统默认弱口令' },
        { pattern: /^(q1w2e3r4|1q2w3e4r|1q2w3e|q1w2e3)$/i, name: '键盘斜向组合' },
        { pattern: /^(P@ssw0rd|P@ssword|Password1|Password!|Admin123!|admin@123)$/i, name: '首字母大写+数字' },
        { pattern: /^(letmein|welcome1|welcome123|welcomeback|welcome)$/i, name: '英文常见弱口令' },
        { pattern: /^(Pa$$w0rd|Pa55word|P@55w0rd|passw0rd!|Password123!)$/i, name: '混合替换弱口令' },
        { pattern: /^(football|baseball|soccer|monkey|shadow|sunshine|princess|dragon|master|master123)$/i, name: '英文常见单词弱口令' },

        // UUID 弱模式
        { pattern: /^([0-9a-f]{8}-[0-9a-f]{4}-)0000-[0-9a-f]{4}-[0-9a-f]{12}$/i, name: '零填充UUID' },
        { pattern: /^([0-9a-f]{8}-[0-9a-f]{4}-)1234-[0-9a-f]{4}-[0-9a-f]{12}$/i, name: '测试UUID' },
        { pattern: /^[0-9a-f]{32}$/, name: '32位纯十六进制（疑似弱UUID）' },

        // Base64 编码弱口令特征
        { pattern: /^(YWRtaW4=|YWRtaW44Mjg=|YWRtaW4xMjM=|YWRtaW4xMjM0NTY3ODkw|pass|YWJjMTIz)=?$/i, name: 'Base64编码常见弱口令' },

        // JWT / Token 格式弱模式
        { pattern: /^(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.)[a-zA-Z0-9_-]*$/, name: 'JWT Token（疑似空签名）' },
        { pattern: /^(Bearer\s+)?[a-zA-Z0-9_=-]{1,32}$/, name: '过短Bearer Token' },

        // 国内云服务密钥弱模式
        { pattern: /^(aliyun|aliyuncs|aliyun[0-9]|oss|rds|ecs)[a-zA-Z0-9_=-]{8,}$/i, name: '阿里云密钥弱模式' },
        { pattern: /^(qcloud|tencent|qcloud[0-9]|cos|secretid|secretkey)[a-zA-Z0-9_=-]{8,}$/i, name: '腾讯云密钥弱模式' },
        { pattern: /^(baidu|bce|baidu[0-9])[a-zA-Z0-9_=-]{8,}$/i, name: '百度云密钥弱模式' },
        { pattern: /^(huawei|hwcloud|huawei[0-9])[a-zA-Z0-9_=-]{8,}$/i, name: '华为云密钥弱模式' },

        // IP 地址/端口作为 token 特征
        { pattern: /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/, name: 'IP或IP:端口作为token' },
      ];

      for (const { pattern, name } of weakPatterns) {
        if (pattern.test(token)) {
          return {
            rule: 'token-weak-pattern',
            severity: 'critical',
            path: 'gateway.auth.token',
            message: `认证令牌存在弱模式: ${name}`,
            currentValue: token.substring(0, 8) + '***',
            suggestion: '请使用随机生成的强令牌,避免使用常见单词、数字序列、键盘顺序等弱模式'
          };
        }
      }

      // 额外检测:包含多个常见弱口令片段
      const weakFragments = ['password', 'admin', 'root', 'user', 'test', 'default', 'secret', 'login', 'welcome', 'qwerty', 'abc123', '111111', '123456', '12345', 'pass', 'passw'];
      const fragmentCount = weakFragments.filter(f => token.toLowerCase().includes(f)).length;
      if (fragmentCount >= 2) {
        return {
          rule: 'token-weak-pattern',
          severity: 'critical',
          path: 'gateway.auth.token',
          message: `令牌包含多个弱口令片段(检测到${fragmentCount}个),容易被猜测`,
          currentValue: token.substring(0, 8) + '***',
          suggestion: '请使用随机生成的强令牌,避免组合多个常见单词'
        };
      }

      return null;
    }
  },

  // ========== 凭证安全: 速率限制检测 (高标准) ==========
  {
    id: 'rate-limiting',
    severity: 'medium',
    check: (cfg) => {
      const rateLimit = cfg.gateway?.rateLimit;

      if (!rateLimit || rateLimit.enabled === false) {
        return {
          rule: 'rate-limiting',
          severity: 'critical',
          path: 'gateway.rateLimit',
          message: '未配置访问速率限制,网关存在暴力破解和DDoS攻击风险',
          currentValue: rateLimit?.enabled ?? '未配置',
          suggestion: '请立即启用速率限制,高安全标准建议: windowMs: 60000, maxRequests: 30'
        };
      }

      // 高标准: 超过50次/分钟即为警告
      if (rateLimit.maxRequests && rateLimit.maxRequests > 50) {
        return {
          rule: 'rate-limiting',
          severity: 'medium',
          path: 'gateway.rateLimit.maxRequests',
          message: `速率限制阈值过高 (${rateLimit.maxRequests}次/窗口期),防护效果有限`,
          currentValue: rateLimit.maxRequests,
          suggestion: '高安全标准建议将 maxRequests 设置为不超过 30 次/分钟'
        };
      }

      // 检查窗口期是否合理
      if (rateLimit.windowMs && rateLimit.windowMs < 30000) {
        return {
          rule: 'rate-limiting',
          severity: 'medium',
          path: 'gateway.rateLimit.windowMs',
          message: `速率限制窗口期过短 (${rateLimit.windowMs}ms),可能影响正常访问`,
          currentValue: rateLimit.windowMs,
          suggestion: '建议窗口期设置为 60000ms (1分钟) 或更长'
        };
      }

      return null;
    }
  },

  // ========== 会话安全: Session TTL 检测 (高标准) ==========
  {
    id: 'session-ttl',
    severity: 'critical',
    check: (cfg) => {
      const timeout = cfg.session?.timeout;

      // 高标准: 未设置=Critical, >12小时=Critical, >4小时=Warning
      if (!timeout) {
        return {
          rule: 'session-ttl',
          severity: 'critical',
          path: 'session.timeout',
          message: `会话超时时间未设置,存在会话劫持和未授权访问风险`,
          currentValue: '未设置',
          suggestion: '请立即设置会话超时时间,建议不超过 14400 秒 (4小时)'
        };
      }

      if (timeout > 43200) { // 超过12小时
        return {
          rule: 'session-ttl',
          severity: 'critical',
          path: 'session.timeout',
          message: `会话超时时间过长 (${timeout}秒/${(timeout/3600).toFixed(1)}小时),安全风险极高`,
          currentValue: timeout,
          suggestion: '请将会话超时时间设置为不超过 14400 秒 (4小时)'
        };
      }

      if (timeout > 14400) { // 超过4小时
        return {
          rule: 'session-ttl',
          severity: 'medium',
          path: 'session.timeout',
          message: `会话超时时间过长 (${timeout}秒/${(timeout/3600).toFixed(1)}小时),建议进一步缩短`,
          currentValue: timeout,
          suggestion: '高安全标准建议将会话超时时间设置为不超过 14400 秒 (4小时)'
        };
      }

      return null;
    }
  },

  // ========== 网络安全: 浏览器控制端口隔离 ==========
  {
    id: 'browser-control-port',
    severity: 'critical',
    check: (cfg) => {
      // 检查 browser control 相关配置
      const gateway = cfg.gateway;
      if (!gateway) return null;

      // 检查是否有暴露的浏览器控制端口
      // 通常 browser control 会使用独立的端口
      const port = gateway.port;

      // 如果绑定到 0.0.0.0 且端口为常见浏览器控制端口
      if (gateway.bind === '0.0.0.0' || gateway.bind === '::') {
        // 常见的浏览器控制端口范围
        if (port && port >= 9100 && port <= 9200) {
          return {
            rule: 'browser-control-port',
            severity: 'critical',
            path: 'gateway.port',
            message: 'Gateway端口可能暴露浏览器控制服务',
            currentValue: port,
            suggestion: '确保浏览器控制仅在可信网络访问'
          };
        }
      }

      return null;
    }
  },

  // ========== 网络安全: TLS 加密传输 ==========
  {
    id: 'tls-required',
    severity: 'critical',
    check: (cfg) => {
      const gateway = cfg.gateway;
      if (!gateway) return null;

      if (gateway.bind === '0.0.0.0' || gateway.bind === '::') {
        return {
          rule: 'tls-required',
          severity: 'critical',
          path: 'gateway.tls',
          message: 'Gateway暴露到公网但未配置TLS/SSL加密传输',
          currentValue: '未配置',
          suggestion: '请配置TLS证书或通过反向代理提供HTTPS加密传输'
        };
      }

      return null;
    }
  },

  // ========== 网络安全: 跨域策略安全 ==========
  {
    id: 'cors-wildcard',
    severity: 'critical',
    check: (cfg) => {
      const cors = cfg.gateway?.cors;
      if (!cors) return null;

      if (!cors.enabled) return null;

      const origins = cors.origins;
      if (!origins || origins.length === 0) return null;

      if (origins.includes('*') || origins.includes('http://*') || origins.includes('https://*')) {
        return {
          rule: 'cors-wildcard',
          severity: 'critical',
          path: 'gateway.cors.origins',
          message: 'CORS跨域策略配置使用通配符(*) ,存在跨站请求伪造风险',
          currentValue: origins,
          suggestion: '请使用具体的可信域名列表,避免使用通配符'
        };
      }

      const httpOrigins = origins.filter(o => o.startsWith('http://'));
      if (httpOrigins.length > 0) {
        return {
          rule: 'cors-wildcard',
          severity: 'critical',
          path: 'gateway.cors.origins',
          message: 'CORS跨域策略包含不安全的HTTP源,存在中间人攻击风险',
          currentValue: origins,
          suggestion: '请使用HTTPS源,确保通信加密'
        };
      }

      return null;
    }
  },

  // ========== 网络安全: 远程接入安全 ==========
  {
    id: 'tailscale-security',
    severity: 'medium',
    check: (cfg) => {
      const ts = cfg.gateway?.tailscale;
      if (!ts) return null;

      // Tailscale 开启但未配置认证
      if (ts.mode === 'on' || ts.mode === 'enabled') {
        const auth = cfg.gateway?.auth;

        // 检查是否配置了认证
        if (!auth?.mode || !auth?.token) {
          return {
            rule: 'tailscale-security',
            severity: 'medium',
            path: 'gateway.tailscale',
            message: 'Tailscale已启用但Gateway未配置认证',
            currentValue: ts.mode,
            suggestion: '确保 gateway.auth.token 已配置'
          };
        }
      }

      return null;
    }
  },

  // ========== 数据防护: 私钥泄露检测 ==========
  {
    id: 'private-key-leak',
    severity: 'critical',
    check: (cfg) => {
      const dangerousPaths = [
        /\.pem$/i,
        /\.key$/i,
        /\.p12$/i,
        /\.pfx$/i,
        /\.cert$/i,
        /\/keys\//i,
        /\/certs\//i,
        /\/private\//i,
      ];

      const providers = cfg.models?.providers;
      if (providers) {
        for (const [name, provider] of Object.entries(providers)) {
          const baseUrl = provider.baseUrl;
          if (baseUrl) {
            for (const pattern of dangerousPaths) {
              if (pattern.test(baseUrl)) {
                return {
                  rule: 'private-key-leak',
                  severity: 'critical',
                  path: `models.providers.${name}.baseUrl`,
                  message: `配置中检测到疑似私钥文件路径,可能造成敏感信息泄露`,
                  currentValue: baseUrl,
                  suggestion: '请确保私钥文件路径不在配置中暴露,使用安全的密钥管理方案'
                };
              }
            }
          }
        }
      }

      return null;
    }
  },

  // ========== 数据防护: 加密货币密钥检测 ==========
  {
    id: 'mnemonic-leak',
    severity: 'critical',
    check: (cfg) => {
      const mnemonicPatterns = [
        // BIP39 助记词（12/15/18/21/24 词）
        /\b([a-z]+\s+){11}[a-z]+\b/i,
        /\b([a-z]+\s+){14}[a-z]+\b/i,
        /\b([a-z]+\s+){17}[a-z]+\b/i,
        /\b([a-z]+\s+){20}[a-z]+\b/i,
        /\b([a-z]+\s+){23}[a-z]+\b/i,
        // 助记词直接标识
        /\b(mnemonic|seed|recovery|wallet|walletseed|bip39|mnemonic phrase|seed phrase|recovery phrase)\s*[:=]\s*["']?[a-z\s]+["']?/i,
        // Ethereum 私钥/钱包
        /\b(0x)?[0-9a-f]{64}\b/i,
        /\b(0x)?[0-9a-f]{128}\b/i,
        // Bitcoin 私钥（WIF 压缩/未压缩）
        /\b[5KLNS][1-9A-HJ-NP-Za-km-z]{50,51}\b/,      // WIF 未压缩
        /\b[LK][1-9A-HJ-NP-Za-km-z]{52}\b/,            // WIF 压缩
        // Bitcoin 地址（Legacy / SegWit）
        /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/,         // P2PKH / P2SH
        /\bbc1[0-9a-z]{39,59}\b/i,                     // Bech32 / Bech32m
        // Solana 私钥 / 助记词
        /\b[0-9a-f]{88}\b/,                            // Solana 私钥
        /\bsolana[a-z\s\d]{50,}/i,                     // Solana 助记词标识
        // XRP 私钥 / 地址
        /\br[0-9a-zA-Z]{24,34}\b/,
        // 加密货币交易所 API Key 格式
        /\b(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?[a-zA-Z0-9+/=]{20,}["']?/i,
        // 钱包地址关键词检测
        /\b(wallet[_-]?address|deposit[_-]?address|withdraw[_-]?address|public[_-]?key)\s*[:=]\s*["']?0x[a-fA-F0-9]{40}["']?/i,
        // 助记词路径标识
        /\b(m\/44'\/0'\/|m\/44'\/60'\/|m\/501')/,
        // 加密货币相关配置标识
        /\b(crypto[_-]?wallet|web3[_-]?wallet|hd[_-]?wallet|keystore|json[_-]?wallet)\s*[:=]/i,
      ];

      const configStr = JSON.stringify(cfg);

      for (const pattern of mnemonicPatterns) {
        if (pattern.test(configStr)) {
          return {
            rule: 'mnemonic-leak',
            severity: 'critical',
            path: 'config',
            message: '配置中检测到疑似加密货币助记词或钱包种子,存在资产被盗风险',
            currentValue: '存在可疑字符串',
            suggestion: '请确保配置中不包含任何加密货币相关的密钥信息'
          };
        }
      }

      return null;
    }
  },

  {
    id: 'gateway-bind-exposed',
    severity: 'critical',
    check: (cfg) => {
      const gateway = cfg.gateway;
      if (!gateway) return null;

      const bind = gateway.bind;
      const port = gateway.port;

      if (bind === '0.0.0.0' || bind === '::') {
        return {
          rule: 'gateway-bind-exposed',
          severity: 'critical',
          path: 'gateway.bind',
          message: `Gateway 绑定到公网地址 (${bind}:${port}),存在未授权访问风险`,
          currentValue: `${bind}:${port}`,
          suggestion: '改为 "127.0.0.1" 或 "loopback"'
        };
      }

      return null;
    }
  },

  {
    id: 'plugins-allow-missing',
    severity: 'critical',
    check: (cfg) => {
      const allow = cfg.plugins?.allow;
      const entries = cfg.plugins?.entries;

      if (!allow && entries && Object.keys(entries).length > 0) {
        return {
          rule: 'plugins-allow-missing',
          severity: 'critical',
          path: 'plugins.allow',
          message: '存在已启用的插件但未设置白名单',
          currentValue: undefined,
          suggestion: '设置 plugins.allow 为可信插件ID列表'
        };
      }

      return null;
    }
  },

  {
    id: 'untrusted-proxy-config',
    severity: 'critical',
    check: (cfg) => {
      const bind = cfg.gateway?.bind;
      const trustedProxies = cfg.gateway?.trustedProxies;

      if ((bind === '127.0.0.1' || bind === 'loopback') && !trustedProxies?.length) {
        return null;
      }

      if (bind !== '127.0.0.1' && bind !== 'loopback' && (!trustedProxies || trustedProxies.length === 0)) {
        return {
          rule: 'untrusted-proxy-config',
          severity: 'critical',
          path: 'gateway.trustedProxies',
          message: 'Gateway暴露在非本地网络但未配置可信代理',
          currentValue: undefined,
          suggestion: '设置 gateway.trustedProxies 包含代理服务器IP'
        };
      }

      return null;
    }
  },

  // ========== 扩展: 综合安全评估 ==========

  {
    id: 'gateway-auth-mode-insecure',
    severity: 'critical',
    check: (cfg) => {
      const authMode = cfg.gateway?.auth?.mode;
      if (authMode === 'none' || authMode === 'disabled' || authMode === 'insecure') {
        return {
          rule: 'gateway-auth-mode-insecure',
          severity: 'critical',
          path: 'gateway.auth.mode',
          message: 'Gateway 认证模式设置为不安全模式',
          currentValue: authMode,
          suggestion: '使用 "token" 或 "oauth" 等安全认证模式'
        };
      }
      return null;
    }
  },

  {
    id: 'gateway-auth-disabled',
    severity: 'critical',
    check: (cfg) => {
      const auth = cfg.gateway?.auth;
      if (!auth) {
        return {
          rule: 'gateway-auth-disabled',
          severity: 'critical',
          path: 'gateway.auth',
          message: 'Gateway 未配置认证字段 (gateway.auth 缺失)',
          currentValue: undefined,
          suggestion: '请在 gateway.auth 中配置 mode 和 token'
        };
      }

      const missing: string[] = [];
      if (!auth.mode) missing.push('mode');
      if (!auth.token) missing.push('token');

      if (missing.length > 0) {
        return {
          rule: 'gateway-auth-disabled',
          severity: 'critical',
          path: `gateway.auth.${missing.join(', ')}`,
          message: `Gateway 认证配置不完整，缺失字段: ${missing.join(', ')}`,
          currentValue: missing.join(', '),
          suggestion: '请设置 gateway.auth.mode 为 "token" 并配置有效 token'
        };
      }
      return null;
    }
  },

  {
    id: 'api-key-exposed',
    severity: 'critical',
    check: (cfg) => {
      const providers = cfg.models?.providers;
      if (!providers) return null;

      for (const [name, provider] of Object.entries(providers)) {
        const apiKey = provider.apiKey;
        if (!apiKey) continue;

        // 检查是否包含明显的不安全模式
        if (apiKey === 'sk-test' || apiKey === 'test-key' || apiKey.startsWith('test_')) {
          return {
            rule: 'api-key-exposed',
            severity: 'critical',
            path: `models.providers.${name}.apiKey`,
            message: `Provider "${name}" 使用测试API Key`,
            currentValue: apiKey.substring(0, 10) + '...',
            suggestion: '使用生产环境的有效API Key'
          };
        }

        // 检查是否直接使用OAuth token而非apiKey
        if (apiKey.includes('oauth') || apiKey.toLowerCase().includes('token')) {
          // 这是正常的OAuth模式,不算安全问题
          continue;
        }
      }
      return null;
    }
  },

  {
    id: 'workspace-not-restricted',
    severity: 'critical',
    check: (cfg) => {
      const workspace = cfg.agents?.defaults?.workspace;
      if (!workspace) return null;

      // 工作区设置为根目录或系统目录
      const dangerousPaths = ['/', '/home', '/root', '/tmp', os.homedir()];
      if (dangerousPaths.includes(workspace) || workspace === os.homedir()) {
        return {
          rule: 'workspace-not-restricted',
          severity: 'critical',
          path: 'agents.defaults.workspace',
          message: '工作区设置为系统敏感目录',
          currentValue: workspace,
          suggestion: '使用专用工作目录,避免授予完整系统访问权限'
        };
      }
      return null;
    }
  },

  {
    id: 'log-level-verbose',
    severity: 'critical',
    check: (cfg) => {
      const logLevel = cfg.log?.level;
      if (!logLevel) return null;

      // trace/debug 级别可能泄露敏感信息
      if (logLevel === 'trace' || logLevel === 'debug') {
        return {
          rule: 'log-level-verbose',
          severity: 'critical',
          path: 'log.level',
          message: '日志级别设置为 trace/debug,可能泄露敏感信息',
          currentValue: logLevel,
          suggestion: '使用 "info" 或 "warn" 级别'
        };
      }
      return null;
    }
  },

  {
    id: 'log-include-sensitive',
    severity: 'critical',
    check: (cfg) => {
      const includeSensitive = cfg.log?.includeSensitive;
      if (includeSensitive === true) {
        return {
          rule: 'log-include-sensitive',
          severity: 'critical',
          path: 'log.includeSensitive',
          message: '日志配置为包含敏感信息',
          currentValue: true,
          suggestion: '设置为 false,避免在日志中记录密码、token等'
        };
      }
      return null;
    }
  },

  {
    id: 'session-timeout-missing',
    severity: 'medium',
    check: (cfg) => {
      const timeout = cfg.session?.timeout;
      const dmScope = cfg.session?.dmScope;

      // 没有设置超时且会话作用域过宽
      if ((!timeout || timeout === 0) && (dmScope === 'all' || dmScope === 'global')) {
        return {
          rule: 'session-timeout-missing',
          severity: 'medium',
          path: 'session.timeout',
          message: '会话无超时限制且作用域为全局,存在持久化访问风险',
          currentValue: timeout,
          suggestion: '设置合理的 session.timeout (如 3600 秒)'
        };
      }
      return null;
    }
  },

  {
    id: 'mcp-untrusted-commands',
    severity: 'critical',
    check: (cfg) => {
      const mcp = cfg.mcp?.entries;
      if (!mcp) return null;

      for (const [name, entry] of Object.entries(mcp)) {
        if (!entry.enabled) continue;

        const command = entry.command;
        if (!command) continue;

        // 检查是否包含危险的shell命令
        if (command.includes('rm -rf') || command.includes('> /dev/') || command.includes('chmod 777')) {
          return {
            rule: 'mcp-untrusted-commands',
            severity: 'critical',
            path: `mcp.entries.${name}.command`,
            message: `MCP "${name}" 配置包含危险命令`,
            currentValue: command.substring(0, 30) + '...',
            suggestion: '审查并移除危险的命令执行'
          };
        }
      }
      return null;
    }
  },

  {
    id: 'plugin-source-untrusted',
    severity: 'critical',
    check: (cfg) => {
      const installs = cfg.plugins?.installs;
      if (!installs) return null;

      for (const [name, install] of Object.entries(installs)) {
        const source = install.source;
        if (!source) continue;

        // 检查是否从不受信任的来源安装
        if (source === 'http' || source.startsWith('http://')) {
          return {
            rule: 'plugin-source-untrusted',
            severity: 'critical',
            path: `plugins.installs.${name}.source`,
            message: `插件 "${name}" 通过不安全协议(HTTP)安装`,
            currentValue: source,
            suggestion: '使用 "npm" 或 "archive" 等安全来源'
          };
        }
      }
      return null;
    }
  },

  {
    id: 'webhook-url-insecure',
    severity: 'critical',
    check: (cfg) => {
      const webhooks = cfg.hooks?.webhooks?.entries;
      if (!webhooks) return null;

      for (const [name, entry] of Object.entries(webhooks)) {
        if (!entry.enabled) continue;

        const url = entry.url;
        if (!url) continue;

        // 检查是否使用HTTP而非HTTPS
        if (url.startsWith('http://')) {
          return {
            rule: 'webhook-url-insecure',
            severity: 'critical',
            path: `hooks.webhooks.entries.${name}.url`,
            message: `Webhook "${name}" 使用不安全的HTTP协议`,
            currentValue: url,
            suggestion: '使用HTTPS确保传输安全'
          };
        }
      }
      return null;
    }
  },

  {
    id: 'default-port-exposed',
    severity: 'critical',
    check: (cfg) => {
      const bind = cfg.gateway?.bind;
      const port = cfg.gateway?.port;

      // 使用默认端口且绑定到公网
      if ((bind === '0.0.0.0' || bind === '::') && port === 18789) {
        return {
          rule: 'default-port-exposed',
          severity: 'critical',
          path: 'gateway.port',
          message: 'Gateway使用默认端口且暴露在公网',
          currentValue: port,
          suggestion: '更换为非默认端口或确保仅通过防火墙内网访问'
        };
      }
      return null;
    }
  },

  {
    id: 'exec-security-disabled',
    severity: 'critical',
    check: (cfg) => {
      const execConfig = cfg.tools?.exec;
      if (!execConfig) return null;

      const security = execConfig.security;
      if (security === 'disabled' || security === 'off' || security === 'none') {
        return {
          rule: 'exec-security-disabled',
          severity: 'critical',
          path: 'tools.exec.security',
          message: '工具执行安全检查已禁用',
          currentValue: security,
          suggestion: '启用安全检查,使用 "sandbox" 或 "audit" 模式'
        };
      }
      return null;
    }
  },

  {
    id: 'write-no-restrictions',
    severity: 'critical',
    check: (cfg) => {
      const writeConfig = cfg.tools?.write;
      if (!writeConfig) return null;

      const allowedPaths = writeConfig.allowedPaths;
      // 允许写入根目录或系统目录
      if (allowedPaths) {
        if (allowedPaths.includes('/') || allowedPaths.includes('*') || allowedPaths.includes('**')) {
          return {
            rule: 'write-no-restrictions',
            severity: 'critical',
            path: 'tools.write.allowedPaths',
            message: '文件写入无限制,允许写入任意路径',
            currentValue: allowedPaths,
            suggestion: '限制为特定工作目录'
          };
        }
      }
      return null;
    }
  },

  {
    id: 'tailscale-remote-url-exposure',
    severity: 'critical',
    check: (cfg) => {
      const ts = cfg.gateway?.tailscale;
      const remoteUrl = cfg.gateway?.remoteUrl;

      // Tailscale开启且配置了远程URL但没有认证
      if ((ts?.mode === 'on' || ts?.mode === 'enabled') && remoteUrl && !cfg.gateway?.auth?.token) {
        return {
          rule: 'tailscale-remote-url-exposure',
          severity: 'critical',
          path: 'gateway.tailscale',
          message: 'Tailscale远程访问已启用但未配置认证',
          currentValue: ts.mode,
          suggestion: '确保 gateway.auth.token 已配置'
        };
      }
      return null;
    }
  },

  {
    id: 'unverified-plugin-source',
    severity: 'critical',
    check: (cfg) => {
      const entries = cfg.plugins?.entries;
      if (!entries) return null;

      // 检查是否有启用的插件没有来源信息
      for (const [name, entry] of Object.entries(entries)) {
        if (!entry.enabled) continue;

        // 启用的插件应该存在于installs中或有明确来源
        const installs = cfg.plugins?.installs;
        if (!installs?.[name] && !entry.source) {
          return {
            rule: 'unverified-plugin-source',
            severity: 'critical',
            path: `plugins.entries.${name}`,
            message: `插件 "${name}" 启用但无法验证来源`,
            currentValue: name,
            suggestion: '确保插件来自可信来源'
          };
        }
      }
      return null;
    }
  },

  // ========== 工具安全: Web搜索配置 ==========
  {
    id: 'web-search-safety',
    severity: 'medium',
    check: (cfg) => {
      const webConfig = cfg.tools?.web;
      if (!webConfig) return null;

      // 检查web搜索配置
      const searchProvider = webConfig.search?.provider;
      if (!searchProvider) {
        return {
          rule: 'web-search-safety',
          severity: 'medium',
          path: 'tools.web.search',
          message: 'Web搜索未配置提供商,可能使用不安全的默认搜索',
          currentValue: '未配置',
          suggestion: '建议配置可信的搜索提供商'
        };
      }

      // 检查是否使用了不安全的搜索配置
      const unsafeProviders = ['unsafe', 'insecure', 'custom'];
      if (unsafeProviders.includes(searchProvider.toLowerCase())) {
        return {
          rule: 'web-search-safety',
          severity: 'medium',
          path: 'tools.web.search.provider',
          message: `Web搜索配置使用不安全的提供商: ${searchProvider}`,
          currentValue: searchProvider,
          suggestion: '建议使用可信的搜索服务提供商'
        };
      }

      return null;
    }
  },

  // ========== 系统安全: 所有者显示信息泄露 ==========
  {
    id: 'owner-display-info-leak',
    severity: 'medium',
    check: (cfg) => {
      const ownerDisplay = cfg.commands?.ownerDisplay;
      if (!ownerDisplay) return null;

      // 检查ownerDisplay配置
      // "raw" 模式可能泄露系统原始信息
      if (ownerDisplay === 'raw') {
        return {
          rule: 'owner-display-info-leak',
          severity: 'medium',
          path: 'commands.ownerDisplay',
          message: '所有者显示设置为raw模式,可能泄露系统原始信息',
          currentValue: ownerDisplay,
          suggestion: '建议使用安全的显示模式,如hash或anonymous'
        };
      }

      return null;
    }
  },

  // ========== 钩子安全: 内部钩子配置 ==========
  {
    id: 'internal-hooks-security',
    severity: 'medium',
    check: (cfg) => {
      const hooks = cfg.hooks?.internal;
      if (!hooks) return null;

      if (!hooks.enabled) return null;

      const entries = hooks.entries;
      if (!entries) return null;

      // 配置了 internal hooks 入口时提示审查（非白名单，禁止反而会造成误报）
      const hookNames = Object.keys(entries);
      if (hookNames.length > 0) {
        return {
          rule: 'internal-hooks-security',
          severity: 'medium',
          path: 'hooks.internal.entries',
          message: `配置了 ${hookNames.length} 个内部钩子: ${hookNames.join(', ')}`,
          currentValue: hookNames,
          suggestion: '请审查每个内部钩子的来源和用途，确保可信'
        };
      }

      return null;
    }
  },

  // ========== 会话安全: 会话隔离配置 ==========
  {
    id: 'session-isolation',
    severity: 'medium',
    check: (cfg) => {
      const dmScope = cfg.session?.dmScope;
      if (!dmScope) return null;

      // 检查会话作用域是否过于宽松
      if (dmScope === 'all' || dmScope === 'global') {
        return {
          rule: 'session-isolation',
          severity: 'medium',
          path: 'session.dmScope',
          message: `会话作用域设置为${dmScope},隔离性较差`,
          currentValue: dmScope,
          suggestion: '建议使用per-channel-peer或trusted模式'
        };
      }

      return null;
    }
  },

  // ========== 接口安全: 模型API端点 ==========
  {
    id: 'api-endpoint-safety',
    severity: 'medium',
    check: (cfg) => {
      const providers = cfg.models?.providers;
      if (!providers) return null;

      for (const [name, provider] of Object.entries(providers)) {
        const baseUrl = provider.baseUrl;
        if (!baseUrl) continue;

        // 检查是否使用HTTP协议
        if (baseUrl.startsWith('http://')) {
          return {
            rule: 'api-endpoint-safety',
            severity: 'medium',
            path: `models.providers.${name}.baseUrl`,
            message: `模型提供商${name}使用不安全的HTTP协议`,
            currentValue: baseUrl,
            suggestion: '建议使用HTTPS协议确保通信安全'
          };
        }

        // 检查是否配置了本地或内网地址
        const localhostPatterns = [
          /^https?:\/\/localhost\//i,
          /^https?:\/\/127\.\d+\.\d+\.\d+/i,
          /^https?:\/\/10\.\d+\.\d+\.\d+/i,
          /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/i,
          /^https?:\/\/192\.168\.\d+\.\d+/i,
        ];

        if (localhostPatterns.some(p => p.test(baseUrl))) {
          // 本地地址需要确认是否可信
          return {
            rule: 'api-endpoint-safety',
            severity: 'medium',
            path: `models.providers.${name}.baseUrl`,
            message: `模型提供商${name}配置了本地或内网地址`,
            currentValue: baseUrl,
            suggestion: '请确认本地API地址是否可信'
          };
        }
      }

      return null;
    }
  },

  // ========== 代理安全: 默认配置检查 ==========
  {
    id: 'agent-defaults-security',
    severity: 'low',
    check: (cfg) => {
      const agentDefaults = cfg.agents?.defaults;
      if (!agentDefaults) return null;
      
      // 检查是否有过于宽泛的fallback配置
      const fallbacks = agentDefaults.model?.fallbacks;
      if (fallbacks && fallbacks.length > 5) {
        return {
          rule: 'agent-defaults-security',
          severity: 'low',
          path: 'agents.defaults.model.fallbacks',
          message: `配置了过多的模型回退选项(${fallbacks.length}个),可能影响稳定性`,
          currentValue: fallbacks.length,
          suggestion: '建议保留2-3个核心回退模型'
        };
      }
      
      return null;
    }
  },

  // ========== 工具安全: 执行权限控制 ==========
  {
    id: 'exec-permission-control',
    severity: 'medium',
    check: (cfg) => {
      const execConfig = cfg.tools?.exec;
      if (!execConfig) return null;

      // 检查是否完全禁用了安全配置
      if (Object.keys(execConfig).length === 0) {
        return {
          rule: 'exec-permission-control',
          severity: 'medium',
          path: 'tools.exec',
          message: '执行工具配置为空,使用默认权限',
          currentValue: '{}',
          suggestion: '建议显式配置执行权限策略'
        };
      }

      return null;
    }
  },

  // ========== 命令安全: 原生命令配置 ==========
  {
    id: 'native-commands-security',
    severity: 'low',
    check: (cfg) => {
      const nativeSkills = cfg.commands?.nativeSkills;
      if (!nativeSkills) return null;

      if (nativeSkills === 'auto') {
        return {
          rule: 'native-commands-security',
          severity: 'low',
          path: 'commands.nativeSkills',
          message: '原生技能设置为自动加载模式',
          currentValue: nativeSkills,
          suggestion: '请确认自动加载的技能来源可信'
        };
      }

      return null;
    }
  },

  // ========== 中等风险项 ==========

  {
    id: 'deny-commands-ineffective',
    severity: 'medium',
    check: (cfg) => {
      const denyCommands = cfg.gateway?.nodes?.denyCommands;
      if (!denyCommands || denyCommands.length === 0) return null;

      const invalidCommands = [
        'camera.snap', 'camera.clip', 'screen.record',
        'contacts.add', 'calendar.add', 'reminders.add', 'sms.send'
      ];

      const invalid = denyCommands.filter(cmd => invalidCommands.includes(cmd));

      if (invalid.length > 0) {
        return {
          rule: 'deny-commands-ineffective',
          severity: 'medium',
          path: 'gateway.nodes.denyCommands',
          message: `以下命令名无效: ${invalid.join(', ')}`,
          currentValue: denyCommands,
          suggestion: '使用正确的命令ID,如 canvas.present, canvas.hide 等'
        };
      }

      return null;
    }
  },

  {
    id: 'dangerous-allow-commands',
    severity: 'medium',
    check: (cfg) => {
      const allowCommands = cfg.gateway?.nodes?.allowCommands;
      if (!allowCommands || allowCommands.length === 0) return null;

      const dangerousCommands = ['system.run', 'tools.exec', 'tools.write', 'shell.execute'];
      const dangerous = allowCommands.filter(cmd => dangerousCommands.includes(cmd));

      if (dangerous.length > 0) {
        return {
          rule: 'dangerous-allow-commands',
          severity: 'medium',
          path: 'gateway.nodes.allowCommands',
          message: `白名单包含高危命令: ${dangerous.join(', ')}`,
          currentValue: allowCommands,
          suggestion: '仔细评估是否真的需要这些命令'
        };
      }

      return null;
    }
  },

  {
    id: 'webhooks-enabled',
    severity: 'medium',
    check: (cfg) => {
      const webhooks = cfg.hooks?.webhooks;
      if (webhooks?.enabled) {
        return {
          rule: 'webhooks-enabled',
          severity: 'medium',
          path: 'hooks.webhooks.enabled',
          message: 'Webhook 已启用,可能存在外部回调风险',
          currentValue: true,
          suggestion: '审查webhook目标URL是否可信'
        };
      }
      return null;
    }
  },

  {
    id: 'tailscale-enabled',
    severity: 'medium',
    check: (cfg) => {
      const ts = cfg.gateway?.tailscale;
      if (ts?.mode === 'on' || ts?.mode === 'enabled') {
        return {
          rule: 'tailscale-enabled',
          severity: 'medium',
          path: 'gateway.tailscale.mode',
          message: 'Tailscale 远程访问已启用',
          currentValue: ts.mode,
          suggestion: '确保Tailscale网络可信,设备已加密'
        };
      }
      return null;
    }
  },

  {
    id: 'tools-profile-permissive',
    severity: 'medium',
    check: (cfg) => {
      const profile = cfg.tools?.profile;
      if (profile === 'admin' || profile === 'unrestricted') {
        return {
          rule: 'tools-profile-permissive',
          severity: 'medium',
          path: 'tools.profile',
          message: `工具配置为 ${profile} 模式,权限过高`,
          currentValue: profile,
          suggestion: '使用 "coding" 或 "read-only" 等受限配置'
        };
      }
      return null;
    }
  },

  // ========== 信息提示项 ==========

  {
    id: 'version-outdated',
    severity: 'medium',
    check: (cfg) => {
      const version = cfg.meta?.lastTouchedVersion;
      if (!version) return null;

      const lastTouched = cfg.meta?.lastTouchedAt;
      if (lastTouched) {
        const days = (Date.now() - new Date(lastTouched).getTime()) / (1000 * 60 * 60 * 24);
        // 先检查 30 天（critical warning），再检查 14 天（info）
        // 注意：必须先判断大阈值，否则小阈值永远到不了
        if (days > 30) {
          return {
            rule: 'version-outdated',
            severity: 'medium',
            path: 'meta.lastTouchedVersion',
            message: `配置已超过 ${days.toFixed(0)} 天未更新,可能存在未修复的安全问题`,
            currentValue: version,
            suggestion: '建议定期检查并更新OpenClaw版本和配置,确保安全补丁及时应用'
          };
        } else if (days > 14) {
          return {
            rule: 'version-outdated',
            severity: 'low',
            path: 'meta.lastTouchedVersion',
            message: `配置已超过 ${days.toFixed(0)} 天未更新`,
            currentValue: version,
            suggestion: '建议检查是否有新版本发布'
          };
        }
      }

      return null;
    }
  },

  {
    id: 'session-scope-broad',
    severity: 'low',
    check: (cfg) => {
      const dmScope = cfg.session?.dmScope;
      if (dmScope === 'all' || dmScope === 'global') {
        return {
          rule: 'session-scope-broad',
          severity: 'low',
          path: 'session.dmScope',
          message: '会话作用域设置为全局,可能过度宽松',
          currentValue: dmScope,
          suggestion: '考虑使用 "per-channel-peer" 或 "trusted"'
        };
      }
      return null;
    }
  },

  {
    id: 'native-commands-auto',
    severity: 'low',
    check: (cfg) => {
      if (cfg.commands?.native === 'auto') {
        return {
          rule: 'native-commands-auto',
          severity: 'low',
          path: 'commands.native',
          message: '原生命令设置为自动模式',
          currentValue: 'auto',
          suggestion: '确认是否符合预期行为'
        };
      }
      return null;
    }
  }
];

/**
 * 获取OpenClaw配置文件路径
 */
export function getConfigPath(): string {
  const homeDir = os.homedir();
  return path.join(homeDir, '.openclaw', 'openclaw.json');
}

/**
 * 加载OpenClaw配置文件
 */
export function loadConfig(): OpenClawConfig | null {
  try {
    const configPath = getConfigPath();
    const content = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    return null;
  }
}

/**
 * 执行安全扫描
 */
export function scanConfig(config: OpenClawConfig): ScanResult[] {
  const results: ScanResult[] = [];

  for (const rule of securityRules) {
    try {
      const result = rule.check(config);
      if (result) {
        results.push(result);
      }
    } catch (e) {
      // 忽略单个规则的错误
    }
  }

  // 按严重程度排序
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  results.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return results;
}

/**
 * 生成扫描报告
 */
export function generateReport(results: ScanResult[]): string {
  if (results.length === 0) {
    return '✅ 未发现安全问题';
  }

  const critical = results.filter(r => r.severity === 'critical');
  const mediums  = results.filter(r => r.severity === 'medium');
  const lows     = results.filter(r => r.severity === 'low');
  const infos    = results.filter(r => r.severity === 'info');

  let report = '# OpenClaw 安全扫描报告\n\n';

  if (critical.length > 0) {
    report += '## 🔴 严重问题\n';
    for (const r of critical) {
      report += `- **${r.path}**: ${r.message}\n`;
      if (r.suggestion) report += `  - 建议: ${r.suggestion}\n`;
    }
    report += '\n';
  }

  if (mediums.length > 0) {
    report += '## 🟡 中危问题\n';
    for (const r of mediums) {
      report += `- **${r.path}**: ${r.message}\n`;
      if (r.suggestion) report += `  - 建议: ${r.suggestion}\n`;
    }
    report += '\n';
  }

  if (lows.length > 0) {
    report += '## 🟢 低危问题\n';
    for (const r of lows) {
      report += `- **${r.path}**: ${r.message}\n`;
    }
    report += '\n';
  }

  if (infos.length > 0) {
    report += '## 🔵 信息\n';
    for (const r of infos) {
      report += `- **${r.path}**: ${r.message}\n`;
    }
    report += '\n';
  }

  return report;
}

/**
 * 执行完整扫描并返回报告
 */
export function runConfigScan(): string {
  const config = loadConfig();
  if (!config) {
    return '❌ 无法加载 OpenClaw 配置文件';
  }

  const results = scanConfig(config);
  return generateReport(results);
}

/**
 * 获取扫描结果JSON(用于程序化处理)
 */
export function getScanResults(): { config: OpenClawConfig | null; results: ScanResult[] } {
  const config = loadConfig();
  if (!config) {
    return { config: null, results: [] };
  }

  return {
    config,
    results: scanConfig(config)
  };
}

/**
 * 获取完整扫描结果(包含所有规则状态)
 */
export function getFullScanResults(): { config: OpenClawConfig | null; results: FullScanResult[] } {
  const config = loadConfig();
  if (!config) {
    return { config: null, results: [] };
  }

  // 先执行检查获取问题项
  const issues = scanConfig(config);
  const issueMap = new Map(issues.map(i => [i.rule, i]));

  // 构建所有规则的状态
  const fullResults: FullScanResult[] = [];

  for (const rule of securityRules) {
    const issue = issueMap.get(rule.id);
    if (issue) {
      fullResults.push({
        ...issue,
        status: 'fail'
      });
    } else {
      // 生成通过时的消息
      const passMessage = getPassMessage(rule.id);
      fullResults.push({
        rule: rule.id,
        severity: rule.severity,
        path: getRulePath(rule.id),
        status: 'pass',
        message: passMessage
      });
    }
  }

  return {
    config,
    results: fullResults
  };
}

/**
 * 获取规则对应的配置路径
 */
function getRulePath(ruleId: string): string {
  const pathMap: Record<string, string> = {
    // 凭证与密钥安全
    'hardcoded-secrets': 'models.providers.*.apiKey',
    // 配置安全
    'dangerous-flags': 'gateway.* / tools.*',
    'env-injection': 'config (环境变量引用)',
    // 凭证安全
    'token-entropy': 'gateway.auth.token',
    'token-weak-pattern': 'gateway.auth.token',
    'rate-limiting': 'gateway.rateLimit',
    // 会话安全
    'session-ttl': 'session.timeout',
    // 网络安全
    'browser-control-port': 'gateway.port',
    'tls-required': 'gateway.tls',
    'cors-wildcard': 'gateway.cors.origins',
    // port-exposure: 已合并至 gateway-bind-exposed
    'tailscale-security': 'gateway.tailscale',
    // 供应链安全 (以下规则需运行时检查，静态扫描无法覆盖)
    // 数据防护
    'private-key-leak': 'models.providers.*.baseUrl',
    'mnemonic-leak': 'config (加密货币密钥)',
    // 扩展: 网关与插件安全
    'gateway-bind-exposed': 'gateway.bind',
    'plugins-allow-missing': 'plugins.allow',
    'untrusted-proxy-config': 'gateway.trustedProxies',
    'gateway-auth-mode-insecure': 'gateway.auth.mode',
    'gateway-auth-disabled': 'gateway.auth.mode / gateway.auth.token',
    'api-key-exposed': 'models.providers.*.apiKey',
    'workspace-not-restricted': 'agents.defaults.workspace',
    'log-level-verbose': 'log.level',
    'log-include-sensitive': 'log.includeSensitive',
    'session-timeout-missing': 'session.timeout',
    'mcp-untrusted-commands': 'mcp.entries.*.command',
    'plugin-source-untrusted': 'plugins.installs.*.source',
    'webhook-url-insecure': 'hooks.webhooks.entries.*.url',
    'default-port-exposed': 'gateway.port',
    'exec-security-disabled': 'tools.exec.security',
    'write-no-restrictions': 'tools.write.allowedPaths',
    'tailscale-remote-url-exposure': 'gateway.tailscale',
    'unverified-plugin-source': 'plugins.entries.*',
    'deny-commands-ineffective': 'gateway.nodes.denyCommands',
    'dangerous-allow-commands': 'gateway.nodes.allowCommands',
    'webhooks-enabled': 'hooks.webhooks.enabled',
    // 扩展: 综合安全评估
    'tailscale-enabled': 'gateway.tailscale.mode',
    'tools-profile-permissive': 'tools.profile',
    'version-outdated': 'meta.lastTouchedVersion',
    'session-scope-broad': 'session.dmScope',
    'native-commands-auto': 'commands.native',
    // 新增第四批: 扩展安全评估
    'web-search-safety': 'tools.web.search',
    'owner-display-info-leak': 'commands.ownerDisplay',
    'internal-hooks-security': 'hooks.internal.entries',
    'session-isolation': 'session.dmScope',
    'api-endpoint-safety': 'models.providers.*.baseUrl',
    'agent-defaults-security': 'agents.defaults',
    'exec-permission-control': 'tools.exec',
    'native-commands-security': 'commands.nativeSkills',
  };
  return pathMap[ruleId] || '';
}

/**
 * 获取规则通过时的默认消息
 */
function getPassMessage(ruleId: string): string {
  const messageMap: Record<string, string> = {
    // 凭证与密钥安全
    'hardcoded-secrets': '未检测到硬编码密钥',
    // 配置安全
    'dangerous-flags': '无危险配置标志',
    'env-injection': '无环境变量注入风险',
    // 凭证安全
    'token-entropy': 'Token熵值符合要求 (>=40字符)',
    'token-weak-pattern': 'Token无弱模式',
    'rate-limiting': '速率限制已配置',
    // 会话安全
    'session-ttl': 'Session超时配置合理',
    // 网络安全
    'browser-control-port': '浏览器控制端口安全',
    'tls-required': 'TLS配置正常',
    'cors-wildcard': 'CORS配置安全',
    // port-exposure: 已合并至 gateway-bind-exposed
    'tailscale-security': 'Tailscale安全配置',
    // 供应链安全
    // 数据防护
    'private-key-leak': '无私钥泄露',
    'mnemonic-leak': '无助记词泄露',
    // 扩展: 网关与插件安全
    'gateway-bind-exposed': 'Gateway未暴露到公网',
    'plugins-allow-missing': '插件白名单已配置',
    'untrusted-proxy-config': '代理信任配置正常',
    'gateway-auth-mode-insecure': '认证模式安全',
    'gateway-auth-disabled': '认证已正确配置',
    'api-key-exposed': 'API Key配置正常',
    'workspace-not-restricted': '工作区已限制',
    'log-level-verbose': '日志级别安全',
    'log-include-sensitive': '日志未包含敏感信息',
    'session-timeout-missing': '会话超时已配置',
    'mcp-untrusted-commands': 'MCP命令安全',
    'plugin-source-untrusted': '插件来源安全',
    'webhook-url-insecure': 'Webhook使用HTTPS',
    'default-port-exposed': '端口配置正常',
    'exec-security-disabled': '执行安全已启用',
    'write-no-restrictions': '写入路径已限制',
    'tailscale-remote-url-exposure': 'Tailscale认证已配置',
    'unverified-plugin-source': '插件来源已验证',
    'deny-commands-ineffective': '命令黑名单配置正确',
    'dangerous-allow-commands': '命令白名单安全',
    'webhooks-enabled': 'Webhook未启用或已审查',
    // 扩展: 综合安全评估
    'tailscale-enabled': 'Tailscale未启用或已审查',
    'tools-profile-permissive': '工具配置安全',
    'version-outdated': '配置为最新版本',
    'session-scope-broad': '会话作用域安全',
    'native-commands-auto': '原生命令配置正常',
    // 新增第四批: 扩展安全评估
    'web-search-safety': 'Web搜索配置安全',
    'owner-display-info-leak': '所有者显示配置安全',
    'internal-hooks-security': '内部钩子配置安全',
    'session-isolation': '会话隔离配置正确',
    'api-endpoint-safety': 'API端点配置安全',
    // gateway-mode-security: 已移除
    'agent-defaults-security': '代理默认配置合理',
    'exec-permission-control': '执行权限配置正确',
    'native-commands-security': '原生技能配置安全',
  };
  return messageMap[ruleId] || '检查通过';
}

// ─────────────────────────────────────────────────────────────
// 运行时检查（需文件系统访问或执行外部命令，不适合静态规则）
// 由 register() 启动时调用，结果格式与 ScanResult 一致
// ─────────────────────────────────────────────────────────────

const INJECTION_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // 忽略/遗忘指令类
  { pattern: /ignore[\s\S]*previous[\s\S]*instruction/i, name: '忽略先前指令' },
  { pattern: /disregard[\s\S]*all[\s\S]*previous/i, name: '无视所有先前指令' },
  { pattern: /forget[\s\S]*guideline/i, name: '遗忘指南指令' },
  { pattern: /disregard[\s\S]*system/i, name: '无视系统指令' },
  { pattern: /ignore[\s\S]*all[\s\S]*previous/i, name: '忽略所有先前内容' },
  // 越狱/角色扮演类
  { pattern: /jailbreak/i, name: '越狱模式' },
  { pattern: /DAN mode/i, name: 'DAN 越狱模式' },
  { pattern: /you are now[\s\S]*(?:a|an)[\s\S]*/i, name: '身份冒充指令' },
  { pattern: /role[\s\S]*play[\s\S]*as[\s\S]*developer/i, name: '开发者角色扮演' },
  { pattern: /pretend[\s\S]*you[\s\S]*are[\s\S]*a/i, name: '身份扮演指令' },
  { pattern: /act[\s\S]*as[\s\S]*if[\s\S]*you[\s\S]*were/i, name: '模拟身份指令' },
  { pattern: /you can[\s\S]*now[\s\S]*do[\s\S]*anything/i, name: '无限制授权指令' },
  { pattern: /AIM[\s\S]*breaker/i, name: 'AIM越狱' },
  { pattern: /Hacking[\s\S]*challenge/i, name: '黑客挑战模式' },
  { pattern: /Developer[\s\S]*mode/i, name: '开发者模式' },
  { pattern: /priviledge[\s\S]*escalation/i, name: '权限提升指令' },
  // 绕过安全类
  { pattern: /bypass[\s\S]*security/i, name: '绕过安全检查' },
  { pattern: /disable[\s\S]*safety[\s\S]*check/i, name: '禁用安全检查' },
  { pattern: /override[\s\S]*policy/i, name: '覆盖策略指令' },
  { pattern: /no restriction/i, name: '解除限制指令' },
  { pattern: /remove[\s\S]*filter/i, name: '移除过滤器' },
  { pattern: /disable[\s\S]*content[\s\S]*policy/i, name: '禁用内容策略' },
  // 提权/管理员类
  { pattern: /sudo[\s\S]*mode/i, name: '提权模式' },
  { pattern: /admin[\s\S]*privilege/i, name: '管理员权限请求' },
  { pattern: /root[\s\S]*access/i, name: 'Root访问请求' },
  { pattern: /elevated[\s\S]*permission/i, name: '提升权限请求' },
  // 无限制访问类
  { pattern: /unrestricted access/i, name: '无限制访问指令' },
  { pattern: /unfiltered/i, name: '无过滤指令' },
  { pattern: /no[\s\S]*limit/i, name: '无限指令' },
  { pattern: /all[\s\S]*capability/i, name: '全能力授权' },
  // 系统提示词替换类
  { pattern: /set[\s\S]*system[\s\S]*prompt/i, name: '替换系统提示词' },
  { pattern: /new[\s\S]*system[\s\S]*instruction/i, name: '新系统指令' },
  { pattern: /override[\s\S]*system[\s\S]*prompt/i, name: '覆盖系统提示词' },
  { pattern: /system[\s\S]*prompt[\s\S]*injection/i, name: '系统提示词注入' },
  // 编码/混淆逃逸类
  { pattern: /encoded[\s\S]*instruction/i, name: '编码指令' },
  { pattern: /decode[\s\S]*this[\s\S]*message/i, name: '解码此消息' },
  { pattern: /translate[\s\S]*from[\s\S]*base64/i, name: 'Base64翻译指令' },
  { pattern: /execute[\s\S]*hidden[\s\S]*command/i, name: '执行隐藏命令' },
  // 提示词注入攻击类
  { pattern: /\b(injection|inject)[\s\S]*(prompt|instruction)/i, name: '提示词注入' },
  { pattern: /forget[\s\S]*your[\s\S]*rules/i, name: '遗忘规则指令' },
  { pattern: /discard[\s\S]*your[\s\S]*guideline/i, name: '丢弃准则指令' },
  { pattern: /you[\s\S]*only[\s\S]*follow[\s\S]*my[\s\S]*instruction/i, name: '仅跟随我指令' },
  // 对齐规避类（Alignment Evasions）
  { pattern: /harmful[\s\S]*content[\s\S]*allowed/i, name: '有害内容允许' },
  { pattern: /not[\s\S]*safe[\s\S]*for[\s\S]*work/i, name: 'NSFW内容请求' },
  { pattern: /political[\s\S]*content[\s\S]*allowed/i, name: '政治内容请求' },
];

/**
 * SOUL.md 提示注入检测
 * 读取 workspace 下所有 SOUL.md 文件，检测恶意指令注入
 */
export function checkSoulMdInjection(): ScanResult[] {
  const results: ScanResult[] = [];
  const config = loadConfig();
  if (!config) return results;

  const workspace = config.agents?.defaults?.workspace;
  if (!workspace) return results;

  // 搜索 SOUL.md 文件（workspace + skills 目录）
  const searchPaths = [workspace];
  const skillsBuiltin = path.join(os.homedir(), '.npm-global/lib/node_modules/openclaw/skills');
  const skillsWorkspace = path.join(workspace, 'skills');
  searchPaths.push(skillsBuiltin, skillsWorkspace);

  const soulFiles: string[] = [];
  for (const basePath of searchPaths) {
    try {
      const found = findFiles(basePath, 'SOUL.md', 5);
      soulFiles.push(...found);
    } catch {
      // ignore access errors
    }
  }

  if (soulFiles.length === 0) {
    // 无 SOUL.md 文件，跳过
    return results;
  }

  let hasInjection = false;
  for (const filePath of soulFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      for (const { pattern, name } of INJECTION_PATTERNS) {
        if (pattern.test(content)) {
          results.push({
            rule: 'soul-md-injection',
            severity: 'critical',
            path: filePath,
            message: `SOUL.md 检测到提示注入模式: ${name}`,
            currentValue: path.basename(filePath),
            suggestion: '从 SOUL.md 中移除包含越权指令、越狱提示的内容'
          });
          hasInjection = true;
          // 不 break：每个文件的每个匹配模式都需要记录
        }
      }
    } catch {
      // ignore read errors
    }
  }

  return results;
}

/**
 * npm 依赖漏洞扫描
 * 在 openclaw 全局安装目录执行 npm audit --json，解析漏洞数量
 */
export function checkNpmAudit(): ScanResult[] {
  const results: ScanResult[] = [];

  // 查找 openclaw package.json
  const possiblePaths = [
    path.join(os.homedir(), '.npm-global/lib/node_modules/openclaw/package.json'),
    '/usr/lib/node_modules/openclaw/package.json',
    '/usr/local/lib/node_modules/openclaw/package.json',
  ];

  let pkgJsonPath: string | null = null;
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      pkgJsonPath = p;
      break;
    }
  }

  if (!pkgJsonPath) {
    return results;
  }

  try {
    const { execSync } = require('child_process');
    const auditOutput = execSync(
      `cd "${path.dirname(pkgJsonPath)}" && npm audit --json 2>/dev/null`,
      { encoding: 'utf8', timeout: 30000 }
    );

    interface NpmAuditMetadata { critical: number; high: number; medium: number; low: number; }
    interface NpmAuditResult { metadata?: { vulnerabilities?: NpmAuditMetadata } }

    let parsed: NpmAuditResult = {};
    try {
      parsed = JSON.parse(auditOutput);
    } catch {
      // ignore parse errors
    }

    const vulns = parsed?.metadata?.vulnerabilities;
    if (!vulns) return results;

    const { critical = 0, high = 0, medium = 0, low = 0 } = vulns;
    const total = critical + high + medium + low;

    if (total === 0) return results;

    if (critical > 0) {
      results.push({
        rule: 'npm-audit',
        severity: 'critical',
        path: pkgJsonPath,
        message: `npm audit: 发现 ${critical} 个 CRITICAL / ${high} 个 HIGH 漏洞`,
        currentValue: `critical:${critical} high:${high} medium:${medium} low:${low}`,
        suggestion: `执行 npm audit fix 修复，或人工审查: cd "${path.dirname(pkgJsonPath)}" && npm audit`
      });
    } else if (high > 0) {
      results.push({
        rule: 'npm-audit',
        severity: 'medium',
        path: pkgJsonPath,
        message: `npm audit: 发现 ${high} 个 HIGH 漏洞`,
        currentValue: `high:${high} medium:${medium} low:${low}`,
        suggestion: `执行 npm audit fix 修复: cd "${path.dirname(pkgJsonPath)}" && npm audit fix`
      });
    } else {
      results.push({
        rule: 'npm-audit',
        severity: 'medium',
        path: pkgJsonPath,
        message: `npm audit: 发现 ${medium} 个中危 / ${low} 个低危漏洞`,
        currentValue: `medium:${medium} low:${low}`,
        suggestion: `建议执行 npm audit review 查看详情`
      });
    }
  } catch (error) {
    // npm audit 不可用或执行失败，不报错静默跳过
  }

  return results;
}

/**
 * Node.js 版本 EOL 检测
 * 检测当前 Node.js 版本是否已停止维护
 */
export function checkNodeEol(): ScanResult[] {
  const results: ScanResult[] = [];

  try {
    const { execSync } = require('child_process');
    const versionOutput = execSync('node --version', { encoding: 'utf8', timeout: 5000 });
    const versionStr = versionOutput.trim().replace(/^v/, '');
    const major = parseInt(versionStr.split('.')[0], 10);

    // EOL 版本: <=18 (LTS 结束), 19/21 (非 LTS 奇数版已 EOL)
    // v20 LTS reaches EOL April 2026 → 接近 EOL 报 warning
    if (major <= 18 || major === 19 || major === 21) {
      results.push({
        rule: 'node-eol',
        severity: 'critical',
        path: 'runtime',
        message: `Node.js v${versionStr} 已停止维护，无安全更新`,
        currentValue: `v${versionStr}`,
        suggestion: '请升级至 Node.js v22 (LTS)'
      });
    } else if (major === 20) {
      results.push({
        rule: 'node-eol',
        severity: 'medium',
        path: 'runtime',
        message: `Node.js v${versionStr} 将于 2026 年 4 月 EOL，建议提前升级`,
        currentValue: `v${versionStr}`,
        suggestion: '请升级至 Node.js v22 (LTS)'
      });
    }
    // v22+ = OK，不报告
  } catch {
    // node 不可用，静默跳过
  }

  return results;
}

// ─────────────────────────────────────────────────────────────
// 辅助函数
// ─────────────────────────────────────────────────────────────

function findFiles(dir: string, filename: string, maxDepth: number, currentDepth = 0): string[] {
  const results: string[] = [];
  if (currentDepth > maxDepth) return results;
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isFile() && entry.name === filename) {
        results.push(fullPath);
      } else if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
        results.push(...findFiles(fullPath, filename, maxDepth, currentDepth + 1));
      }
    }
  } catch {
    // ignore access errors
  }
  return results;
}
