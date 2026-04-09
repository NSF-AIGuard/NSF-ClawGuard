import type { OpenClawPluginApi } from "./types.js";
import { LOG_PREFIX } from "./constants.js";
import { getLogger } from "./logger.js";

const DANGEROUS_PATTERNS: Array<{
  pattern: RegExp;
  name: string;
  severity: string;
}> = [
  {
    pattern:
      /\bruby\s+(-e|--eval)\s+.*\b(system\s*\(|exec\s*\(|File\.delete|FileUtils\.rm_rf)/,
    name: "ruby -e with dangerous system call",
    severity: "critical",
  },
  {
    pattern:
      /\bruby\s+(-e|--eval)\s+.*\b(TCPServer|TCPSocket|Socket\.new|UDPSocket|UNIXServer)\b/,
    name: "ruby -e with network socket/server",
    severity: "critical",
  },
  {
    pattern: /bash\s+-i\s+>&?\s*\/dev\/tcp\//,
    name: "bash reverse shell via /dev/tcp",
    severity: "critical",
  },
  {
    pattern: /\bnc\s+.*-e\s+/,
    name: "netcat reverse shell (nc -e)",
    severity: "critical",
  },
  {
    pattern: /\bncat\s+.*--(?:exec|sh-exec)\b/,
    name: "ncat reverse shell (--exec/--sh-exec)",
    severity: "critical",
  },
  {
    pattern: /\bsocat\b.*\bexec\b/i,
    name: "socat exec (reverse shell / command relay)",
    severity: "critical",
  },
  {
    pattern: /awk\s+['"]BEGIN.*\/inet\/tcp\//i,
    name: "awk reverse shell via /inet/tcp",
    severity: "critical",
  },
  {
    pattern: /exec\s+.*\/dev\/tcp\//i,
    name: "exec reverse shell via /dev/tcp",
    severity: "critical",
  },
  {
    pattern: /mkfifo.*\/bin\/sh.*-i.*openssl.*-connect/i,
    name: "mkfifo reverse shell with openssl",
    severity: "critical",
  },
  {
    pattern:
      /python[23]?\s+(-c|--command)\s+.*import\s+(urllib|requests|socket)/i,
    name: "python -c with network module import",
    severity: "critical",
  },
  {
    pattern: /perl\s+(-e|--eval)\s+.*use\s+Socket.*bash/i,
    name: "perl -e reverse shell with Socket",
    severity: "critical",
  },
  {
    pattern: /php\s+(-r|--run)\s+.*fsockopen.*bash/i,
    name: "php -r reverse shell with fsockopen",
    severity: "critical",
  },
  {
    pattern: /ruby\s+(-e|--eval)\s+.*Socket\.new/i,
    name: "ruby -e reverse shell with Socket.new",
    severity: "critical",
  },
  {
    pattern: /socat.*tcp-connect.*:/i,
    name: "socat reverse shell connection",
    severity: "critical",
  },
  {
    pattern: /\bgdb\s+.*-p\s+\d+/,
    name: "gdb process attach (process injection)",
    severity: "critical",
  },
  {
    pattern:
      /rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|--recursive\s+)\/(?!tmp\/|home\/clawdbot\/)/,
    name: "rm -rf on root-level system path",
    severity: "critical",
  },
  {
    pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|--recursive\s+)~\//,
    name: "rm -rf on home directory",
    severity: "critical",
  },
  {
    pattern: /\b(?:curl|wget)\b.*&&.*chmod\s+\+x\b/,
    name: "download + chmod +x chain (download and execute)",
    severity: "critical",
  },
  {
    pattern: /\b(?:curl|wget)\b.*&&.*\bsh\b/,
    name: "download + shell execute chain",
    severity: "critical",
  },
  {
    pattern: /\b(?:curl|wget)\b.*&&.*\bbash\b/,
    name: "download + bash execute chain",
    severity: "critical",
  },
  { pattern: /mkfs\b/, name: "filesystem format (mkfs)", severity: "critical" },
  {
    pattern: /dd\s+if=.*of=\/dev\//,
    name: "raw disk write (dd)",
    severity: "critical",
  },
  {
    pattern: />\s*\/dev\/sd/,
    name: "redirect to block device",
    severity: "critical",
  },
  {
    pattern: /(?:tee|>>?)\s*\/etc\/(?:passwd|shadow|sudoers)/,
    name: "write to system auth file",
    severity: "critical",
  },
  {
    pattern: /sed\s+-i.*\/etc\/(?:passwd|shadow|sudoers)/,
    name: "in-place edit of system auth file",
    severity: "critical",
  },
  {
    pattern: /\b(?:shutdown|reboot)\b/,
    name: "system shutdown/reboot",
    severity: "critical",
  },
  {
    pattern: /\binit\s+[06]\b/,
    name: "system halt/reboot (init)",
    severity: "critical",
  },
  {
    pattern: /systemctl\s+(?:stop|disable)\s+sshd/,
    name: "disable SSH (remote lockout)",
    severity: "critical",
  },
  {
    pattern: /\/bin\/rm\s+(-[a-zA-Z]*r[a-zA-Z]*)\s+/,
    name: "rm via absolute path",
    severity: "critical",
  },
  {
    pattern: /\/usr\/bin\/rm\s+(-[a-zA-Z]*r[a-zA-Z]*)\s+/,
    name: "rm via absolute path",
    severity: "critical",
  },
  {
    pattern: /\beval\s+/,
    name: "eval execution (arbitrary code)",
    severity: "critical",
  },
  {
    pattern:
      /\bnode\s+(-e|--eval)\s+.*\b(child_process|\.exec\s*\(|\.spawn\s*\(|\.execSync\s*\(|\.spawnSync\s*\()/,
    name: "node -e with subprocess execution",
    severity: "critical",
  },
  {
    pattern:
      /\bnode\s+(-e|--eval)\s+.*\b(unlinkSync|rmdirSync|rmSync|writeFileSync)\s*\(\s*['"]\/(?!tmp\/)/,
    name: "node -e with dangerous fs op on system path",
    severity: "critical",
  },
  {
    pattern:
      /\bnode\s+(-e|--eval)\s+.*(net\.createServer|http\.createServer|https\.createServer|dgram\.createSocket|tls\.createServer)/,
    name: "node -e with network server creation",
    severity: "critical",
  },
  {
    pattern:
      /\bnode\s+(-e|--eval)\s+.*\b(vm\.runInNewContext|vm\.runInThisContext)\b/,
    name: "node -e with VM sandbox escape",
    severity: "critical",
  },
  {
    pattern: /\bnode\s+(-e|--eval)\s+.*\beval\s*\(.*\brequire\b/,
    name: "node -e with eval+require (code injection)",
    severity: "critical",
  },
  {
    pattern:
      /\bpython[23]?\s+(-c|--command)\s+.*\b(os\.system|subprocess|shutil\.rmtree|os\.remove|os\.unlink)\b/,
    name: "python -c with dangerous system call",
    severity: "critical",
  },
  {
    pattern: /\bpython[23]?\s+(-c|--command)\s+.*\bopen\s*\(\s*['"]\/etc\//,
    name: "python -c writing to system config",
    severity: "critical",
  },
  {
    pattern:
      /\bpython[23]?\s+(-c|--command)\s+.*\b(socket\.socket|http\.server|socketserver)\b/,
    name: "python -c with network server/socket",
    severity: "critical",
  },
  {
    pattern:
      /\bpython[23]?\s+(-c|--command)\s+.*__import__\s*\(\s*['"]os['"]\s*\)/,
    name: "python -c with __import__('os') (stealth import)",
    severity: "critical",
  },
  {
    pattern:
      /\bpython[23]?\s+(-c|--command)\s+.*\b(exec|eval)\s*\(.*\b(os\.|subprocess|shutil|socket)\b/,
    name: "python -c with exec/eval containing dangerous module",
    severity: "critical",
  },
  {
    pattern:
      /\bperl\s+(-e|--eval)\s+.*\b(system\s*\(|exec\s*\(|unlink\s+['"]\/(?!tmp\/))/,
    name: "perl -e with dangerous system call",
    severity: "critical",
  },
  {
    pattern: /\bperl\s+(-e|--eval)\s+.*\bIO::Socket\b/,
    name: "perl -e with network socket (IO::Socket)",
    severity: "critical",
  },
  {
    pattern: /\bstrace\s+.*-p\s+\d+/,
    name: "strace process attach (process inspection)",
    severity: "critical",
  },
  {
    pattern: /\bptrace\b/,
    name: "ptrace (process injection/tracing)",
    severity: "critical",
  },
  {
    pattern: /\b(?:insmod|modprobe|rmmod)\s+/,
    name: "kernel module manipulation",
    severity: "critical",
  },
  {
    pattern: /insmod\s+[\w.]+\.ko/i,
    name: "kernel module insertion (rootkit)",
    severity: "critical",
  },
  {
    pattern: /xargs\s+.*\brm\b/,
    name: "xargs rm (indirect deletion)",
    severity: "critical",
  },
  {
    pattern: /xargs\s+.*\bchmod\b/,
    name: "xargs chmod (indirect permission change)",
    severity: "critical",
  },
  {
    pattern: /find\s+.*-exec\s+.*\brm\b/,
    name: "find -exec rm (indirect deletion)",
    severity: "critical",
  },
  {
    pattern: /find\s+.*-delete\b/,
    name: "find -delete (bulk deletion)",
    severity: "critical",
  },
  {
    pattern: /[`|;]\s*telnet\s+/i,
    name: "telnet command injection",
    severity: "critical",
  },
  {
    pattern: /[`|;]\s*busybox\b/i,
    name: "busybox command injection",
    severity: "critical",
  },
  {
    pattern: /[`|;]\s*powershell\s+\(new-object/i,
    name: "PowerShell command injection with new-object",
    severity: "critical",
  },
  {
    pattern: /\|\s*rev\s*\|/i,
    name: "command reversal obfuscation (pipe to rev)",
    severity: "critical",
  },
  {
    pattern:
      /<!--#(echo|exec|include|printenv|set|flastmod|fsize)\s+(cmd|file|virtual|var)\s*=/i,
    name: "SSI injection (server-side include)",
    severity: "critical",
  },
  {
    pattern:
      /escapeshellarg\s*\(\s*(gzcompress|gzuncompress|gzpassthru|gzinflate|bzcompress|bzdecompress|base64_decode)/i,
    name: "PHP escapeshellarg with compression/encoding bypass",
    severity: "critical",
  },
  {
    pattern:
      /escapeshellcmd\s*\(\s*(gzcompress|gzuncompress|gzpassthru|gzinflate|bzcompress|bzdecompress|base64_decode)/i,
    name: "PHP escapeshellcmd with compression/encoding bypass",
    severity: "critical",
  },
  {
    pattern:
      /\bpassthru\s*\(\s*(gzcompress|gzuncompress|gzpassthru|gzinflate|bzcompress|bzdecompress|base64_decode)/i,
    name: "PHP passthru with compression/encoding bypass",
    severity: "critical",
  },
  {
    pattern:
      /\bproc_open\s*\(\s*(gzcompress|gzuncompress|gzpassthru|gzinflate|bzcompress|bzdecompress|base64_decode)/i,
    name: "PHP proc_open with compression/encoding bypass",
    severity: "critical",
  },
  {
    pattern:
      /\bsystem\s*\(\s*(gzcompress|gzuncompress|gzpassthru|gzinflate|bzcompress|bzdecompress|base64_decode)/i,
    name: "PHP system with compression/encoding bypass",
    severity: "critical",
  },
  {
    pattern:
      /\beval\s*\(\s*(gzcompress|gzuncompress|gzpassthru|gzinflate|bzcompress|bzdecompress|base64_decode)/i,
    name: "PHP eval with compression/encoding bypass",
    severity: "critical",
  },
  {
    pattern: /BadPotato\.exe\s+whoami/i,
    name: "BadPotato privilege escalation tool",
    severity: "critical",
  },
  {
    pattern: /SweetPotato(\.exe)?\s+-a\s+["']?whoami/i,
    name: "SweetPotato privilege escalation tool",
    severity: "critical",
  },
  {
    pattern: /JuicyPotato(\.exe)?\s+-a\s+["']?whoami/i,
    name: "JuicyPotato privilege escalation tool",
    severity: "critical",
  },
  {
    pattern: /EfsPotato(\.exe)?\s+whoami/i,
    name: "EfsPotato privilege escalation tool",
    severity: "critical",
  },
  {
    pattern: /procdump(\.exe)?\s+-ma\s+lsass/i,
    name: "procdump LSASS memory dump (credential theft)",
    severity: "critical",
  },
  {
    pattern: /Sqldumper(\.exe)?\s+ProcessID/i,
    name: "Sqldumper process dump (credential theft)",
    severity: "critical",
  },
  {
    pattern: /rundll32\.exe\s+comsvcs\.dll.*MiniDump/i,
    name: "comsvcs.dll LSASS dump (credential theft)",
    severity: "critical",
  },
  {
    pattern: /C:\\windows\\System32\\comsvcs\.dll/i,
    name: "comsvcs.dll usage (potential credential dump)",
    severity: "critical",
  },
  {
    pattern: /reg\s+save\s+HKLM/i,
    name: "registry hive dump (credential theft)",
    severity: "critical",
  },
  {
    pattern: /REG\s+(ADD|DELETE|QUERY|LOAD|UNLOAD|SAVE|RESTORE)\s/i,
    name: "registry modification (persistence)",
    severity: "critical",
  },
  {
    pattern: /wevtutil\s+(cl|sl|el|epl|gp)\s/i,
    name: "Windows event log manipulation",
    severity: "critical",
  },
  {
    pattern: /wevtutil\s+qe\s+Security/i,
    name: "Windows Security event log query",
    severity: "critical",
  },
  {
    pattern: /EventCleaner(\.exe)?\s+(suspend|normal)/i,
    name: "EventCleaner anti-forensics tool",
    severity: "critical",
  },
  {
    pattern: /wx-dump-key-v0\.1\.0(\.exe)?\s+zmkm/i,
    name: "wx-dump-key credential dumping tool",
    severity: "critical",
  },
  {
    pattern: /base64\s+(-d|--decode).*\|\s*(?:bash|sh|zsh|dash)/,
    name: "base64 decoded pipe to shell",
    severity: "critical",
  },
  {
    pattern: /\bcurl\b.*\|\s*(?:bash|sh|zsh|dash|python|perl|ruby)/,
    name: "curl pipe to shell (remote code execution)",
    severity: "critical",
  },
  {
    pattern: /\bwget\b.*\|\s*(?:bash|sh|zsh|dash|python|perl|ruby)/,
    name: "wget pipe to shell (remote code execution)",
    severity: "critical",
  },
  {
    pattern: /\becho\b.*\|\s*(?:bash|sh|zsh|dash)\b/,
    name: "echo pipe to shell",
    severity: "critical",
  },
  {
    pattern: /\bprintf\b.*\|\s*(?:bash|sh|zsh|dash)\b/,
    name: "printf pipe to shell",
    severity: "critical",
  },
  {
    pattern: /\|\s*(?:bash|sh|zsh|dash)\s*$/,
    name: "pipe to shell interpreter",
    severity: "critical",
  },
  {
    pattern: /\|\s*(?:bash|sh|zsh|dash)\s*[;&|]/,
    name: "pipe to shell interpreter",
    severity: "critical",
  },
  {
    pattern: /\bbase64\b.*\|\s*(?:bash|sh|zsh|dash)/,
    name: "base64 pipe to shell (encoding bypass)",
    severity: "critical",
  },
  {
    pattern: /\|.*\bcrontab\s+-\s*$/,
    name: "pipe to crontab stdin (crontab injection)",
    severity: "critical",
  },
  {
    pattern: /\becho\b.*\|\s*crontab\b/,
    name: "echo pipe to crontab (crontab injection)",
    severity: "critical",
  },
];

const DANGEROUS_PATH_PATTERNS: Array<{
  pattern: RegExp;
  name: string;
  severity: string;
}> = [
  {
    pattern: /^\/etc\/(?:passwd|shadow|sudoers)$/,
    name: "write to system auth file",
    severity: "critical",
  },
  {
    pattern: /^\/boot\//,
    name: "write to boot partition",
    severity: "critical",
  },
];

interface DangerMatch {
  pattern: RegExp;
  name: string;
  severity: string;
}

export function checkCommandSafety(
  command: string,
  filePath?: string,
): DangerMatch[] {
  const matched: DangerMatch[] = [];

  for (const item of DANGEROUS_PATTERNS) {
    if (item.pattern.test(command)) {
      matched.push(item);
    }
  }

  if (filePath) {
    for (const item of DANGEROUS_PATH_PATTERNS) {
      if (item.pattern.test(filePath)) {
        matched.push(item);
      }
    }
  }

  return matched;
}

export function checkPathSafety(filePath: string): DangerMatch[] {
  const matched: DangerMatch[] = [];

  for (const item of DANGEROUS_PATH_PATTERNS) {
    if (item.pattern.test(filePath)) {
      matched.push(item);
    }
  }

  return matched;
}

export function logDangerousCommand(
  api: OpenClawPluginApi,
  toolName: string,
  command: string,
  matches: DangerMatch[],
): void {
  const logger = getLogger()!;
  const severityEmoji = matches.some((m) => m.severity === "critical")
    ? "🔴"
    : "🟠";
  const names = matches.map((m) => m.name).join(", ");
  logger.info(`${severityEmoji} ⚠️ 检测到危险命令 [${toolName}]: ${names}`);
  logger.info(
    `命令: ${command.substring(0, 100)}${command.length > 100 ? "..." : ""}`,
  );
}
