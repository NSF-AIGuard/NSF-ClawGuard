import type {
  OpenClawPluginApi,
  Logger,
  OpenClawPluginCliContext,
} from "../types.js";
import checkCommadHandler from "./check.js";
import { currentPluginRoot } from '../utils.js'
import path from "path";
import { runConfigScan, getScanResults, getFullScanResults } from "../config-scanner.js";
import type  FormData  from "form-data";

function registerLmSecurityCli(options: OpenClawPluginCliContext & {uploadDetectFile: (file: FormData) => Promise<void>}) {
  const { program, logger,uploadDetectFile } = options;
  const root = program
    .command("lmsecurity")
    .description("lm-security plugin commands")
  
  // 上传检测命令
  root
    .command("check")
    .description("Collect and upload skills/plugins for security detection")
    .action(() => {
      const root = currentPluginRoot();
      const openclawPath = path.join(root, "..", "..", "..", "..");
      checkCommadHandler(logger,openclawPath,uploadDetectFile);
    });
  
  // 配置扫描命令 - 仅显示问题项
  root
    .command("config-scan")
    .description("Scan OpenClaw configuration for security issues")
    .option("-j, --json", "Output results in JSON format")
    .action((options: { json?: boolean }) => {
      const { json } = options;
      const { results } = getScanResults();
      
      if (json) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        console.log(runConfigScan());
      }
    });
  
  // 配置扫描命令 - 显示所有规则项
  root
    .command("config-scan-full")
    .description("Scan OpenClaw configuration - show all rules")
    .option("-j, --json", "Output results in JSON format")
    .action((options: { json?: boolean }) => {
      const { json } = options;
      const { results, config } = getFullScanResults();
      
      if (json) {
        console.log(JSON.stringify({
          scanTime: new Date().toISOString(),
          totalRules: results.length,
          passCount: results.filter(r => r.status === 'pass').length,
          failCount: results.filter(r => r.status === 'fail').length,
          results: results
        }, null, 2));
      } else {
        // 格式化输出
        const pass = results.filter(r => r.status === 'pass');
        const fail = results.filter(r => r.status === 'fail');
        
        console.log('# OpenClaw 完整配置安全扫描报告\n');
        console.log(`扫描时间: ${new Date().toISOString()}`);
        console.log(`总规则数: ${results.length}`);
        console.log(`✅ 通过: ${pass.length}`);
        console.log(`❌ 失败: ${fail.length}\n`);
        
        if (fail.length > 0) {
          console.log('## ❌ 失败项目\n');
          for (const r of fail) {
            const emoji = r.severity === 'critical' ? '🔴' : r.severity === 'high' ? '🟠' : r.severity === 'medium' ? '🟡' : r.severity === 'low' ? '🟢' : '🔵';
            console.log(`${emoji} [${r.severity.toUpperCase()}] ${r.path}`);
            console.log(`   ${r.message}`);
            if (r.suggestion) console.log(`   建议: ${r.suggestion}`);
            console.log('');
          }
        }
        
        if (pass.length > 0) {
          console.log('## ✅ 通过项目\n');
          for (const r of pass) {
            const emoji = r.severity === 'critical' ? '🛡️' : r.severity === 'high' ? '🛡️' : r.severity === 'medium' ? '⚠️' : r.severity === 'low' ? 'ℹ️' : 'ℹ️';
            console.log(`${emoji} [${r.severity.toUpperCase()}] ${r.path}: ${r.message}`);
          }
        }
      }
    });
}
export default function registerCli(
  api: OpenClawPluginApi,
  logger: Logger,
  uploadDetectFile: (file: FormData) => Promise<void>,
) {
  api.registerCli(
    ({ program }) =>
      registerLmSecurityCli({
        program,
        logger,
        uploadDetectFile
      }),
    { commands: ["lmsecurity"] },
  );
}
