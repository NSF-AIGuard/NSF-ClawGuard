import path from "node:path";
import fs from "node:fs";
import { execSync } from "node:child_process";
import archiver from "archiver";
import FormData from "form-data";

import type { PluginLogger } from "../types.js";

type TArchiver = archiver.Archiver;

// ─── Helpers ─────────────────────────────────────────────────────────────────

const IS_WIN = process.platform === "win32";

/** Locate the openclaw binary and derive the global installation root. */
function getOpenclawGlobalRoot(): string | null {
  const cmd = IS_WIN ? "where.exe openclaw" : "which openclaw";

  try {
    const output = execSync(cmd, { stdio: "pipe" }).toString().trim();
    if (!output) return null;

    // Take the first line (Windows may return multiple matches)
    const binPath = output.split(/\r?\n/)[0];
    // Binary sits at <root>/bin/openclaw (or <root>/openclaw on Windows);
    // resolve upward to the package root.
    return path.resolve(binPath, IS_WIN ? ".." : "../..");
  } catch {
    return null;
  }
}

// ─── Archiving ───────────────────────────────────────────────────────────────

/**
 * Recursively append files under `dirPath` to the archive, skipping
 * `node_modules` directories.
 */
function addDirectoryRecursive(
  archive: TArchiver,
  dirPath: string,
  destPrefix: string,
): void {
  try {
    for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
      if (entry.name === "node_modules") continue;

      const fullPath = path.join(dirPath, entry.name);
      const destPath = `${destPrefix}/${entry.name}`;

      if (entry.isDirectory()) {
        addDirectoryRecursive(archive, fullPath, destPath);
      } else if (entry.isFile()) {
        archive.file(fullPath, { name: destPath });
      }
    }
  } catch (error) {
    console.error(error);
  }
}

/** Add the `skills` and `extensions` sub-directories from `sourceDir`. */
function addTools(
  archive: TArchiver,
  sourceDir: string,
  destPrefix: string,
): void {
  for (const tool of ["skills", "extensions"]) {
    const toolPath = path.join(sourceDir, tool);
    if (!fs.existsSync(toolPath)) continue;

    if (tool === "extensions") {
      // Use manual recursion for extensions (already skips node_modules)
      addDirectoryRecursive(archive, toolPath, `${destPrefix}/${tool}`);
    } else {
      archive.directory(toolPath, `${destPrefix}/${tool}`);
    }
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

export default async function collectAndUpload(
  logger: PluginLogger,
  openclawPath: string,
  uploadDetectFile: (file: FormData) => Promise<void>,
): Promise<void> {
  // 1. Build in-memory zip
  const archive = archiver("zip", { zlib: { level: 9 } });
  const chunks: Buffer[] = [];

  archive.on("data", (chunk: Buffer) => chunks.push(chunk));
  archive.on("end", () => logger.info("压缩完成，数据已写入内存"));
  archive.on("error", (err) => {
    logger.error(`压缩过程中发生错误: ${err}`);
    throw err;
  });

  // 2. Collect files into the archive
  //    a) Built-in tools (global openclaw installation)
  const globalRoot = getOpenclawGlobalRoot();
  if (globalRoot) {
    const builtInDir = path.join(globalRoot, "lib", "node_modules", "openclaw");
    addTools(archive, builtInDir, "builtIn");
  }

  //    b) Main openclaw.json config
  const configPath = path.join(openclawPath, "openclaw.json");
  if (fs.existsSync(configPath)) {
    archive.file(configPath, { name: "openclaw.json" });
  }

  //    c) Expand tools (user-installed skills / extensions)
  addTools(archive, openclawPath, "expand");

  //    d) Workspace skills
  const workspaceSkills = path.join(openclawPath, "workspace", "skills");
  if (fs.existsSync(workspaceSkills)) {
    archive.directory(workspaceSkills, "workspace/skills");
  }

  // 3. Finalize & upload
  await archive.finalize();

  const zipBuffer = Buffer.concat(chunks);
  logger.info(`压缩包大小: ${zipBuffer.length} 字节`);

  const form = new FormData();
  form.append("file", zipBuffer, {
    filename: "output.zip",
    contentType: "application/zip",
  });

  logger.info("开始上传...");
  try {
    const result = await uploadDetectFile(form);
    logger.info(`上传成功 ----\n${JSON.stringify(result)}`);
  } catch (error) {
    logger.error(`上传失败: ${error}`);
  }
}