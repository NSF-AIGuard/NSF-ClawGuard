
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// Get the directory of the current script
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define directories
const lmSecurityDir = path.join(__dirname, ".."); // lm-security directory
const uiDir = path.join(lmSecurityDir, "src", "server", "ui");
const webDir = path.join(lmSecurityDir, "src", "server", "web");
const distDir = path.join(lmSecurityDir, "dist");
const projectRoot = path.dirname(lmSecurityDir); // lm-openclaw-security-plugin
const outputDir = path.join(projectRoot, "output", 'lm-security');

// Helper function to execute commands
function executeCommand(command, cwd, description) {
  console.log(`${description}...`);
  try {
    execSync(command, {
      stdio: "inherit",
      cwd: cwd
    });
    console.log(`${description} completed successfully.`);
  } catch (e) {
    console.error(`${description} failed.`);
    process.exit(1);
  }
}

// Helper function to copy directory recursively
function copyDirectoryRecursive(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  
  const entries = fs.readdirSync(src, { withFileTypes: true });
  
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    
    if (entry.isDirectory()) {
      copyDirectoryRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// Step 1: Install dependencies and build UI
console.log("=== Step 1: Building UI ===");
executeCommand("npm install", uiDir, "Installing UI dependencies");
executeCommand("npm run build", uiDir, "Building UI");

// Step 2: Build main package
console.log("\n=== Step 2: Building main package ===");
executeCommand("npm run build", lmSecurityDir, "Building main package");

// Step 3: Copy web directory to dist
console.log("\n=== Step 3: Copying web directory to dist ===");
if (fs.existsSync(webDir)) {
  const webDestDir = path.join(distDir, "web");
  copyDirectoryRecursive(webDir, webDestDir);
  console.log("Web directory copied to dist successfully.");
} else {
  console.warn("Warning: web directory does not exist, skipping copy.");
}

// Step 4: Copy required files to output directory
console.log("\n=== Step 4: Creating output directory and copying files ===");

// Clean and create output directory
if (fs.existsSync(outputDir)) {
  console.log("Cleaning existing output directory...");
  fs.rmSync(outputDir, { recursive: true, force: true });
}
fs.mkdirSync(outputDir, { recursive: true });

// Files/directories to copy
const itemsToCopy = [
  { name: "dist", type: "dir" },
  { name: "clawdbot.plugin.json", type: "file" },
  { name: "openclaw.plugin.json", type: "file" },
  { name: "package-lock.json", type: "file" },
  { name: "package.json", type: "file" }
];

// Copy each item
for (const item of itemsToCopy) {
  const srcPath = path.join(lmSecurityDir, item.name);
  const destPath = path.join(outputDir, item.name);
  
  if (!fs.existsSync(srcPath)) {
    console.warn(`Warning: ${item.name} does not exist, skipping.`);
    continue;
  }
  
  if (item.type === "dir") {
    console.log(`Copying directory: ${item.name}`);
    copyDirectoryRecursive(srcPath, destPath);
  } else {
    console.log(`Copying file: ${item.name}`);
    fs.copyFileSync(srcPath, destPath);
  }
}

console.log("\n=== Build completed successfully! ===");
console.log(`Output directory created at: ${outputDir}`);
