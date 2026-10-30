import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { analyzeHosts, getProcesses, getStartupSnapshot } from "./system.mjs";
import { loadSignatureDb } from "./signatures.mjs";
import { logEvent, writeLastScan } from "./store.mjs";

const RISKY_EXT = new Set(["exe", "dll", "sys", "scr", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "msi", "msp", "cpl", "ocx", "jar", "lnk", "iso", "img", "vhd", "vhdx", "docm", "xlsm", "pptm", "dotm", "xlam", "ppam", "reg", "inf"]);
const TEXT_EXT = new Set(["txt", "md", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "xml", "html", "htm", "reg", "inf", "url", "json", "ini", "cfg", "log", "py", "sh", "bas", "vba", "com", "csv"]);
const MACRO_EXT = new Set(["docm", "xlsm", "pptm", "dotm", "xlam", "ppam"]);
const PE_MISMATCH_EXT = new Set(["pdf", "docx", "xlsx", "pptx", "jpg", "jpeg", "png", "gif", "webp", "bmp", "txt", "md", "csv", "mp3", "mp4", "avi", "mkv", "zip", "rar", "7z", "iso", "img"]);
const EXEC_EXT = new Set(["exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "js", "hta", "msi", "pif", "cpl"]);
const DOUBLE_EXT = /\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|webp|bmp|txt|md|csv|mp[34]|avi|mkv|zip|rar|7z|iso|img)\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|lnk|msi)$/i;
const RANSOM_NOTE = /^(?:decrypt|how[-_ ]?(?:to[-_ ]?)?decrypt|read[-_ ]?me[-_ ]?(?:for[-_ ]?)?decrypt|restore[-_ ]?files|recover[-_ ]?files|unlock[-_ ]?files)[^\\/]*\.(?:txt|html?|rtf|md)$/i;
const SKIP_DIRS = new Set(["node_modules", ".git", ".svn", ".hg", "$Recycle.Bin", "System Volume Information", "Windows", "WinSxS", "Program Files", "Program Files (x86)", "ProgramData", "AppData", "OneDriveTemp", ".cache", "__pycache__"]);
const MAX_DETECTIONS = 300;
const HASH_SIZE_CAP = 128 * 1024 * 1024;

const SEVERITY_WEIGHT = { high: 3, medium: 2, low: 1, info: 0 };

function normalizeExt(file) {
  return path.extname(file).replace(/^\./, "").toLowerCase();
}

function truncate(value, length = 500) {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

function homeDir() {
  return process.env.USERPROFILE || os.homedir();
}

function existing(paths) {
  return paths.filter((entry) => {
    try { return fs.statSync(entry).isDirectory() || fs.statSync(entry).isFile(); } catch { return false; }
  });
}

export function quickTargets() {
  const home = homeDir();
  const appData = process.env.APPDATA || "";
  const programData = process.env.ProgramData || process.env.PROGRAMDATA || "";
  return existing([
    path.join(home, "Downloads"),
    path.join(home, "Desktop"),
    path.join(home, "Documents"),
    os.tmpdir(),
    appData && path.join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    programData && path.join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
  ]);
}

export function deepTargets() {
  const home = homeDir();
  return existing([
    path.join(home, "Desktop"),
    path.join(home, "Downloads"),
    path.join(home, "Documents"),
    path.join(home, "Pictures"),
    path.join(home, "Videos"),
    os.tmpdir(),
  ]);
}

function collectFiles(targets, options) {
  const files = [];
  const errors = [];
  const maxFiles = Math.max(100, Math.min(Number(options.maxFiles) || 8000, 40000));
  const maxSeconds = Math.max(5, Math.min(Number(options.maxSeconds) || 45, 180));
  const maxDepth = Math.max(2, Math.min(Number(options.maxDepth) || 10, 20));
  const excluded = (options.excluded ?? []).map((entry) => {
    try { return path.resolve(entry); } catch { return ""; }
  }).filter(Boolean);
  const started = Date.now();
  let truncated = false;
  let visited = 0;
  const stack = [];
  for (const target of targets) {
    let stat;
    try { stat = fs.lstatSync(target); } catch { continue; }
    if (stat.isSymbolicLink()) continue;
    if (stat.isFile()) files.push(target);
    else if (stat.isDirectory()) stack.push({ dir: target, depth: 0 });
  }
  while (stack.length) {
    if (files.length >= maxFiles) { truncated = true; break; }
    if (Date.now() - started > maxSeconds * 1000) { truncated = true; break; }
    const { dir, depth } = stack.pop();
    if (excluded.some((entry) => dir === entry || dir.startsWith(`${entry}${path.sep}`))) continue;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { errors.push(dir); continue; }
    for (const entry of entries) {
      if (files.length >= maxFiles) { truncated = true; break; }
      visited += 1;
      if (visited % 200 === 0 && Date.now() - started > maxSeconds * 1000) { truncated = true; break; }
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".") && entry.name !== ".well-known") continue;
        if (depth < maxDepth) stack.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (entry.isFile()) files.push(full);
    }
    if (truncated) break;
  }
  return { files, errors, truncated, elapsedMs: Date.now() - started };
}

function shouldHash(file, size, mode) {
  if (size <= 0 || size > HASH_SIZE_CAP) return false;
  const ext = normalizeExt(file);
  if (RISKY_EXT.has(ext)) return true;
  return size <= (mode === "quick" ? 4 : 8) * 1024 * 1024;
}

function isTextLike(file, buffer) {
  const ext = normalizeExt(file);
  if (TEXT_EXT.has(ext)) return true;
  if (!buffer.length) return false;
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  let nul = 0;
  for (const byte of sample) if (byte === 0) nul += 1;
  return nul / sample.length < 0.05;
}

function readHead(file, size) {
  const length = Math.min(size, 1024 * 1024);
  if (length <= 0) return Buffer.alloc(0);
  const fd = fs.openSync(file, "r");
  try {
    const buffer = Buffer.alloc(length);
    const bytes = fs.readSync(fd, buffer, 0, length, 0);
    return buffer.subarray(0, bytes);
  } finally {
    fs.closeSync(fd);
  }
}

function detection(base) {
  return {
    id: `${base.kind}:${base.ruleId}:${base.path}${base.pid ? `:${base.pid}` : ""}`,
    severity: "medium",
    canQuarantine: base.kind === "hash" || base.kind === "heuristic" || base.kind === "structure",
    ...base,
  };
}

function analyzeTextRules(file, ext, buffer, compiled) {
  const candidates = [];
  const text = buffer.toString("utf8");
  candidates.push(text);
  if (buffer.length >= 2) {
    let nul = 0;
    const sample = buffer.subarray(0, Math.min(buffer.length, 2048));
    for (const byte of sample) if (byte === 0) nul += 1;
    if (nul / sample.length > 0.1) candidates.push(buffer.toString("utf16le").replace(/\u0000/g, ""));
  }
  const hits = [];
  for (const rule of compiled.heuristics) {
    if (rule.extensions?.size && !rule.extensions.has(ext)) continue;
    if (Number.isFinite(rule.maxSize) && buffer.length > rule.maxSize) continue;
    for (const value of candidates) {
      rule.regex.lastIndex = 0;
      if (!rule.regex.test(value)) continue;
      const match = value.match(rule.regex);
      hits.push({ rule, evidence: truncate(match?.[0] ?? "", 180) });
      break;
    }
  }
  return hits;
}

function analyzeFile(file, compiled, mode) {
  const results = [];
  let stat;
  try { stat = fs.lstatSync(file); } catch { return results; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 512 * 1024 * 1024) return results;
  const ext = normalizeExt(file);
  const name = path.basename(file);
  const isStartup = /[\\/]Start Menu[\\/]Programs[\\/]Startup[\\/]/i.test(file);

  if (DOUBLE_EXT.test(name)) {
    results.push(detection({
      kind: "structure",
      ruleId: "STRUCT-DOUBLE-EXT",
      title: "双扩展名伪装",
      severity: "high",
      path: file,
      name,
      size: stat.size,
      detail: "文件名使用文档/图片后缀包裹可执行后缀，常见于钓鱼投递。",
    }));
  }
  if (RANSOM_NOTE.test(name)) {
    results.push(detection({
      kind: "structure",
      ruleId: "STRUCT-RANSOM-NOTE",
      title: "疑似勒索信文件",
      severity: "medium",
      path: file,
      name,
      size: stat.size,
      detail: "文件名符合常见勒索说明命名。",
    }));
  }

  let sha256 = null;
  let buffer = null;
  try { buffer = readHead(file, stat.size); } catch { return results; }

  if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a && PE_MISMATCH_EXT.has(ext)) {
    results.push(detection({
      kind: "structure",
      ruleId: "STRUCT-PE-DISGUISE",
      title: "可执行文件伪装成普通文档",
      severity: "high",
      path: file,
      name,
      size: stat.size,
      detail: "文件头为 Windows PE（MZ），但扩展名不是可执行类型。",
    }));
  }
  if (ext === "exe" && !(buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a)) {
    results.push(detection({
      kind: "structure",
      ruleId: "STRUCT-EXE-HEADER",
      title: "EXE 文件头异常",
      severity: "low",
      path: file,
      name,
      size: stat.size,
      detail: "扩展名为 .exe，但缺少标准 PE 文件头（可能是损坏下载或伪装脚本）。",
    }));
  }
  if (isStartup && EXEC_EXT.has(ext)) {
    results.push(detection({
      kind: "structure",
      ruleId: "STRUCT-STARTUP-EXEC",
      title: "启动目录中的可执行文件",
      severity: "medium",
      path: file,
      name,
      size: stat.size,
      detail: "开机启动目录中的脚本或程序会在登录时自动执行，请确认来源。",
    }));
  }
  if (MACRO_EXT.has(ext) && stat.size <= 8 * 1024 * 1024) {
    try {
      const raw = fs.readFileSync(file);
      if (raw.includes(Buffer.from("vbaProject.bin"))) {
        results.push(detection({
          kind: "structure",
          ruleId: "STRUCT-OFFICE-MACRO",
          title: "文档包含 VBA 宏",
          severity: "low",
          path: file,
          name,
          size: stat.size,
          detail: "宏本身不等于恶意，请勿运行来源不明的宏。",
        }));
      }
    } catch { /* 忽略读取失败 */ }
  }

  if (shouldHash(file, stat.size, mode)) {
    try { sha256 = awaitHashSync(file); } catch { sha256 = null; }
  }
  if (sha256 && compiled.hashMap.has(sha256)) {
    const signature = compiled.hashMap.get(sha256);
    results.push(detection({
      kind: "hash",
      ruleId: signature.name,
      title: `已知恶意文件：${signature.name}`,
      severity: signature.severity || "high",
      path: file,
      name,
      size: stat.size,
      sha256,
      detail: `SHA-256 命中病毒库特征 ${sha256.slice(0, 16)}…`,
    }));
    return results;
  }

  if (isTextLike(file, buffer)) {
    const hits = analyzeTextRules(file, ext, buffer, compiled);
    for (const hit of hits) {
      results.push(detection({
        kind: "heuristic",
        ruleId: hit.rule.id,
        title: hit.rule.title,
        severity: hit.rule.severity || "medium",
        path: file,
        name,
        size: stat.size,
        sha256,
        detail: `命中规则 ${hit.rule.id}：${hit.evidence}`,
      }));
    }
  }
  return results;
}

function awaitHashSync(file) {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(file, "r");
  try {
    const chunk = Buffer.alloc(1024 * 1024);
    let position = 0;
    while (position < HASH_SIZE_CAP) {
      const bytes = fs.readSync(fd, chunk, 0, chunk.length, position);
      if (!bytes) break;
      hash.update(chunk.subarray(0, bytes));
      position += bytes;
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

const MINER_NAMES = new Set(["xmrig", "minerd", "phoenixminer", "nbminer", "lolminer", "teamredminer", "ethminer", "cgminer", "bfgminer", "cpuminer", "kawpowminer", "srbminer"]);
const REMOTE_PATTERNS = [
  { id: "PROC-PS-ENCODED", title: "进程使用编码 PowerShell 命令", severity: "high", regex: /powershell(?:\.exe)?[^\r\n]{0,120}\s-(?:enc|encodedcommand)\b/i },
  { id: "PROC-MSHTA-REMOTE", title: "进程通过 MSHTA 加载远程脚本", severity: "high", regex: /mshta(?:\.exe)?[^\r\n]{0,80}(?:https?:\/\/|javascript:)/i },
  { id: "PROC-REGSVR32", title: "进程使用 Regsvr32 绕过执行", severity: "high", regex: /regsvr32(?:\.exe)?[^\r\n]{0,120}scrobj\.dll/i },
  { id: "PROC-RUNDLL32-REMOTE", title: "进程通过 Rundll32 执行远程内容", severity: "high", regex: /rundll32(?:\.exe)?[^\r\n]{0,120}(?:javascript:|https?:\/\/)/i },
  { id: "PROC-CERTUTIL", title: "进程使用 Certutil 下载载荷", severity: "high", regex: /certutil(?:\.exe)?[^\r\n]{0,120}-urlcache/i },
  { id: "PROC-MINING-POOL", title: "进程连接挖矿矿池", severity: "high", regex: /stratum\+tcp:\/\//i },
];

function analyzeProcesses(processes) {
  const results = [];
  const seen = new Set();
  for (const proc of processes) {
    const name = String(proc.name ?? "").toLowerCase().replace(/\.exe$/, "");
    const commandLine = String(proc.commandLine ?? "");
    const signature = `${name}|${proc.pid}`;
    if (name === "node" || name === "electron" || name === "code") continue;
    if (MINER_NAMES.has(name)) {
      results.push(detection({
        kind: "process",
        ruleId: "PROC-MINER",
        title: "疑似挖矿进程",
        severity: "high",
        path: proc.path || commandLine || name,
        name: proc.name || name,
        size: 0,
        detail: `进程 ${proc.name}（PID ${proc.pid}）属于常见挖矿程序名称。`,
        pid: proc.pid,
      }));
      continue;
    }
    for (const pattern of REMOTE_PATTERNS) {
      if (!pattern.regex.test(commandLine)) continue;
      const key = `${pattern.id}|${signature}`;
      if (seen.has(key)) continue;
      seen.add(key);
      results.push(detection({
        kind: "process",
        ruleId: pattern.id,
        title: pattern.title,
        severity: pattern.severity,
        path: proc.path || commandLine || name,
        name: proc.name || name,
        size: 0,
        detail: `${proc.name}（PID ${proc.pid}）：${truncate(commandLine, 260)}`,
        pid: proc.pid,
      }));
    }
  }
  return results;
}

const STARTUP_HIGH = [
  /powershell(?:\.exe)?[^\r\n]{0,120}\s-(?:enc|encodedcommand)\b/i,
  /mshta(?:\.exe)?[^\r\n]{0,80}(?:https?:\/\/|javascript:)/i,
  /regsvr32(?:\.exe)?[^\r\n]{0,120}scrobj\.dll/i,
  /certutil(?:\.exe)?[^\r\n]{0,120}-urlcache/i,
  /wmic(?:\.exe)?[^\r\n]{0,120}process\s+call\s+create/i,
  /-windowstyle\s+hidden/i,
];
const STARTUP_MEDIUM = [
  /[\\/](?:Temp|Users[\\/]Public|Downloads)[\\/][^\r\n]{0,200}\.(?:exe|scr|bat|cmd|vbs|js|hta|ps1)\b/i,
  /[\\/]AppData[\\/](?:Roaming|Local)[\\/][^\r\n]{0,200}\.(?:vbs|vbe|js|jse|hta|wsf|bat|cmd)\b/i,
];

export function analyzeStartupItems(items, tasks) {
  const results = [];
  const seen = new Set();
  const check = (item, kind) => {
    const command = String(item.command ?? "");
    if (!command) return;
    let severity = "";
    if (STARTUP_HIGH.some((pattern) => pattern.test(command))) severity = "high";
    else if (STARTUP_MEDIUM.some((pattern) => pattern.test(command))) severity = "medium";
    if (!severity) return;
    const key = `${kind}|${command}`.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    const label = kind === "task" ? "计划任务" : "启动项";
    results.push(detection({
      kind: kind === "task" ? "task" : "startup",
      ruleId: kind === "task" ? "STARTUP-TASK" : "STARTUP-ITEM",
      title: `${label}指向可疑命令`,
      severity,
      path: kind === "task" ? `${item.path || ""}${item.name}` : item.name,
      name: item.name || label,
      size: 0,
      detail: `${label}「${item.name || "-"}」：${truncate(command, 260)}`,
    }));
  };
  for (const item of items) check(item, "startup");
  for (const task of tasks) check(task, "task");
  return results;
}

function dedupeDetections(detections) {
  const map = new Map();
  for (const item of detections) {
    const key = `${item.kind}|${item.ruleId}|${item.path}|${item.pid ?? ""}`;
    if (!map.has(key)) map.set(key, item);
  }
  return [...map.values()].sort((a, b) => (SEVERITY_WEIGHT[b.severity] ?? 0) - (SEVERITY_WEIGHT[a.severity] ?? 0)).slice(0, MAX_DETECTIONS);
}

function summarize(detections) {
  const summary = { total: detections.length, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of detections) {
    if (summary[item.severity] != null) summary[item.severity] += 1;
  }
  return summary;
}

export async function scan(input = {}) {
  const mode = ["quick", "deep", "custom"].includes(String(input.mode)) ? String(input.mode) : "quick";
  const startedAt = new Date();
  const started = Date.now();
  const { compiled } = await loadSignatureDb();
  const excluded = Array.isArray(input.exclusions) ? input.exclusions.map(String) : [];
  let targets;
  if (mode === "custom") {
    targets = existing((Array.isArray(input.paths) ? input.paths : []).map((entry) => path.resolve(String(entry))));
    if (!targets.length) throw new Error("请选择至少一个有效的扫描目录或文件");
  } else if (mode === "deep") {
    targets = deepTargets();
  } else {
    targets = quickTargets();
  }
  const budgets = {
    quick: { maxFiles: 6000, maxSeconds: 40, maxDepth: 8 },
    deep: { maxFiles: 18000, maxSeconds: 105, maxDepth: 12 },
    custom: { maxFiles: 18000, maxSeconds: 120, maxDepth: 14 },
  }[mode];
  const timeBudget = Math.max(5, Math.min(Number(input.maxSeconds) || budgets.maxSeconds, 180));
  const collected = collectFiles(targets, {
    ...budgets,
    maxFiles: Number(input.maxFiles) || budgets.maxFiles,
    maxSeconds: timeBudget,
    excluded,
  });

  const detections = [];
  let scannedBytes = 0;
  let errors = collected.errors.length;
  for (const [index, file] of collected.files.entries()) {
    if (Date.now() - started > timeBudget * 1000 + 5000) break;
    try {
      const stat = fs.lstatSync(file);
      scannedBytes += stat.size;
    } catch { /* 忽略 */ }
    const found = analyzeFile(file, compiled, mode);
    detections.push(...found);
    if (index % 400 === 0 && Date.now() - started > timeBudget * 1000 + 5000) break;
  }

  const includeProcesses = mode === "quick" || input.includeProcesses === true;
  const includeStartup = mode === "quick" || input.includeStartup === true;
  let processesChecked = 0;
  let startupChecked = 0;
  let tasksChecked = 0;
  if (includeProcesses) {
    const processes = await getProcesses();
    processesChecked = processes.length;
    detections.push(...analyzeProcesses(processes));
  }
  if (includeStartup) {
    const snapshot = await getStartupSnapshot();
    startupChecked = snapshot.startup.length;
    tasksChecked = snapshot.tasks.length;
    detections.push(...analyzeStartupItems(snapshot.startup, snapshot.tasks));
    if (snapshot.error) errors += 1;
  }

  const hostsPath = process.env.SystemRoot ? path.join(process.env.SystemRoot, "System32", "drivers", "etc", "hosts") : "C:\\Windows\\System32\\drivers\\etc\\hosts";
  try {
    const hosts = analyzeHosts(fs.readFileSync(hostsPath, "utf8"));
    if (hosts.suspicious.length) {
      detections.push(detection({
        kind: "hosts",
        ruleId: "HOSTS-HIJACK",
        title: "hosts 文件疑似劫持系统域名",
        severity: "high",
        path: hostsPath,
        name: "hosts",
        size: 0,
        detail: hosts.suspicious.slice(0, 6).map((entry) => `${entry.ip} ${entry.host}`).join("；"),
      }));
    }
    if (hosts.oversized) {
      detections.push(detection({
        kind: "hosts",
        ruleId: "HOSTS-OVERSIZED",
        title: "hosts 文件异常庞大",
        severity: "medium",
        path: hostsPath,
        name: "hosts",
        size: 0,
        detail: `检测到 ${hosts.entries} 条 hosts 记录，可能被广告/恶意软件批量写入。`,
      }));
    }
  } catch { /* 无权限读取 hosts 时跳过 */ }

  const unique = dedupeDetections(detections);
  const summary = summarize(unique);
  const elapsedMs = Date.now() - started;
  const result = {
    mode,
    startedAt: startedAt.toISOString(),
    elapsedMs,
    targets,
    scannedFiles: collected.files.length,
    scannedBytes,
    errors,
    limitsHit: collected.truncated,
    db: { version: compiled.version, hashes: compiled.rules.hashes.length, rules: compiled.rules.heuristics.length },
    processesChecked,
    startupChecked,
    tasksChecked,
    detections: unique,
    summary,
  };
  const persisted = {
    ...result,
    detections: unique.slice(0, 200),
    finishedAt: new Date().toISOString(),
  };
  await writeLastScan(persisted);
  logEvent("scan", {
    mode,
    files: result.scannedFiles,
    detections: summary.total,
    high: summary.high,
    elapsedMs,
  });
  return result;
}
