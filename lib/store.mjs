import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const MAX_LOG_BYTES = 1024 * 1024;

function resolveRoot() {
  const override = String(process.env.RUODAO_GUARD_HOME ?? "").trim();
  if (override) return path.resolve(override);
  if (process.platform === "win32" && process.env.LOCALAPPDATA) return path.join(process.env.LOCALAPPDATA, "RuodaoGuard");
  return path.join(os.homedir(), ".ruodao-guard");
}

export const PLUGIN_DIR = fileURLToPath(new URL("..", import.meta.url));
export const ROOT_DIR = resolveRoot();
export const PATHS = {
  root: ROOT_DIR,
  db: path.join(ROOT_DIR, "db"),
  quarantine: path.join(ROOT_DIR, "quarantine"),
  logs: path.join(ROOT_DIR, "logs"),
  data: path.join(ROOT_DIR, "data"),
  userDb: path.join(ROOT_DIR, "db", "signatures.json"),
  dbMeta: path.join(ROOT_DIR, "db", "meta.json"),
  lastScan: path.join(ROOT_DIR, "data", "last-scan.json"),
  logFile: path.join(ROOT_DIR, "logs", "guard.jsonl"),
};

export function ensureStore() {
  for (const dir of [PATHS.root, PATHS.db, PATHS.quarantine, PATHS.logs, PATHS.data]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return PATHS;
}

export function readJson(file, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

export async function atomicWriteJson(file, value) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  await fsp.writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  try {
    await fsp.rename(temp, file);
  } catch {
    await fsp.copyFile(temp, file);
    await fsp.unlink(temp).catch(() => undefined);
  }
}

export function logEvent(type, data = {}) {
  try {
    ensureStore();
    const stat = fs.statSync(PATHS.logFile, { throwIfNoEntry: false });
    if (stat && stat.size > MAX_LOG_BYTES) {
      fs.renameSync(PATHS.logFile, `${PATHS.logFile}.1`);
    }
    fs.appendFileSync(PATHS.logFile, `${JSON.stringify({ at: new Date().toISOString(), type, ...data })}\n`, "utf8");
  } catch {
    /* 日志失败不阻断安全操作 */
  }
}

export function readEvents(limit = 12) {
  try {
    const lines = fs.readFileSync(PATHS.logFile, "utf8").trim().split("\n").filter(Boolean);
    return lines.slice(-limit).reverse().map((line) => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);
  } catch {
    return [];
  }
}

function quarantineId() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
}

export function quarantinePaths(id) {
  return {
    bin: path.join(PATHS.quarantine, `${id}.bin`),
    meta: path.join(PATHS.quarantine, `${id}.json`),
  };
}

export async function addQuarantineEntry(entry) {
  ensureStore();
  const id = quarantineId();
  const { bin, meta } = quarantinePaths(id);
  await atomicWriteJson(meta, { id, ...entry });
  return { id, bin, meta };
}

export function listQuarantine() {
  ensureStore();
  const items = [];
  for (const name of fs.readdirSync(PATHS.quarantine)) {
    if (!name.endsWith(".json")) continue;
    const meta = readJson(path.join(PATHS.quarantine, name));
    if (meta && meta.id) items.push(meta);
  }
  return items.sort((a, b) => String(b.quarantinedAt ?? "").localeCompare(String(a.quarantinedAt ?? "")));
}

export function quarantineStats() {
  const items = listQuarantine();
  return { count: items.length, bytes: items.reduce((sum, item) => sum + (Number(item.size) || 0), 0) };
}

export async function removeQuarantineEntry(id) {
  const { bin, meta } = quarantinePaths(String(id));
  await fsp.unlink(bin).catch(() => undefined);
  await fsp.unlink(meta).catch(() => undefined);
}

export async function updateQuarantineMeta(id, patch) {
  const { meta } = quarantinePaths(String(id));
  const current = readJson(meta);
  if (!current) throw new Error("隔离记录不存在");
  await atomicWriteJson(meta, { ...current, ...patch });
}

export function readLastScan() {
  return readJson(PATHS.lastScan, null);
}

export async function writeLastScan(summary) {
  await atomicWriteJson(PATHS.lastScan, summary);
}

export async function sha256File(file) {
  const hash = crypto.createHash("sha256");
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(file);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return hash.digest("hex");
}
