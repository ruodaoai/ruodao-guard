import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { PATHS, PLUGIN_DIR, atomicWriteJson, ensureStore, readJson } from "./store.mjs";

export const DB_FORMAT = "ruodao-guard-signatures/1";
const MAX_HASHES = 200000;
const MAX_RULES = 5000;
const MAX_DB_BYTES = 20 * 1024 * 1024;
const SEVERITIES = new Set(["high", "medium", "low", "info"]);
const FLAGS = /^[imsugd]*$/;

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

export function compareDbVersion(a, b) {
  const left = String(a ?? "").split(/[^0-9]+/).filter(Boolean).map(Number);
  const right = String(b ?? "").split(/[^0-9]+/).filter(Boolean).map(Number);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const diff = (left[index] ?? 0) - (right[index] ?? 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  return 0;
}

function normalizeSeverity(value) {
  const severity = String(value ?? "").trim().toLowerCase();
  return SEVERITIES.has(severity) ? severity : "medium";
}

export function validateDb(db) {
  if (!db || typeof db !== "object" || Array.isArray(db)) return { ok: false, error: "病毒库必须是 JSON 对象" };
  if (String(db.format ?? "") !== DB_FORMAT) return { ok: false, error: `病毒库格式不受支持：${String(db.format ?? "(缺失)")}` };
  if (!String(db.version ?? "").trim()) return { ok: false, error: "病毒库缺少 version" };
  const rules = db.rules;
  if (!rules || typeof rules !== "object") return { ok: false, error: "病毒库缺少 rules" };
  if (!Array.isArray(rules.hashes)) return { ok: false, error: "rules.hashes 必须是数组" };
  if (!Array.isArray(rules.heuristics)) return { ok: false, error: "rules.heuristics 必须是数组" };
  if (rules.hashes.length > MAX_HASHES) return { ok: false, error: `hash 特征过多（上限 ${MAX_HASHES}）` };
  if (rules.heuristics.length > MAX_RULES) return { ok: false, error: `启发式规则过多（上限 ${MAX_RULES}）` };
  for (const [index, entry] of rules.hashes.entries()) {
    if (!entry || !/^[a-f0-9]{64}$/i.test(String(entry.sha256 ?? ""))) return { ok: false, error: `第 ${index + 1} 条 hash 特征 sha256 无效` };
    if (!String(entry.name ?? "").trim()) return { ok: false, error: `第 ${index + 1} 条 hash 特征缺少 name` };
  }
  for (const [index, rule] of rules.heuristics.entries()) {
    if (!rule || !String(rule.id ?? "").trim()) return { ok: false, error: `第 ${index + 1} 条启发式规则缺少 id` };
    if (!String(rule.title ?? "").trim()) return { ok: false, error: `规则 ${rule.id} 缺少 title` };
    const flags = String(rule.flags ?? "i");
    if (!FLAGS.test(flags)) return { ok: false, error: `规则 ${rule.id} 的 flags 无效` };
    try {
      new RegExp(String(rule.pattern ?? ""), flags);
    } catch (error) {
      return { ok: false, error: `规则 ${rule.id} 正则无效：${error.message}` };
    }
    if (rule.extensions != null && !Array.isArray(rule.extensions)) return { ok: false, error: `规则 ${rule.id} 的 extensions 必须是数组` };
  }
  return { ok: true };
}

export function dbStats(db) {
  return {
    version: String(db?.version ?? ""),
    releasedAt: String(db?.releasedAt ?? ""),
    publisher: String(db?.publisher ?? ""),
    hashes: db?.rules?.hashes?.length ?? 0,
    rules: db?.rules?.heuristics?.length ?? 0,
  };
}

function normalizeKey(input) {
  const raw = String(input ?? "").trim();
  if (!raw) return null;
  if (raw.includes("BEGIN PUBLIC KEY")) return crypto.createPublicKey(raw);
  return crypto.createPublicKey({ key: Buffer.from(raw, "base64"), format: "der", type: "spki" });
}

export function loadPublicKey() {
  const envKey = String(process.env.RUODAO_GUARD_PUBLIC_KEY ?? "").trim();
  if (envKey) {
    const key = normalizeKey(envKey);
    return { key, pem: key.export({ type: "spki", format: "pem" }), source: "config" };
  }
  const file = path.join(PLUGIN_DIR, "db", "public-key.pem");
  const pem = fs.readFileSync(file, "utf8");
  return { key: crypto.createPublicKey(pem), pem, source: "builtin" };
}

export function keyFingerprint(pem) {
  const der = crypto.createPublicKey(pem).export({ type: "spki", format: "der" });
  const hex = crypto.createHash("sha256").update(der).digest("hex").toUpperCase();
  return hex.match(/.{1,4}/g).slice(0, 4).join(" ");
}

export function verifyDbSignature(db, publicKeyPem) {
  if (!db?.signature) return { ok: false, error: "病毒库缺少 signature" };
  const unsigned = { ...db };
  delete unsigned.signature;
  const data = Buffer.from(canonicalJson(unsigned), "utf8");
  const signature = Buffer.from(String(db.signature), "base64");
  try {
    const ok = crypto.verify(null, data, crypto.createPublicKey(publicKeyPem), signature);
    return ok ? { ok: true } : { ok: false, error: "病毒库签名校验失败" };
  } catch (error) {
    return { ok: false, error: `病毒库签名校验失败：${error.message}` };
  }
}

export function verifyChecksum(db) {
  if (!db?.checksum) return { ok: true, skipped: true };
  const unsigned = { ...db };
  delete unsigned.checksum;
  delete unsigned.signature;
  const actual = crypto.createHash("sha256").update(canonicalJson(unsigned), "utf8").digest("hex");
  return actual === String(db.checksum).toLowerCase()
    ? { ok: true }
    : { ok: false, error: "病毒库 checksum 校验失败" };
}

function sanitizeDb(db) {
  return {
    format: DB_FORMAT,
    version: String(db.version),
    releasedAt: String(db.releasedAt ?? ""),
    publisher: String(db.publisher ?? "Community"),
    description: String(db.description ?? ""),
    signature: db.signature ? String(db.signature) : undefined,
    checksum: db.checksum ? String(db.checksum) : undefined,
    rules: {
      hashes: db.rules.hashes.map((entry) => ({
        sha256: String(entry.sha256).toLowerCase(),
        name: String(entry.name).slice(0, 120),
        severity: normalizeSeverity(entry.severity),
        tags: Array.isArray(entry.tags) ? entry.tags.map((tag) => String(tag).slice(0, 40)).slice(0, 12) : [],
      })),
      heuristics: db.rules.heuristics.map((rule) => ({
        id: String(rule.id).slice(0, 80),
        title: String(rule.title).slice(0, 160),
        severity: normalizeSeverity(rule.severity),
        pattern: String(rule.pattern),
        flags: String(rule.flags ?? "i"),
        extensions: Array.isArray(rule.extensions) ? rule.extensions.map((ext) => String(ext).replace(/^\./, "").toLowerCase()).slice(0, 32) : undefined,
        maxSize: Number(rule.maxSize) > 0 ? Math.min(Number(rule.maxSize), 8 * 1024 * 1024) : undefined,
      })),
    },
  };
}

export function compileDb(db) {
  const hashMap = new Map();
  for (const entry of db.rules.hashes) hashMap.set(entry.sha256.toLowerCase(), entry);
  const heuristics = db.rules.heuristics.map((rule) => ({
    ...rule,
    extensions: new Set((rule.extensions ?? []).map((ext) => ext.toLowerCase())),
    regex: new RegExp(rule.pattern, rule.flags || "i"),
  }));
  return { ...db, hashMap, heuristics };
}

export async function loadSignatureDb() {
  ensureStore();
  const warnings = [];
  const builtinRaw = readJson(path.join(PLUGIN_DIR, "db", "signatures.json"));
  const builtinCheck = validateDb(builtinRaw);
  if (!builtinCheck.ok) throw new Error(`内置病毒库损坏：${builtinCheck.error}`);
  let userRaw = readJson(PATHS.userDb);
  let userCheck = { ok: false };
  if (userRaw) {
    userCheck = validateDb(userRaw);
    if (!userCheck.ok) {
      warnings.push(`已安装病毒库无效，已回退内置库：${userCheck.error}`);
      userRaw = null;
    }
  }
  const builtinVersion = dbStats(builtinRaw).version;
  const userVersion = userRaw ? dbStats(userRaw).version : "";
  const useUser = userRaw && compareDbVersion(userVersion, builtinVersion) >= 0;
  const db = useUser ? userRaw : builtinRaw;
  const meta = readJson(PATHS.dbMeta, {}) ?? {};
  const key = loadPublicKey();
  return {
    db,
    compiled: compileDb(db),
    source: useUser ? "user" : "builtin",
    builtin: dbStats(builtinRaw),
    installed: userRaw ? dbStats(userRaw) : null,
    warnings,
    meta,
    publicKeyFingerprint: keyFingerprint(key.pem),
    publicKeySource: key.source,
  };
}

export async function installSignatureDb(db, options = {}) {
  ensureStore();
  const check = validateDb(db);
  if (!check.ok) throw new Error(check.error);
  const allowUnsigned = Boolean(options.allowUnsigned);
  const key = loadPublicKey();
  if (db.signature) {
    const verified = verifyDbSignature(db, key.pem);
    if (!verified.ok) throw new Error(verified.error);
  } else if (!allowUnsigned) {
    throw new Error("订阅源未签名。请使用带 Ed25519 签名的病毒库，或在设置中显式允许未签名源。");
  }
  const checksum = verifyChecksum(db);
  if (!checksum.ok) throw new Error(checksum.error);
  const clean = sanitizeDb(db);
  await atomicWriteJson(PATHS.userDb, clean);
  await atomicWriteJson(PATHS.dbMeta, {
    source: options.source ?? "import",
    url: options.url ?? "",
    installedAt: new Date().toISOString(),
    signed: Boolean(db.signature),
    publicKeyFingerprint: keyFingerprint(key.pem),
    stats: dbStats(clean),
  });
  return { stats: dbStats(clean), signed: Boolean(db.signature), publicKeyFingerprint: keyFingerprint(key.pem) };
}

export async function resetSignatureDb() {
  await fsp.unlink(PATHS.userDb).catch(() => undefined);
  await fsp.unlink(PATHS.dbMeta).catch(() => undefined);
}

export async function fetchSignatureDb(url, timeoutMs = 30000) {
  const target = String(url ?? "").trim();
  if (!target) throw new Error("请先填写病毒库订阅源地址");
  let parsed;
  try { parsed = new URL(target); } catch { throw new Error("订阅源地址无效"); }
  const local = ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:")) {
    throw new Error("订阅源必须使用 HTTPS（本机调试可用 http://127.0.0.1）");
  }
  const response = await fetch(target, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { "User-Agent": "RuodaoGuard/1.0", Accept: "application/json" },
  }).catch((error) => { throw new Error(`订阅源请求失败：${error.message}`); });
  if (!response.ok) throw new Error(`订阅源返回 HTTP ${response.status}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > MAX_DB_BYTES) throw new Error("病毒库超过 20MB 上限");
  let db;
  try { db = JSON.parse(buffer.toString("utf8")); } catch { throw new Error("订阅源不是有效的 JSON"); }
  return db;
}
