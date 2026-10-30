#!/usr/bin/env node
/**
 * 若道安全卫士命令入口。
 *
 * 设计边界：不做驱动/内核/常驻服务；实时防护与官方病毒库由 Windows Defender 提供。
 * 本插件负责统一状态、开放规则查杀、加固体检、隔离区与可签名的开放病毒库订阅。
 *
 * stdin: JSON（Host 会注入 config）；stdout: 单行 JSON { state: "succeeded" | "failed", ... }
 */

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { PLUGIN_DIR, PATHS, ROOT_DIR, ensureStore, readJson, readEvents, readLastScan, listQuarantine, quarantinePaths, quarantineStats, removeQuarantineEntry, sha256File, atomicWriteJson, logEvent } from "../lib/store.mjs";
import { chatEndpoint, runAgent } from "../lib/agent-core.mjs";
import { compact, contextText, preparePayload, systemPrompt, tools as agentTools } from "../lib/agent-tools.mjs";
import { loadSignatureDb, loadPublicKey, fetchSignatureDb, installSignatureDb, resetSignatureDb, validateDb, verifyDbSignature, verifyChecksum, compareDbVersion, dbStats } from "../lib/signatures.mjs";
import { getSystemSnapshot, getStartupSnapshot, isAdmin, runPowerShellJson, applyFix, fixCatalog, updateDefenderSignatures, runDefenderQuickScan } from "../lib/system.mjs";
import { scan, analyzeStartupItems } from "../lib/scanner.mjs";
import { buildStatus, buildAudit, activeThirdPartyAv } from "../lib/status.mjs";

const PLUGIN = readJson(path.join(PLUGIN_DIR, "plugin.json"), {});
const VERSION = String(PLUGIN.version ?? "1.0.0");
const COMMAND = String(process.argv[2] ?? "").trim();
const MAX_QUARANTINE_BYTES = 1024 * 1024 * 1024;
const PRELUDE_PS = "$ErrorActionPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)";

const env = (key, fallback = "") => String(process.env[key] ?? fallback).trim();

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    if (process.stdin.isTTY) return resolve({});
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => { data += chunk; });
    process.stdin.on("end", () => {
      try { resolve(data.trim() ? JSON.parse(data) : {}); }
      catch { resolve({ prompt: data.trim() }); }
    });
    process.stdin.on("error", () => resolve({}));
  });
}

function emit(payload) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

function fail(message, extra = {}) {
  emit({ state: "failed", error: String(message ?? "未知错误"), ...extra });
  process.exit(1);
}

function requireConfirm(input, action) {
  if (input?.confirm !== true) throw new Error(`${action}需要显式确认（confirm: true）`);
}

function safeQuarantineId(value) {
  const id = String(value ?? "").trim();
  if (!/^[a-z0-9][a-z0-9-]{2,80}$/i.test(id)) throw new Error("隔离记录 ID 无效");
  return id;
}

function isInside(target, root) {
  if (!root) return false;
  const left = path.resolve(target).toLowerCase();
  const right = path.resolve(root).toLowerCase().replace(/[\\/]+$/, "");
  return left === right || left.startsWith(`${right}${path.sep}`);
}

function allowUnsignedDb() {
  return env("RUODAO_GUARD_ALLOW_UNSIGNED") === "1";
}

async function moveFile(source, target) {
  await fsp.mkdir(path.dirname(target), { recursive: true });
  try {
    await fsp.rename(source, target);
  } catch (error) {
    if (error?.code !== "EXDEV") throw error;
    await fsp.copyFile(source, target);
    try {
      await fsp.unlink(source);
    } catch (unlinkError) {
      await fsp.unlink(target).catch(() => undefined);
      throw unlinkError;
    }
  }
}

async function commandDoctor() {
  ensureStore();
  const checks = [];
  const add = (id, title, status, detail) => checks.push({ id, title, status, detail });

  add("platform", "操作系统", process.platform === "win32" ? "pass" : "warn", process.platform === "win32" ? "Windows" : `当前为 ${process.platform}，仅文件查杀与开放病毒库可用`);
  add("node", "Node.js 运行时", "pass", process.version);

  const ps = await runPowerShellJson(`${PRELUDE_PS}; $v=$PSVersionTable.PSVersion; [ordered]@{ version=$v.ToString() } | ConvertTo-Json -Compress`, 20000);
  add("powershell", "PowerShell", ps.json?.version ? "pass" : "warn", ps.json?.version ? `PowerShell ${ps.json.version}` : "无法运行 PowerShell，系统加固与 Defender 调度不可用");

  const admin = await isAdmin();
  add("admin", "管理员权限", admin ? "pass" : "warn", admin ? "当前进程以管理员身份运行" : "加固修复与应用需要以管理员身份运行若道");

  let writable = false;
  try {
    const probe = path.join(PATHS.data, `.write-test-${process.pid}`);
    fs.writeFileSync(probe, "ok", "utf8");
    fs.unlinkSync(probe);
    writable = true;
  } catch { /* 保持 false */ }
  add("storage", "数据目录", writable ? "pass" : "fail", writable ? PATHS.root : `数据目录不可写：${PATHS.root}`);

  let dbInfo = null;
  try {
    dbInfo = await loadSignatureDb();
    add("signature-db", "开放病毒库", "pass", `${dbInfo.db.version} · ${dbInfo.db.rules.hashes.length} 条哈希 · ${dbInfo.db.rules.heuristics.length} 条规则 · 来源 ${dbInfo.source}`);
  } catch (error) {
    add("signature-db", "开放病毒库", "fail", String(error?.message ?? error));
  }
  add("public-key", "订阅公钥", dbInfo ? "pass" : "warn", dbInfo ? `${dbInfo.publicKeyFingerprint}（${dbInfo.publicKeySource === "config" ? "用户配置" : "内置"}）` : "无法读取公钥");

  const snapshot = await getSystemSnapshot();
  if (!snapshot.supported) {
    add("defender", "Defender", "warn", "非 Windows 系统，无法调度 Defender");
  } else if (snapshot.partial) {
    add("defender", "Defender", "warn", snapshot.error || "系统防护状态读取不完整");
  } else if (snapshot.defender?.antivirusEnabled) {
    add("defender", "Defender", "pass", `Defender 已启用（${snapshot.defender.signatureVersion || "病毒库版本未知"}）`);
  } else {
    const av = activeThirdPartyAv(snapshot).map((item) => item.name).filter(Boolean);
    if (av.length) add("defender", "杀毒引擎", "pass", `Defender 处于被动模式，实时防护由第三方杀毒接管：${av.join("、")}`);
    else if (snapshot.defender?.present) add("defender", "Defender", "warn", "Defender 已安装但防病毒引擎未开启，且没有其他已启用的杀毒软件");
    else add("defender", "Defender", "warn", "未检测到 Defender 或已启用的第三方杀毒引擎");
  }
  add("os", "Windows 版本", snapshot.os ? "pass" : "warn", snapshot.os ? `${snapshot.os.caption} ${snapshot.os.version}（Build ${snapshot.os.build}）` : "无法读取系统版本");

  const summary = { pass: 0, warn: 0, fail: 0 };
  for (const item of checks) summary[item.status] += 1;
  const state = checks.some((item) => item.status === "fail") ? "failed" : "succeeded";
  if (state === "failed") process.exitCode = 1;
  return {
    state,
    version: VERSION,
    platform: process.platform,
    dataDir: ROOT_DIR,
    admin,
    summary,
    checks,
    warning: checks.some((item) => item.status === "fail") ? "存在阻断项，请根据提示处理" : "",
  };
}

async function commandStatus() {
  ensureStore();
  const [snapshot, dbInfo] = await Promise.all([getSystemSnapshot(), loadSignatureDb()]);
  const quarantine = quarantineStats();
  const lastScan = readLastScan();
  const status = buildStatus(snapshot, dbInfo, quarantine, lastScan);
  status.recentEvents = readEvents(12);
  status.plugin = { id: "com.ruodao.guard", version: VERSION, dataDir: ROOT_DIR };
  return { state: "succeeded", status };
}

async function commandAudit() {
  ensureStore();
  const [snapshot, startupSnapshot] = await Promise.all([getSystemSnapshot(), getStartupSnapshot()]);
  const audit = buildAudit(snapshot, startupSnapshot, readLastScan());
  return { state: "succeeded", admin: snapshot.admin === true, audit };
}

async function commandStartup() {
  const snapshot = await getStartupSnapshot();
  const detections = analyzeStartupItems(snapshot.startup, snapshot.tasks);
  return {
    state: "succeeded",
    startup: snapshot.startup,
    tasks: snapshot.tasks,
    detections,
    counts: { startup: snapshot.startup.length, tasks: snapshot.tasks.length, suspicious: detections.length },
    error: snapshot.error,
  };
}

async function commandScan(input) {
  const result = await scan(input);
  return { state: "succeeded", result };
}

async function commandFix(input) {
  requireConfirm(input, "加固修复");
  const catalog = fixCatalog();
  const requested = Array.isArray(input?.fixIds) ? input.fixIds : input?.fixId ? [input.fixId] : [];
  const ids = [...new Set(requested.map((entry) => String(entry ?? "").trim()).filter(Boolean))];
  if (!ids.length) throw new Error("没有指定要修复的项目");
  const unknown = ids.filter((id) => !catalog[id]);
  if (unknown.length) throw new Error(`不支持的修复项：${unknown.join("、")}`);
  if (!(await isAdmin())) {
    const error = new Error("加固修复需要管理员权限。请关闭若道，右键“以管理员身份运行”后重试。");
    error.needsAdmin = true;
    throw error;
  }
  const applied = [];
  const failed = [];
  for (const id of ids) {
    try {
      const result = await applyFix(id);
      applied.push(result);
      logEvent("fix", { id, ok: true });
    } catch (error) {
      failed.push({ id, title: catalog[id]?.title ?? id, error: String(error?.message ?? error) });
      logEvent("fix", { id, ok: false, error: String(error?.message ?? error) });
    }
  }
  return {
    state: failed.length ? "failed" : "succeeded",
    applied,
    failed,
    requiresReboot: applied.some((entry) => entry.requiresReboot),
    error: failed.length ? failed.map((entry) => `${entry.title}：${entry.error}`).join("；") : "",
  };
}

function resolveQuarantineTarget(file) {
  const target = path.resolve(String(file ?? "").trim());
  if (!target) throw new Error("缺少文件路径");
  const systemRoot = process.env.SystemRoot || "C:\\Windows";
  if (isInside(target, systemRoot)) throw new Error("为保护系统稳定，安全卫士不会隔离 Windows 系统目录内的文件，请交给 Defender 处理");
  if (isInside(target, PATHS.root)) throw new Error("不能隔离安全卫士自己的数据目录");
  if (isInside(target, PLUGIN_DIR)) throw new Error("不能隔离插件自身文件");
  return target;
}

async function quarantineOne(item) {
  const target = resolveQuarantineTarget(item?.path);
  const info = await fsp.lstat(target).catch(() => null);
  if (!info) throw new Error(`文件不存在：${target}`);
  if (info.isSymbolicLink()) throw new Error("不支持隔离符号链接");
  if (!info.isFile()) throw new Error("只能隔离普通文件");
  if (info.size > MAX_QUARANTINE_BYTES) throw new Error("文件超过 1GB，无法隔离");

  const id = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
  const { bin, meta } = quarantinePaths(id);
  await moveFile(target, bin);

  let sha256;
  try {
    sha256 = await sha256File(bin);
  } catch (error) {
    await moveFile(bin, target).catch(() => undefined);
    throw new Error(`隔离文件校验失败：${error.message}`);
  }
  const expected = String(item?.sha256 ?? "").trim().toLowerCase();
  if (expected && expected !== sha256) {
    try {
      await moveFile(bin, target);
    } catch (restoreError) {
      await atomicWriteJson(meta, {
        id,
        originalPath: target,
        name: item?.name || path.basename(target),
        ruleId: String(item?.ruleId ?? ""),
        severity: String(item?.severity ?? "medium"),
        sha256,
        size: info.size,
        quarantinedAt: new Date().toISOString(),
        verification: "mismatch",
      }).catch(() => undefined);
      throw new Error(`文件在扫描后发生变化，已保留在隔离区但未记录为威胁：${restoreError.message}`);
    }
    throw new Error("文件在扫描后发生变化（哈希不一致），已放回原位置，请重新扫描");
  }

  const record = {
    id,
    originalPath: target,
    name: String(item?.name || path.basename(target)).slice(0, 260),
    ruleId: String(item?.ruleId ?? "").slice(0, 120),
    severity: String(item?.severity ?? "medium"),
    sha256,
    size: info.size,
    quarantinedAt: new Date().toISOString(),
  };
  try {
    await atomicWriteJson(meta, record);
  } catch (error) {
    await moveFile(bin, target).catch(() => undefined);
    throw new Error(`写入隔离记录失败：${error.message}`);
  }
  return record;
}

async function commandQuarantine(input) {
  requireConfirm(input, "隔离文件");
  const items = Array.isArray(input?.items) ? input.items : input?.path ? [input] : [];
  if (!items.length) throw new Error("没有要隔离的文件");
  const quarantined = [];
  const failed = [];
  for (const item of items) {
    try {
      quarantined.push(await quarantineOne(item));
    } catch (error) {
      failed.push({ path: String(item?.path ?? ""), error: String(error?.message ?? error) });
    }
  }
  logEvent("quarantine", { count: quarantined.length, failed: failed.length });
  return {
    state: failed.length ? "failed" : "succeeded",
    quarantined,
    failed,
    error: failed.length ? failed.map((entry) => `${entry.path}：${entry.error}`).join("；") : "",
  };
}

async function commandQuarantineList() {
  const items = listQuarantine().map((entry) => {
    const id = String(entry.id ?? "");
    let binExists = false;
    try { binExists = fs.statSync(quarantinePaths(id).bin).isFile(); } catch { binExists = false; }
    return { ...entry, binExists };
  });
  return {
    state: "succeeded",
    items,
    count: items.length,
    bytes: items.reduce((sum, item) => sum + (Number(item.size) || 0), 0),
    dir: PATHS.quarantine,
  };
}

function readQuarantineMeta(id) {
  const safe = safeQuarantineId(id);
  const { bin, meta } = quarantinePaths(safe);
  const record = readJson(meta);
  if (!record) throw new Error("隔离记录不存在");
  let binExists = false;
  try { binExists = fs.statSync(bin).isFile(); } catch { binExists = false; }
  if (!binExists) throw new Error("隔离文件已丢失，无法恢复");
  return { record, bin, meta };
}

async function commandQuarantineRestore(input) {
  requireConfirm(input, "恢复隔离文件");
  const { record, bin, meta } = readQuarantineMeta(input?.id);
  let target = path.resolve(String(record.originalPath ?? ""));
  if (!record.originalPath) throw new Error("隔离记录缺少原始路径");
  let exists = false;
  try { exists = fs.statSync(target).isFile(); } catch { exists = false; }
  if (exists) target = `${target}.restored`;
  try { exists = fs.statSync(target).isFile(); } catch { exists = false; }
  if (exists) target = `${target}.${Date.now()}`;
  await moveFile(bin, target);
  await fsp.unlink(meta).catch(() => undefined);
  logEvent("quarantine-restore", { id: record.id, target });
  return { state: "succeeded", restored: { ...record, restoredPath: target } };
}

async function commandQuarantineDelete(input) {
  requireConfirm(input, "删除隔离文件");
  const safe = safeQuarantineId(input?.id);
  const { meta } = quarantinePaths(safe);
  if (!readJson(meta)) throw new Error("隔离记录不存在");
  await removeQuarantineEntry(safe);
  logEvent("quarantine-delete", { id: safe });
  return { state: "succeeded", id: safe };
}

async function commandDbInfo() {
  const info = await loadSignatureDb();
  let installedCheck = null;
  if (info.installed) {
    const raw = readJson(PATHS.userDb);
    const checksum = raw ? verifyChecksum(raw) : { ok: false, error: "无法读取已安装病毒库" };
    const signature = raw?.signature ? verifyDbSignature(raw, loadPublicKey().pem) : { ok: false, error: "未签名" };
    installedCheck = { checksum, signature };
  }
  return {
    state: "succeeded",
    current: dbStats(info.db),
    source: info.source,
    builtin: info.builtin,
    installed: info.installed,
    installedCheck,
    meta: info.meta,
    signed: Boolean(info.db.signature),
    publicKey: { fingerprint: info.publicKeyFingerprint, source: info.publicKeySource },
    warnings: info.warnings,
    dataDir: PATHS.db,
    format: info.db.format,
    description: info.db.description,
  };
}

async function installFromDb(db, options, previous) {
  const validation = validateDb(db);
  if (!validation.ok) throw new Error(validation.error);
  if (previous && compareDbVersion(db.version, previous.version) < 0) {
    throw new Error(`订阅源版本 ${db.version} 低于当前版本 ${previous.version}，已拒绝降级`);
  }
  const result = await installSignatureDb(db, options);
  logEvent("db-install", { source: options.source, version: result.stats.version, signed: result.signed });
  return {
    state: "succeeded",
    installed: result.stats,
    signed: result.signed,
    publicKeyFingerprint: result.publicKeyFingerprint,
    previous,
    source: options.source,
    url: options.url ?? "",
    warning: result.signed ? "" : "已安装未签名病毒库，请确认来源可信",
  };
}

async function commandDbUpdate(input) {
  requireConfirm(input, "安装病毒库");
  const url = String(input?.url ?? env("RUODAO_GUARD_DB_URL")).trim();
  const previousInfo = await loadSignatureDb();
  const db = await fetchSignatureDb(url, Math.max(5000, Number(env("RUODAO_GUARD_TIMEOUT", "30000")) || 30000));
  return installFromDb(db, { source: "subscription", url, allowUnsigned: allowUnsignedDb() }, previousInfo.installed ?? previousInfo.builtin);
}

async function commandDbImport(input) {
  requireConfirm(input, "导入病毒库");
  const file = path.resolve(String(input?.file ?? input?.path ?? "").trim());
  if (!file) throw new Error("缺少病毒库文件路径");
  const info = await fsp.stat(file).catch(() => null);
  if (!info || !info.isFile()) throw new Error(`文件不存在：${file}`);
  if (info.size > 20 * 1024 * 1024) throw new Error("病毒库文件超过 20MB 上限");
  let db;
  try { db = JSON.parse(await fsp.readFile(file, "utf8")); } catch { throw new Error("文件不是有效的 JSON"); }
  const previousInfo = await loadSignatureDb();
  return installFromDb(db, { source: "import", url: file, allowUnsigned: allowUnsignedDb() }, previousInfo.installed ?? previousInfo.builtin);
}

async function commandDbReset(input) {
  requireConfirm(input, "恢复内置病毒库");
  const previous = await loadSignatureDb();
  await resetSignatureDb();
  logEvent("db-reset", { previous: previous.installed?.version ?? "" });
  return {
    state: "succeeded",
    previous: previous.installed,
    current: previous.builtin,
    message: "已恢复内置病毒库",
  };
}

async function commandDefenderUpdate() {
  const result = await updateDefenderSignatures();
  logEvent("defender-update", { version: result.signatureVersion });
  return { state: "succeeded", result };
}

async function commandDefenderScan() {
  const result = await runDefenderQuickScan();
  logEvent("defender-scan", { elapsedSec: result.elapsedSec, threats: result.threats.length });
  return { state: "succeeded", result };
}

// 云端 AI 诊断：把本机安全状态与加固体检结果交给若道云端模型分析。
// 复用宿主注入的 RUODAO_LLM_* 契约（应用内来自模型库，独立版来自账号网关），
// 插件本身不保存任何凭据。
async function commandAiDiagnose(input) {
  const focus = String(input?.focus ?? "").trim().slice(0, 2000);
  const [statusData, auditData] = await Promise.all([
    commandStatus(),
    commandAudit().catch(() => null),
  ]);
  if (statusData.state !== "succeeded") throw new Error("安全状态读取失败，无法进行 AI 诊断");
  const evidence = {
    status: statusData.status,
    audit: auditData?.audit ?? null,
  };
  const evidenceText = JSON.stringify(evidence);
  if (evidenceText.length > 120_000) throw new Error("本机安全数据过大，请稍后重试");

  const endpoint = chatEndpoint(env("RUODAO_LLM_BASE_URL"));
  const apiKey = env("RUODAO_LLM_API_KEY");
  const model = env("RUODAO_LLM_MODEL");
  if (!endpoint || !model) throw new Error("未配置 AI 模型：请先登录若道账号并选择云端模型（或在应用内模型管理中配置）");
  const system = [
    "你是 Windows 安全专家，负责解读安全卫士插件采集的本机安全数据。",
    "基于提供的 JSON 证据给出简明中文诊断：1) 总体安全评估（2-3 句）；2) 主要风险点（按严重程度排序，每条说明风险与理由）；",
    "3) 建议操作（可执行的具体步骤，注明哪些需要管理员权限）。",
    "只基于证据判断，不要编造未提供的检测项；证据为空的部分不要展开。",
  ].join("\n");
  const user = [focus ? `用户关注点：${focus}` : "", "——以下为本机安全检测数据（JSON）——", evidenceText].filter(Boolean).join("\n\n");

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new Error("AI 请求超时")), Math.max(30000, Number(input?.timeoutMs ?? 180000) || 180000));
  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) },
      body: JSON.stringify({ model, temperature: 0.3, messages: [{ role: "system", content: system }, { role: "user", content: user }] }),
      signal: ac.signal,
    });
  } finally { clearTimeout(timer); }
  if (!response.ok) {
    const detail = (await response.text().catch(() => "")).slice(0, 300);
    throw new Error(`AI 请求失败（HTTP ${response.status}）：${detail}`);
  }
  const data = await response.json();
  const result = String(data?.choices?.[0]?.message?.content ?? "").trim();
  if (!result) throw new Error("AI 未返回内容");
  logEvent("ai-diagnose", { model });
  return { state: "succeeded", model, result };
}

// AI 管家：对话式调度插件全部命令（读操作直接执行，写入/破坏性操作先请用户确认）。
async function commandAgent(input) {
  return runAgent(input, {
    binPath: fileURLToPath(import.meta.url),
    cwd: PLUGIN_DIR,
    tools: agentTools,
    systemPrompt,
    contextText,
    preparePayload,
    compact,
  });
}

async function main() {
  if (!COMMAND) throw new Error("缺少命令参数");
  const input = await readStdin();
  switch (COMMAND) {
    case "doctor": return commandDoctor();
    case "status": return commandStatus();
    case "scan": return commandScan(input);
    case "audit": return commandAudit();
    case "startup": return commandStartup();
    case "fix": return commandFix(input);
    case "quarantine": return commandQuarantine(input);
    case "quarantine-list": return commandQuarantineList();
    case "quarantine-restore": return commandQuarantineRestore(input);
    case "quarantine-delete": return commandQuarantineDelete(input);
    case "db-info": return commandDbInfo();
    case "db-update": return commandDbUpdate(input);
    case "db-import": return commandDbImport(input);
    case "db-reset": return commandDbReset(input);
    case "defender-update": return commandDefenderUpdate();
    case "defender-scan": return commandDefenderScan();
    case "ai-diagnose": return commandAiDiagnose(input);
    case "agent": return commandAgent(input);
    default: throw new Error(`未知命令：${COMMAND}`);
  }
}

main()
  .then((payload) => { emit(payload); })
  .catch((error) => { fail(error?.message ?? error, error?.needsAdmin ? { needsAdmin: true } : {}); });
