import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const PLUGIN_DIR = fileURLToPath(new URL("..", import.meta.url));
const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "ruodao-guard-test-"));
process.env.RUODAO_GUARD_HOME = TEST_HOME;

const store = await import("../lib/store.mjs");
const signatures = await import("../lib/signatures.mjs");
const scanner = await import("../lib/scanner.mjs");
const status = await import("../lib/status.mjs");
const system = await import("../lib/system.mjs");

const FIXTURES = fs.mkdtempSync(path.join(os.tmpdir(), "ruodao-guard-fixtures-"));

after(() => {
  try { fs.rmSync(TEST_HOME, { recursive: true, force: true }); } catch { /* 忽略清理失败 */ }
  try { fs.rmSync(FIXTURES, { recursive: true, force: true }); } catch { /* 忽略清理失败 */ }
});

function writeFixture(name, content) {
  const file = path.join(FIXTURES, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  return file;
}

function sha256FileSync(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function runCli(command, input = {}, extraEnv = {}) {
  const result = spawnSync(process.execPath, [path.join(PLUGIN_DIR, "bin", "guard.mjs"), command], {
    cwd: PLUGIN_DIR,
    env: { ...process.env, RUODAO_GUARD_HOME: TEST_HOME, ...extraEnv },
    input: JSON.stringify(input),
    encoding: "utf8",
    timeout: 120000,
  });
  const lines = String(result.stdout ?? "").trim().split(/\r?\n/).filter(Boolean);
  let payload = null;
  try { payload = JSON.parse(lines.at(-1)); } catch { payload = null; }
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, payload };
}

function baseSnapshot(overrides = {}) {
  return {
    supported: true,
    partial: false,
    platform: "win32",
    admin: false,
    os: { caption: "Windows 11", version: "10.0.22631", build: 22631, architecture: "64-bit" },
    defender: {
      present: true, antivirusEnabled: false, realtimeEnabled: false, behaviorMonitorEnabled: false,
      ioavEnabled: false, onAccessEnabled: false, tamperProtected: false, signatureVersion: "",
      signatureUpdated: null, signatureAgeDays: null, engineVersion: "0.0.0.0", lastQuickScan: null, lastFullScan: null,
    },
    avProducts: [
      { name: "Lenovo Anti-Virus powered by Huorong Security", state: 262144 },
      { name: "360 安全套装", state: 331776 },
      { name: "Windows Defender", state: 393472 },
    ],
    firewall: { known: true, enabled: true, profiles: [{ name: "Domain", enabled: true }, { name: "Private", enabled: true }, { name: "Public", enabled: true }] },
    uac: { known: true, enabled: true, consentPrompt: 5 },
    smb: { supported: true, smb1Enabled: false },
    autorun: { known: true, disabled: true, noAutorun: 1, noDriveTypeAutoRun: 255 },
    rdp: { known: true, enabled: false, nla: true },
    guest: { supported: true, enabled: false },
    wdigest: { enabled: false },
    lsa: { runAsPPL: 1 },
    defenderExclusions: { paths: [], extensions: [], processes: [], puaProtection: 0 },
    threats: [],
    hosts: "",
    proxy: { enabled: false, server: "", autoConfigUrl: "" },
    secureBoot: true,
    error: "",
    ...overrides,
  };
}

const DB_STUB = {
  db: { version: "2026.10.22.1", format: "ruodao-guard-signatures/1", rules: { hashes: [], heuristics: [] } },
  source: "builtin",
  builtin: { version: "2026.10.22.1" },
  installed: null,
  meta: {},
  publicKeyFingerprint: "TEST",
  publicKeySource: "builtin",
  warnings: [],
};

test("manifest declares unique process commands and whitelisted permissions", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(PLUGIN_DIR, "ruodao-plugin.json"), "utf8"));
  assert.equal(manifest.id, "com.ruodao.guard");
  assert.equal(manifest.contributes.commands[0].id.startsWith("com.ruodao.guard."), true);
  const ids = manifest.contributes.commands.map((entry) => entry.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const command of manifest.contributes.commands) {
    assert.equal(command.action.type, "process");
    assert.deepEqual(command.action.args.slice(0, 1), ["bin/guard.mjs"]);
  }
  const whitelist = new Set(["filesystem-read", "filesystem-write", "network", "process"]);
  for (const permission of manifest.permissions) assert.ok(whitelist.has(permission), `未知权限：${permission}`);
  const required = ["status", "scan", "audit", "fix", "quarantine", "db-update", "defender-update"];
  for (const suffix of required) assert.ok(ids.includes(`com.ruodao.guard.${suffix}`), `缺少命令 ${suffix}`);
});

test("built-in DB carries the EICAR hash and open heuristic rules", async () => {
  const info = await signatures.loadSignatureDb();
  assert.equal(info.source, "builtin");
  const hashes = info.db.rules.hashes.map((entry) => entry.sha256);
  assert.ok(hashes.includes("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"));
  assert.ok(info.db.rules.heuristics.length >= 10);
  assert.equal(info.publicKeyFingerprint, "D0B7 4FD6 8BB4 04D7");
});

test("third-party AV keeps the Defender-passive system safe and auditable", () => {
  const lastScan = {
    mode: "quick",
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    summary: { total: 0, high: 0, medium: 0, low: 0, info: 0 },
    detections: [],
  };
  const evaluation = status.evaluate(baseSnapshot(), DB_STUB, { count: 0, bytes: 0 }, lastScan);
  assert.equal(evaluation.engine.mode, "third-party");
  assert.deepEqual(evaluation.engine.thirdPartyActive, ["360 安全套装"]);
  assert.equal(evaluation.risks.some((risk) => risk.id === "defender-disabled" || risk.id === "realtime-disabled"), false);
  assert.equal(evaluation.score, 100);
  assert.equal(evaluation.level, "safe");

  const audit = status.buildAudit(baseSnapshot(), { startup: [], tasks: [] }, lastScan);
  const byId = Object.fromEntries(audit.checks.map((entry) => [entry.id, entry]));
  assert.equal(byId["av-engine"].status, "pass");
  assert.equal(byId.realtime.status, "pass");
  assert.equal(byId.signatures.status, "pass");
  assert.equal(byId.autorun.status, "pass");
  assert.equal(byId.lsa.status, "pass");
  assert.equal(byId["last-scan"].status, "pass");
  assert.equal(audit.summary.fail, 0);
});

test("Defender-off without any active AV is still a high risk", () => {
  const snapshot = baseSnapshot({
    avProducts: [{ name: "Lenovo Anti-Virus powered by Huorong Security", state: 262144 }, { name: "Windows Defender", state: 393472 }],
  });
  const evaluation = status.evaluate(snapshot, DB_STUB, { count: 0, bytes: 0 }, null);
  assert.equal(evaluation.engine.mode, "none");
  assert.equal(evaluation.risks.some((risk) => risk.id === "defender-disabled"), true);
  assert.ok(evaluation.score <= 80);
});

test("scanner detects hash, heuristic, structure and leaves benign files alone", async () => {
  const dir = path.join(FIXTURES, "scan");
  fs.mkdirSync(dir, { recursive: true });
  const known = path.join(dir, "known.bin");
  fs.writeFileSync(known, Buffer.from("ruodao-guard-test-malware\x00\x01", "utf8"));
  const knownHash = sha256FileSync(known);
  fs.writeFileSync(path.join(dir, "encoded.ps1"), "powershell.exe -EncodedCommand ZQBjAGgAbwA=\r\n");
  fs.writeFileSync(path.join(dir, "invoice.pdf.exe"), "MZ fake");
  fs.writeFileSync(path.join(dir, "photo.jpg"), Buffer.from("MZ\x90\x00fake-pe", "binary"));
  fs.writeFileSync(path.join(dir, "HOW_TO_DECRYPT.txt"), "pay bitcoin");
  fs.writeFileSync(path.join(dir, "notes.txt"), "hello world");

  const testDb = {
    format: signatures.DB_FORMAT,
    version: "2026.10.22.99",
    releasedAt: new Date().toISOString(),
    publisher: "Test",
    rules: {
      hashes: [{ sha256: knownHash, name: "Test.Known", severity: "high" }],
      heuristics: [{ id: "TEST-PS-ENCODED", title: "测试编码 PowerShell", severity: "high", pattern: "powershell[^\\n]{0,40}-enc", flags: "i", extensions: ["ps1"] }],
    },
  };
  await signatures.installSignatureDb(testDb, { source: "test", allowUnsigned: true });
  try {
    const result = await scanner.scan({ mode: "custom", paths: [dir], includeProcesses: false, includeStartup: false, maxSeconds: 10 });
    const rules = result.detections.map((entry) => entry.ruleId);
    assert.ok(rules.includes("Test.Known"), `缺少 hash 命中：${rules.join(",")}`);
    assert.ok(rules.includes("TEST-PS-ENCODED"), `缺少启发式命中：${rules.join(",")}`);
    assert.ok(rules.includes("STRUCT-DOUBLE-EXT"));
    assert.ok(rules.includes("STRUCT-PE-DISGUISE"));
    assert.ok(rules.includes("STRUCT-RANSOM-NOTE"));
    assert.equal(result.detections.some((entry) => entry.path.endsWith("notes.txt")), false);
    assert.equal(result.summary.high >= 4, true);
  } finally {
    await signatures.resetSignatureDb();
  }
});

test("startup analyzer flags encoded PowerShell and marks tasks", () => {
  const detections = scanner.analyzeStartupItems(
    [{ name: "Updater", command: "powershell.exe -EncodedCommand ZQBjAGgAbwA=", source: "HKCU Run" }],
    [{ name: "Cleanup", path: "\\Custom\\", command: "cmd.exe /c start" }],
  );
  assert.equal(detections.length, 1);
  assert.equal(detections[0].kind, "startup");
  assert.equal(detections[0].severity, "high");
});

test("quarantine requires confirmation, re-hashes, restores and deletes", () => {
  const file = writeFixture("quarantine/sample.exe", "MZ harmless test payload");
  const hash = sha256FileSync(file);

  const denied = runCli("quarantine", { path: file, sha256: hash });
  assert.equal(denied.payload?.state, "failed");
  assert.ok(fs.existsSync(file));

  const mismatch = runCli("quarantine", { confirm: true, path: file, sha256: "0".repeat(64) });
  assert.equal(mismatch.payload?.state, "failed");
  assert.ok(fs.existsSync(file));

  const created = runCli("quarantine", { confirm: true, path: file, sha256: hash, name: "sample.exe", ruleId: "TEST", severity: "high" });
  assert.equal(created.payload?.state, "succeeded", created.stdout + created.stderr);
  assert.equal(created.payload.quarantined.length, 1);
  assert.equal(fs.existsSync(file), false);
  const id = created.payload.quarantined[0].id;

  const listed = runCli("quarantine-list");
  assert.equal(listed.payload?.count, 1);
  assert.equal(listed.payload.items[0].id, id);
  assert.equal(listed.payload.items[0].binExists, true);

  const restored = runCli("quarantine-restore", { id, confirm: true });
  assert.equal(restored.payload?.state, "succeeded", restored.stdout + restored.stderr);
  assert.equal(fs.existsSync(file), true);
  assert.equal(fs.readFileSync(file, "utf8"), "MZ harmless test payload");

  const again = runCli("quarantine", { confirm: true, path: file, sha256: hash });
  assert.equal(again.payload?.state, "succeeded");
  const secondId = again.payload.quarantined[0].id;
  const deleted = runCli("quarantine-delete", { id: secondId, confirm: true });
  assert.equal(deleted.payload?.state, "succeeded");
  assert.equal(fs.existsSync(file), false);
  assert.equal(fs.existsSync(store.quarantinePaths(secondId).bin), false);
});

test("unsigned DB import is rejected by default and accepted only with opt-in", () => {
  const file = path.join(TEST_HOME, "unsigned-db.json");
  fs.writeFileSync(file, JSON.stringify({
    format: signatures.DB_FORMAT,
    version: "2026.10.22.50",
    releasedAt: new Date().toISOString(),
    publisher: "Test",
    rules: { hashes: [], heuristics: [] },
  }));

  const rejected = runCli("db-import", { file, confirm: true });
  assert.equal(rejected.payload?.state, "failed");
  assert.match(String(rejected.payload?.error), /未签名/);

  const accepted = runCli("db-import", { file, confirm: true }, { RUODAO_GUARD_ALLOW_UNSIGNED: "1" });
  assert.equal(accepted.payload?.state, "succeeded", accepted.stdout + accepted.stderr);
  assert.equal(accepted.payload.installed.version, "2026.10.22.50");

  const info = runCli("db-info");
  assert.equal(info.payload?.source, "user");
  assert.equal(info.payload.current.version, "2026.10.22.50");

  const reset = runCli("db-reset", { confirm: true });
  assert.equal(reset.payload?.state, "succeeded");
  assert.equal(reset.payload.current.version, "2026.10.22.1");
});

test("Ed25519-signed feed installs over localhost HTTP and rejects tampering", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const previousKey = process.env.RUODAO_GUARD_PUBLIC_KEY;
  process.env.RUODAO_GUARD_PUBLIC_KEY = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  try {
    const db = {
      format: signatures.DB_FORMAT,
      version: "2026.10.22.80",
      releasedAt: new Date().toISOString(),
      publisher: "Test Signer",
      rules: { hashes: [], heuristics: [] },
    };
    db.checksum = crypto.createHash("sha256").update(signatures.canonicalJson(db)).digest("hex");
    db.signature = crypto.sign(null, Buffer.from(signatures.canonicalJson(db), "utf8"), privateKey).toString("base64");

    const server = http.createServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(db));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const fetched = await signatures.fetchSignatureDb(`http://127.0.0.1:${port}/signatures.json`);
      const installed = await signatures.installSignatureDb(fetched, { source: "subscription", url: "test" });
      assert.equal(installed.signed, true);
      assert.equal(installed.stats.version, "2026.10.22.80");

      const info = await signatures.loadSignatureDb();
      assert.equal(info.source, "user");
      assert.equal(info.db.version, "2026.10.22.80");
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }

    const tampered = { ...db, version: "2026.10.22.81" };
    await assert.rejects(
      () => signatures.installSignatureDb(tampered, { allowUnsigned: true }),
      /签名校验失败/,
    );
  } finally {
    await signatures.resetSignatureDb();
    if (previousKey === undefined) delete process.env.RUODAO_GUARD_PUBLIC_KEY;
    else process.env.RUODAO_GUARD_PUBLIC_KEY = previousKey;
  }
});

test("fix command refuses unconfirmed and unsupported fixes", async () => {
  const unconfirmed = runCli("fix", { fixIds: ["autorun"] });
  assert.equal(unconfirmed.payload?.state, "failed");
  assert.match(String(unconfirmed.payload?.error), /确认/);

  const unsupported = runCli("fix", { fixIds: ["not-a-real-fix"], confirm: true });
  assert.equal(unsupported.payload?.state, "failed");
  assert.match(String(unsupported.payload?.error), /不支持/);
});

test("doctor and db-info run as real CLI entry points", () => {
  const doctor = runCli("doctor");
  const manifest = JSON.parse(fs.readFileSync(path.join(PLUGIN_DIR, "plugin.json"), "utf8"));
  assert.ok(["succeeded", "failed"].includes(doctor.payload?.state));
  assert.equal(doctor.payload.version, manifest.version);
  assert.ok(Array.isArray(doctor.payload.checks));
  assert.equal(doctor.payload.checks.some((entry) => entry.id === "signature-db" && entry.status === "pass"), true);

  const info = runCli("db-info");
  assert.equal(info.payload?.state, "succeeded");
  assert.equal(info.payload.source, "builtin");
  assert.equal(info.payload.current.hashes >= 1, true);
});

test("system module exposes only fixed, reboot-aware fix scripts", async () => {
  const catalog = system.fixCatalog();
  assert.deepEqual(Object.keys(catalog).sort(), ["autorun", "defender-realtime", "firewall", "guest", "lsa", "rdp-nla", "smb1", "uac", "wdigest"]);
  assert.equal(catalog.lsa.requiresReboot, true);
  assert.equal(catalog.firewall.requiresReboot, false);
  await assert.rejects(() => system.applyFix("not-a-real-fix"), /未知修复项/);
});
