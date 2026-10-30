#!/usr/bin/env node
/**
 * 开放病毒库签名工具（维护者使用，不随运行时执行）。
 *
 *   keygen --private <path> --public <path> [--force]
 *   sign --db <input.json> --key <private.pem> [--out <signed.json>] [--publisher <name>]
 *   verify --db <signed.json> --key <public.pem|base64>
 *   public-key --key <private.pem> [--out <public.pem>] [--base64]
 *   fingerprint --key <public.pem>
 *
 * 私钥只应保存在维护者本地，绝不能提交到仓库或打进插件 ZIP。
 */

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { canonicalJson, validateDb, verifyDbSignature, verifyChecksum, keyFingerprint, dbStats } from "../lib/signatures.mjs";

function parseArgs(argv) {
  const args = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) { args._.push(token); continue; }
    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) { args[key] = true; continue; }
    args[key] = next;
    index += 1;
  }
  return args;
}

function emit(payload) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

function fail(message) {
  emit({ state: "failed", error: String(message) });
  process.exit(1);
}

function requireArg(args, name) {
  const value = args[name];
  if (!value || value === true) throw new Error(`缺少参数 --${name}`);
  return String(value);
}

async function readJson(file) {
  return JSON.parse(await fsp.readFile(file, "utf8"));
}

async function writeJson(file, value) {
  await fsp.mkdir(path.dirname(path.resolve(file)), { recursive: true });
  await fsp.writeFile(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function exists(file) {
  try { await fsp.access(file); return true; } catch { return false; }
}

async function keygen(args) {
  const privateFile = path.resolve(String(args.private ?? "ruodao-guard-signing-key.pem"));
  const publicFile = path.resolve(String(args.public ?? "ruodao-guard-public-key.pem"));
  if (!args.force && (await exists(privateFile) || await exists(publicFile))) {
    throw new Error("密钥文件已存在；如确认要覆盖旧密钥，请加 --force（覆盖后旧病毒库签名将无法验证）");
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" });
  await fsp.mkdir(path.dirname(privateFile), { recursive: true });
  await fsp.writeFile(privateFile, privatePem, { encoding: "utf8", mode: 0o600 });
  await fsp.writeFile(publicFile, publicPem, { encoding: "utf8" });
  return {
    state: "succeeded",
    privateKey: privateFile,
    publicKey: publicFile,
    publicKeyBase64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    fingerprint: keyFingerprint(publicPem),
    warning: "私钥仅保存在本机，不要提交仓库或打包进插件。",
  };
}

async function sign(args) {
  const dbFile = path.resolve(requireArg(args, "db"));
  const keyFile = path.resolve(requireArg(args, "key"));
  const db = await readJson(dbFile);
  const check = validateDb(db);
  if (!check.ok) throw new Error(check.error);
  if (args.publisher) db.publisher = String(args.publisher);
  delete db.signature;
  delete db.checksum;
  db.checksum = crypto.createHash("sha256").update(canonicalJson(db), "utf8").digest("hex");
  const privateKey = crypto.createPrivateKey(await fsp.readFile(keyFile, "utf8"));
  db.signature = crypto.sign(null, Buffer.from(canonicalJson(db), "utf8"), privateKey).toString("base64");
  const out = path.resolve(String(args.out ?? dbFile.replace(/\.json$/i, "") + ".signed.json"));
  await writeJson(out, db);
  return { state: "succeeded", out, stats: dbStats(db), signed: true, checksum: db.checksum };
}

async function verify(args) {
  const db = await readJson(path.resolve(requireArg(args, "db")));
  const keyInput = String(args.key ?? "").trim();
  let key;
  if (!keyInput) {
    key = await fsp.readFile(path.resolve(requireArg(args, "key")), "utf8");
  } else if (keyInput.includes("BEGIN PUBLIC KEY")) {
    key = keyInput;
  } else if (await exists(keyInput)) {
    key = await fsp.readFile(keyInput, "utf8");
  } else {
    key = crypto.createPublicKey({ key: Buffer.from(keyInput, "base64"), format: "der", type: "spki" }).export({ type: "spki", format: "pem" });
  }
  const signature = verifyDbSignature(db, key);
  const checksum = verifyChecksum(db);
  const ok = signature.ok && checksum.ok;
  return {
    state: ok ? "succeeded" : "failed",
    signature,
    checksum,
    stats: dbStats(db),
    fingerprint: keyFingerprint(key),
  };
}

async function publicKey(args) {
  const keyFile = path.resolve(requireArg(args, "key"));
  const privateKey = crypto.createPrivateKey(await fsp.readFile(keyFile, "utf8"));
  const publicKeyObject = crypto.createPublicKey(privateKey);
  const pem = publicKeyObject.export({ type: "spki", format: "pem" });
  if (args.out) await fsp.writeFile(path.resolve(String(args.out)), pem, "utf8");
  return {
    state: "succeeded",
    fingerprint: keyFingerprint(pem),
    publicKeyPem: args.out ? undefined : pem.trim(),
    publicKeyBase64: publicKeyObject.export({ type: "spki", format: "der" }).toString("base64"),
    out: args.out ? path.resolve(String(args.out)) : undefined,
  };
}

async function fingerprint(args) {
  const pem = await fsp.readFile(path.resolve(requireArg(args, "key")), "utf8");
  return { state: "succeeded", fingerprint: keyFingerprint(pem) };
}

async function main() {
  const command = process.argv[2];
  const args = parseArgs(process.argv.slice(3));
  switch (command) {
    case "keygen": return keygen(args);
    case "sign": return sign(args);
    case "verify": return verify(args);
    case "public-key": return publicKey(args);
    case "fingerprint": return fingerprint(args);
    default: throw new Error("用法：keygen | sign | verify | public-key | fingerprint");
  }
}

main()
  .then((payload) => emit(payload))
  .catch((error) => fail(error?.message ?? error));
