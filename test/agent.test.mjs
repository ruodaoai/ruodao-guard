import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_DIR = fileURLToPath(new URL("..", import.meta.url));
const CLI = path.join(PLUGIN_DIR, "bin", "guard.mjs");
const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "ruodao-guard-agent-"));

after(() => {
  try { fs.rmSync(TEST_HOME, { recursive: true, force: true }); } catch { /* 忽略清理失败 */ }
});

function toolCall(id, name, args) {
  return {
    role: "assistant",
    content: "",
    tool_calls: [{ id, type: "function", function: { name, arguments: JSON.stringify(args ?? {}) } }],
  };
}

function reply(content) {
  return { role: "assistant", content };
}

async function stubServer(script) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      let parsed = null;
      try { parsed = JSON.parse(body); } catch { parsed = null; }
      requests.push({ url: req.url, body: parsed });
      const message = script[Math.min(requests.length - 1, script.length - 1)];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ choices: [{ message }], usage: { total_tokens: 1 } }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const llmEnv = (baseUrl) => ({ RUODAO_LLM_BASE_URL: baseUrl, RUODAO_LLM_MODEL: "stub-model", RUODAO_LLM_API_KEY: "test-key" });

function runAgent(payload, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, RUODAO_GUARD_HOME: TEST_HOME, ...extraEnv };
    if (!extraEnv.RUODAO_LLM_BASE_URL) {
      delete env.RUODAO_LLM_BASE_URL;
      delete env.RUODAO_LLM_MODEL;
    }
    const child = spawn(process.execPath, [CLI, "agent"], { cwd: PLUGIN_DIR, windowsHide: true, env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", () => {
      const line = String(stdout).trim().split(/\r?\n/).filter(Boolean).at(-1) ?? "";
      let data = null;
      try { data = JSON.parse(line); } catch { data = null; }
      if (!data) reject(new Error(`非 JSON 输出：${stdout || stderr}`));
      else resolve(data);
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

test("AI 管家工具覆盖清单中的全部命令（agent 自身除外）", async () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(PLUGIN_DIR, "ruodao-plugin.json"), "utf8"));
  const commands = manifest.contributes.commands.map((command) => String(command.id).split(".").pop());
  const { tools } = await import("../lib/agent-tools.mjs");
  for (const name of commands) {
    if (name === "agent") continue;
    assert.ok(tools[name], `缺少工具：${name}`);
  }
});

test("只读工具自动执行，高风险工具等待审批，批准后继续", async () => {
  const stub = await stubServer([
    toolCall("call_info", "db-info", {}),
    toolCall("call_reset", "db-reset", {}),
    reply("当前病毒库已确认，并已恢复内置版本。"),
  ]);
  try {
    const first = await runAgent({ messages: [{ role: "user", content: "检查病毒库并恢复内置库" }] }, llmEnv(stub.baseUrl));
    assert.equal(first.state, "succeeded");
    assert.equal(first.status, "awaiting_approval");
    assert.equal(first.pending.command, "db-reset");
    assert.equal(first.pending.risk, "destructive");
    assert.equal(first.steps.length, 1);
    assert.equal(first.steps[0].command, "db-info");
    assert.equal(first.steps[0].ok, true);
    assert.equal(stub.requests[0].url, "/chat/completions");
    assert.ok(stub.requests[0].body.tools.some((tool) => tool.function.name === "quarantine"));

    const second = await runAgent({ messages: first.messages, approvals: [first.pending.id] }, llmEnv(stub.baseUrl));
    assert.equal(second.status, "done");
    assert.equal(second.reply, "当前病毒库已确认，并已恢复内置版本。");
    const resetStep = second.steps.find((step) => step.command === "db-reset");
    assert.equal(resetStep.ok, true);
    const toolMessage = stub.requests[1].body.messages.find((message) => message.role === "tool");
    assert.ok(toolMessage.content.includes("病毒库"));
  } finally {
    await stub.close();
  }
});

test("拒绝高风险工具时不执行并回传拒绝结果", async () => {
  const stub = await stubServer([
    toolCall("call_reset", "db-reset", {}),
    reply("已取消，没有改动病毒库。"),
  ]);
  try {
    const first = await runAgent({ messages: [{ role: "user", content: "恢复内置病毒库" }] }, llmEnv(stub.baseUrl));
    assert.equal(first.status, "awaiting_approval");
    const second = await runAgent({ messages: first.messages, rejections: [first.pending.id] }, llmEnv(stub.baseUrl));
    assert.equal(second.status, "done");
    const resetStep = second.steps.find((step) => step.command === "db-reset");
    assert.equal(resetStep.rejected, true);
    assert.equal(resetStep.ok, false);
    const toolMessage = stub.requests[1].body.messages.find((message) => message.role === "tool");
    assert.ok(toolMessage.content.includes("拒绝"));
  } finally {
    await stub.close();
  }
});

test("工具执行失败以错误结果回传，不中断本轮对话", async () => {
  const stub = await stubServer([
    toolCall("call_restore", "quarantine-restore", { id: "not-a-real-id-xyz" }),
    reply("该隔离记录不存在。"),
  ]);
  try {
    // 恢复属于高风险工具，先审批后执行，执行失败应回传错误
    const first = await runAgent({ messages: [{ role: "user", content: "恢复隔离文件" }] }, llmEnv(stub.baseUrl));
    assert.equal(first.status, "awaiting_approval");
    const second = await runAgent({ messages: first.messages, approvals: [first.pending.id] }, llmEnv(stub.baseUrl));
    assert.equal(second.status, "done");
    const step = second.steps.find((entry) => entry.command === "quarantine-restore");
    assert.equal(step.ok, false);
    assert.ok(step.error);
    const toolMessage = stub.requests[1].body.messages.find((message) => message.role === "tool");
    assert.equal(JSON.parse(toolMessage.content.split("\n")[0]).ok, false);
  } finally {
    await stub.close();
  }
});

test("缺少模型配置时返回明确错误", async () => {
  const result = await runAgent({ messages: [{ role: "user", content: "你好" }] });
  assert.equal(result.state, "failed");
  assert.ok(String(result.error).includes("未配置 AI 模型"));
});
