/**
 * 插件内置 AI 管家核心：OpenAI 兼容 tools 协议 + 多步工具执行 + 审批恢复。
 *
 * 设计要点：
 * - 无状态：会话以 messages 数组往返，宿主（工作台）负责持久化。
 * - 复权：每次工具调用重新拉起插件命令进程，行为与手动操作完全一致。
 * - 审批：写入/破坏性工具先返回 pending，宿主确认后带 approvals 重新进入。
 */
import { spawn } from "node:child_process";
import path from "node:path";

const MAX_TOOL_RESULT_CHARS = 9000;
const MAX_TOOL_CALLS = 16;

const RISK_HINT = {
  read: "（只读，可直接执行）",
  write: "（会写入文件，执行前需用户确认）",
  destructive: "（高风险操作，执行前必须经用户确认）",
};

export const RISK_LABEL = { read: "只读", write: "写入", destructive: "高风险" };

export function chatEndpoint(baseUrl) {
  const base = String(baseUrl ?? "").trim().replace(/\/+$/, "");
  if (!base) return "";
  return /\/chat\/completions$/i.test(base) ? base : `${base}/chat/completions`;
}

function normalizeMessage(message) {
  if (!message || typeof message !== "object") return null;
  const role = String(message.role ?? "");
  if (!["user", "assistant", "tool"].includes(role)) return null;
  const next = { role, content: typeof message.content === "string" ? message.content : String(message.content ?? "") };
  if (role === "assistant" && Array.isArray(message.tool_calls) && message.tool_calls.length) {
    next.tool_calls = message.tool_calls.map((call) => ({
      id: String(call?.id ?? ""),
      type: "function",
      function: {
        name: String(call?.function?.name ?? ""),
        arguments: typeof call?.function?.arguments === "string" ? call.function.arguments : JSON.stringify(call?.function?.arguments ?? {}),
      },
    })).filter((call) => call.id && call.function.name);
  }
  if (role === "tool") next.tool_call_id = String(message.tool_call_id ?? "");
  return next;
}

export function normalizeMessages(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.map(normalizeMessage).filter(Boolean).slice(-60);
}

function parseArguments(raw) {
  if (raw && typeof raw === "object") return raw;
  const text = String(raw ?? "").trim();
  if (!text) return {};
  try { return JSON.parse(text); } catch { throw new Error("工具参数不是合法 JSON"); }
}

function parseStdout(stdout) {
  const lines = String(stdout ?? "").trim().split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try { return JSON.parse(lines[index]); } catch { /* 继续向上找 */ }
  }
  return null;
}

export function toolDefinitions(tools) {
  return Object.entries(tools).map(([name, spec]) => ({
    type: "function",
    function: {
      name,
      description: `${spec.description}${RISK_HINT[spec.risk] ?? ""}`,
      parameters: spec.parameters ?? { type: "object", properties: {} },
    },
  }));
}

function runProcess({ binPath, cwd, command, payload, env, timeoutMs }) {
  return new Promise((resolve) => {
    const started = Date.now();
    let child;
    try {
      child = spawn(process.execPath, [binPath, command], { cwd, windowsHide: true, env });
    } catch (error) {
      resolve({ ok: false, error: String(error?.message ?? error), durationMs: 0 });
      return;
    }
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      resolve({ ok: false, error: `工具执行超时（${timeoutMs}ms）`, durationMs: Date.now() - started });
    }, Math.max(5000, Number(timeoutMs) || 120000));
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ok: false, error: `工具启动失败：${String(error?.message ?? error)}`, durationMs: Date.now() - started });
    });
    child.on("close", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const data = parseStdout(stdout);
      if (!data) {
        resolve({ ok: false, error: String(stderr || stdout || "工具没有返回结果").slice(0, 800), durationMs: Date.now() - started });
        return;
      }
      if (data.state === "failed") {
        resolve({ ok: false, error: String(data.error ?? "工具执行失败"), data, durationMs: Date.now() - started });
        return;
      }
      resolve({ ok: true, data, durationMs: Date.now() - started });
    });
    child.stdin.on("error", () => { /* 子进程提前退出时忽略 */ });
    child.stdin.end(JSON.stringify(payload));
  });
}

function truncate(text, limit) {
  const value = String(text ?? "");
  return value.length > limit ? `${value.slice(0, limit)}\n…（已截断，原长 ${value.length} 字符）` : value;
}

function toolContent(result) {
  const text = JSON.stringify(result);
  return truncate(text, MAX_TOOL_RESULT_CHARS);
}

function previewArguments(args) {
  const text = JSON.stringify(args ?? {});
  return text.length > 600 ? `${text.slice(0, 600)}…` : text;
}

export function defaultLimitFor(name, spec) {
  return spec.timeoutMs ?? 120000;
}

async function callModel({ endpoint, apiKey, model, messages, tools, signal }) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json", ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      messages,
      tools: toolDefinitions(tools),
      tool_choice: "auto",
    }),
    signal,
  });
  if (!response.ok) {
    const detail = (await response.text().catch(() => "")).slice(0, 400);
    const hint = response.status === 400 || response.status === 422
      ? "。当前模型可能不支持工具调用（Function Calling），请在模型管理中换用支持工具调用的文本模型"
      : "";
    throw new Error(`AI 请求失败（HTTP ${response.status}）${hint}${detail ? `：${detail}` : ""}`);
  }
  const data = await response.json();
  const message = data?.choices?.[0]?.message;
  if (!message) throw new Error("AI 未返回有效消息");
  const content = Array.isArray(message.content)
    ? message.content.map((part) => String(part?.text ?? "")).join("")
    : String(message.content ?? "");
  const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
  return {
    message: {
      role: "assistant",
      content,
      ...(toolCalls.length ? {
        tool_calls: toolCalls.map((call) => ({
          id: String(call?.id ?? ""),
          type: "function",
          function: {
            name: String(call?.function?.name ?? ""),
            arguments: typeof call?.function?.arguments === "string" ? call.function.arguments : JSON.stringify(call?.function?.arguments ?? {}),
          },
        })).filter((call) => call.id && call.function.name),
      } : {}),
    },
    usage: data?.usage ?? null,
  };
}

function summarizeStep(command, spec, result, args) {
  if (!result.ok) return result.error || "执行失败";
  try {
    return spec.summarize ? spec.summarize(args, result.data) : `${spec.title}完成`;
  } catch {
    return `${spec.title}完成`;
  }
}

/**
 * 执行一轮 AI 管家：可能是发起新模型请求，也可能是恢复待审批的工具调用。
 * 返回的 messages 是“可直接持久化并在下一次原样传回”的会话。
 */
export async function runAgent(input, spec) {
  const baseUrl = String(process.env.RUODAO_LLM_BASE_URL ?? "").trim();
  const apiKey = String(process.env.RUODAO_LLM_API_KEY ?? "").trim();
  const model = String(input?.model ?? process.env.RUODAO_LLM_MODEL ?? "").trim();
  if (!baseUrl || !model) throw new Error("未配置 AI 模型：请先在模型管理中配置文本模型，并在 AI 管家中选择模型");
  const endpoint = chatEndpoint(baseUrl);

  let messages = normalizeMessages(input?.messages);
  if (!messages.length || messages.at(-1).role === "tool") {
    if (!messages.length) throw new Error("messages 不能为空");
  }
  const approvals = new Set(Array.isArray(input?.approvals) ? input.approvals.map(String) : []);
  const rejections = new Set(Array.isArray(input?.rejections) ? input.rejections.map(String) : []);
  const contextText = spec.contextText ? spec.contextText(input?.context ?? null) : "";
  const system = [spec.systemPrompt, contextText].filter(Boolean).join("\n\n");
  const deadline = Date.now() + Math.max(60000, Number(input?.timeoutMs) || 480000);
  const steps = [];
  const configEnv = input?.config && typeof input.config === "object"
    ? Object.fromEntries(Object.entries(input.config).filter(([key, value]) => /^RUODAO_[A-Z0-9_]+$/.test(key) && typeof value === "string"))
    : {};
  const env = { ...process.env, ...configEnv };

  const context = {
    messages,
    steps,
    approvals,
    rejections,
    system,
    endpoint,
    apiKey,
    model,
    spec,
    env,
    deadline,
  };

  let toolCallCount = 0;
  let llmCount = 0;
  const maxLlmSteps = Math.min(12, Math.max(2, Number(input?.maxSteps) || 6));

  while (true) {
    if (Date.now() > context.deadline) {
      return finish("partial", messages, steps, "本次操作已超时，已保留当前进度。可以继续说“继续”或缩小任务范围。", model);
    }
    const resolved = await resolveToolCalls(context);
    if (resolved) {
      messages.push(...resolved.messages);
      steps.push(...resolved.steps);
      toolCallCount += resolved.executed;
      if (resolved.pending.length) {
        return {
          state: "succeeded",
          status: "awaiting_approval",
          messages,
          steps,
          pending: resolved.pending[0],
          pendingList: resolved.pending,
          pendingIds: resolved.pending.map((entry) => entry.id),
          model,
          reply: "",
        };
      }
      if (toolCallCount > MAX_TOOL_CALLS) {
        return finish("done", messages, steps, "本次已连续执行较多操作，先停在这里。请确认结果后继续下一步。", model);
      }
      continue;
    }

    if (llmCount >= maxLlmSteps) {
      return finish("done", messages, steps, "本次会话已达到操作步数上限，先停在这里。请确认结果后继续。", model);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("AI 请求超时")), Math.max(15000, Math.min(180000, context.deadline - Date.now())));
    let response;
    try {
      response = await callModel({
        endpoint,
        apiKey,
        model,
        tools: spec.tools,
        messages: [{ role: "system", content: system }, ...messages],
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    llmCount += 1;
    const assistant = response.message;
    messages.push(assistant);
    if (!assistant.tool_calls?.length) {
      return {
        state: "succeeded",
        status: "done",
        messages,
        steps,
        reply: String(assistant.content ?? "").trim() || "已完成。",
        model,
        usage: response.usage ?? null,
      };
    }
  }

  async function resolveToolCalls(ctx) {
    const last = ctx.messages.at(-1);
    if (!last || last.role !== "assistant" || !last.tool_calls?.length) return null;
    const answered = new Set(ctx.messages.filter((message) => message.role === "tool").map((message) => message.tool_call_id));
    const unresolved = last.tool_calls.filter((call) => !answered.has(call.id));
    if (!unresolved.length) return null;
    const nextMessages = [];
    const nextSteps = [];
    const pending = [];
    let executed = 0;
    for (const call of unresolved) {
      const toolSpec = ctx.spec.tools[call.function.name];
      const base = { id: call.id, command: call.function.name };
      if (!toolSpec) {
        nextMessages.push({ role: "tool", tool_call_id: call.id, content: toolContent({ ok: false, summary: `未知工具：${call.function.name}` }) });
        nextSteps.push({ ...base, title: "未知工具", risk: "read", arguments: {}, ok: false, summary: "未知工具", durationMs: 0 });
        continue;
      }
      let args;
      try {
        args = parseArguments(call.function.arguments);
      } catch (error) {
        nextMessages.push({ role: "tool", tool_call_id: call.id, content: toolContent({ ok: false, summary: String(error?.message ?? error) }) });
        nextSteps.push({ ...base, title: toolSpec.title, risk: toolSpec.risk, arguments: {}, ok: false, summary: "参数解析失败", durationMs: 0 });
        continue;
      }
      if (ctx.rejections.has(call.id)) {
        const summary = "用户拒绝了该操作，未执行";
        nextMessages.push({ role: "tool", tool_call_id: call.id, content: toolContent({ ok: false, summary }) });
        nextSteps.push({ ...base, title: toolSpec.title, risk: toolSpec.risk, arguments: args, ok: false, summary, durationMs: 0, rejected: true });
        continue;
      }
      if (toolSpec.risk !== "read" && !ctx.approvals.has(call.id)) {
        pending.push({
          id: call.id,
          command: call.function.name,
          title: toolSpec.title,
          risk: toolSpec.risk,
          arguments: args,
          reason: toolSpec.approvalReason || (toolSpec.risk === "destructive" ? "该操作不可撤销，需要你确认后执行。" : "该操作会写入文件或修改系统，需要你确认后执行。"),
        });
        continue;
      }
      if (Date.now() > ctx.deadline) {
        pending.push({
          id: call.id,
          command: call.function.name,
          title: toolSpec.title,
          risk: toolSpec.risk,
          arguments: args,
          reason: "本次执行时间已用尽，确认后可继续执行该操作。",
        });
        continue;
      }
      let payload;
      try {
        payload = ctx.spec.preparePayload ? ctx.spec.preparePayload(call.function.name, args) : args;
      } catch (error) {
        const summary = `参数处理失败：${String(error?.message ?? error)}`;
        nextMessages.push({ role: "tool", tool_call_id: call.id, content: toolContent({ ok: false, summary }) });
        nextSteps.push({ ...base, title: toolSpec.title, risk: toolSpec.risk, arguments: args, ok: false, summary, durationMs: 0, error: summary });
        continue;
      }
      const result = await runProcess({
        binPath: ctx.spec.binPath,
        cwd: ctx.spec.cwd,
        command: toolSpec.command ?? call.function.name,
        payload,
        env: ctx.env,
        timeoutMs: toolSpec.timeoutMs,
      });
      const summary = summarizeStep(call.function.name, toolSpec, result, args);
      const compact = result.ok && ctx.spec.compact ? ctx.spec.compact(call.function.name, result.data) : result.ok ? result.data : null;
      nextMessages.push({
        role: "tool",
        tool_call_id: call.id,
        content: toolContent({ ok: result.ok, summary, ...(compact !== null && compact !== undefined ? { data: compact } : {}) }),
      });
      nextSteps.push({
        ...base,
        title: toolSpec.title,
        risk: toolSpec.risk,
        arguments: args,
        ok: result.ok,
        summary,
        durationMs: result.durationMs,
        output: result.ok ? compact : undefined,
        error: result.ok ? undefined : result.error,
      });
      executed += 1;
    }
    return { messages: nextMessages, steps: nextSteps, pending, executed };
  }
}

function finish(status, messages, steps, reply, model) {
  return { state: "succeeded", status, messages, steps, reply, model };
}

export function stepPreview(step) {
  return previewArguments(step.arguments);
}

export { truncate };
