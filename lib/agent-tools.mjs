/**
 * 若道安全卫士的 AI 管家能力声明：工具集覆盖状态、体检、查杀、隔离、修复与病毒库维护。
 */
import { RISK_LABEL, truncate } from "./agent-core.mjs";

const SEVERITY_TEXT = { high: "高风险", medium: "中风险", low: "低风险", info: "提示" };

function riskOf(command) {
  return tools[command]?.risk ?? "read";
}

export const tools = {
  doctor: {
    command: "doctor",
    title: "环境自检",
    risk: "read",
    timeoutMs: 90000,
    description: "检查 PowerShell、管理员权限、数据目录、病毒库、公钥与 Defender 引擎是否可用。排查“读取失败/无法扫描/修复不可用”这类问题时先调用它。",
    parameters: { type: "object", properties: {} },
    summarize: (args, data) => data?.summary ? `自检 ${data.summary.pass} 通过 / ${data.summary.warn} 提醒 / ${data.summary.fail} 阻断` : "自检完成",
  },
  status: {
    command: "status",
    title: "读取安全状态",
    risk: "read",
    timeoutMs: 120000,
    description: "汇总 Defender、防火墙、系统加固、病毒库、隔离区与最近扫描，返回 0-100 防护评分、风险列表与待修复项。做任何判断前先调用它。",
    parameters: { type: "object", properties: {} },
    summarize: (args, data) => data?.status ? `${data.status.headline ?? "状态已更新"}（${data.status.score ?? "—"} 分）` : "状态已读取",
  },
  audit: {
    command: "audit",
    title: "系统加固体检",
    risk: "read",
    timeoutMs: 150000,
    description: "逐项检查防护引擎、网络、系统加固与持久化项，返回 pass/warn/fail 明细、建议与可一键修复项。",
    parameters: { type: "object", properties: {} },
    summarize: (args, data) => {
      const summary = data?.audit?.summary;
      return summary ? `体检完成：${summary.pass} 通过 / ${summary.warn} 建议 / ${summary.fail} 未通过` : "体检完成";
    },
  },
  scan: {
    command: "scan",
    title: "病毒查杀",
    risk: "read",
    timeoutMs: 300000,
    description: "用开放病毒库（SHA-256 + 启发式规则）查杀文件，并可检查进程、启动项与计划任务。mode=quick 覆盖下载/桌面/文档/临时目录；deep 覆盖常用用户目录；custom 需传 paths。只报告，不删除。",
    parameters: {
      type: "object",
      properties: {
        mode: { type: "string", enum: ["quick", "deep", "custom"] },
        paths: { type: "array", items: { type: "string" }, description: "mode=custom 时的目录/文件路径" },
        includeProcesses: { type: "boolean", description: "是否检查运行进程，默认 true" },
        includeStartup: { type: "boolean", description: "是否检查启动项与计划任务，默认 true" },
        maxSeconds: { type: "number", description: "时间预算（秒），可选" },
      },
      required: [],
    },
    summarize: (args, data) => {
      const result = data?.result;
      return result ? `扫描 ${result.scannedFiles ?? 0} 个文件，发现 ${result.summary?.total ?? 0} 项结果` : "扫描完成";
    },
  },
  startup: {
    command: "startup",
    title: "启动项检查",
    risk: "read",
    timeoutMs: 120000,
    description: "列出开机启动项与非微软计划任务，并标记指向可疑命令的条目（编码 PowerShell、临时目录、隐藏窗口等）。",
    parameters: { type: "object", properties: {} },
    summarize: (args, data) => `${data?.counts?.startup ?? 0} 个启动项、${data?.counts?.tasks ?? 0} 个计划任务，可疑 ${data?.counts?.suspicious ?? 0} 项`,
  },
  fix: {
    command: "fix",
    title: "应用加固修复",
    risk: "destructive",
    timeoutMs: 180000,
    description: "应用加固体检中的白名单修复项（如开启 Defender 实时防护、关闭 SMBv1、启用 UAC）。需要管理员权限；执行前系统会请求用户确认。",
    parameters: {
      type: "object",
      properties: {
        fixIds: { type: "array", items: { type: "string" }, description: "来自 audit/status 的 fixId 列表" },
      },
      required: ["fixIds"],
    },
    approvalReason: "将修改系统安全设置（可能需要管理员权限，部分项目需重启生效）。请确认要应用的修复项。",
    summarize: (args, data) => `已应用 ${data?.applied?.length ?? 0} 项修复${data?.requiresReboot ? "，部分需重启生效" : ""}`,
  },
  quarantine: {
    command: "quarantine",
    title: "隔离文件",
    risk: "destructive",
    timeoutMs: 180000,
    description: "把查杀结果中的可疑文件移入隔离区（会重新校验哈希，不直接删除）。只对 canQuarantine=true 的文件有效。",
    parameters: {
      type: "object",
      properties: {
        items: {
          type: "array",
          items: {
            type: "object",
            properties: {
              path: { type: "string" },
              sha256: { type: "string" },
              name: { type: "string" },
              ruleId: { type: "string" },
              severity: { type: "string" },
            },
            required: ["path"],
          },
        },
      },
      required: ["items"],
    },
    approvalReason: "将把文件移入隔离区（可恢复，但会中断该文件的使用）。请确认要隔离的文件。",
    summarize: (args, data) => `已隔离 ${data?.quarantined?.length ?? 0} 个文件`,
  },
  "quarantine-list": {
    command: "quarantine-list",
    title: "查看隔离区",
    risk: "read",
    timeoutMs: 60000,
    description: "列出隔离区条目（原始路径、哈希、大小、隔离时间）。",
    parameters: { type: "object", properties: {} },
    summarize: (args, data) => `隔离区有 ${data?.items?.length ?? 0} 个文件`,
  },
  "quarantine-restore": {
    command: "quarantine-restore",
    title: "恢复隔离文件",
    risk: "destructive",
    timeoutMs: 60000,
    description: "把隔离文件还原到原始路径；原位置被占用时追加 .restored。",
    parameters: {
      type: "object",
      properties: { id: { type: "string", description: "隔离条目 id，来自 quarantine-list" } },
      required: ["id"],
    },
    approvalReason: "将把隔离文件恢复到原位置，若该文件确实有风险可能重新影响系统。请确认。",
    summarize: (args, data) => `已恢复到 ${data?.restored?.restoredPath ?? "原路径"}`,
  },
  "quarantine-delete": {
    command: "quarantine-delete",
    title: "永久删除隔离文件",
    risk: "destructive",
    timeoutMs: 60000,
    description: "永久删除隔离区中的文件与记录，无法撤销。",
    parameters: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
    approvalReason: "该操作会永久删除隔离文件，无法撤销。请确认。",
    summarize: (args, data) => `已永久删除隔离条目 ${data?.id ?? ""}`,
  },
  "db-info": {
    command: "db-info",
    title: "查看病毒库",
    risk: "read",
    timeoutMs: 60000,
    description: "返回当前生效病毒库版本、来源、哈希/规则数量、签名状态与公钥指纹。",
    parameters: { type: "object", properties: {} },
    summarize: (args, data) => `病毒库 ${data?.current?.version ?? "未知"}${data?.signed ? "（已签名）" : "（内置/未签名）"}`,
  },
  "db-update": {
    command: "db-update",
    title: "升级开放病毒库",
    risk: "write",
    timeoutMs: 180000,
    description: "从 HTTPS 订阅源下载并校验（Ed25519 签名 + checksum）后安装。未传 url 时使用设置中的订阅源。",
    parameters: {
      type: "object",
      properties: { url: { type: "string", description: "HTTPS JSON 订阅地址（可选）" } },
      required: [],
    },
    approvalReason: "将从网络下载并安装新的病毒库，替换当前规则。请确认来源可信。",
    summarize: (args, data) => `病毒库已升级到 ${data?.installed?.version ?? "新版本"}${data?.signed ? "（签名已验证）" : "（未签名）"}`,
  },
  "db-import": {
    command: "db-import",
    title: "导入病毒库",
    risk: "write",
    timeoutMs: 120000,
    description: "导入本地 JSON 病毒库并校验签名与 checksum。",
    parameters: {
      type: "object",
      properties: { file: { type: "string", description: "JSON 病毒库绝对路径" } },
      required: ["file"],
    },
    approvalReason: "将用本地文件替换当前病毒库规则。请确认文件来源可信。",
    summarize: (args, data) => `病毒库已导入：${data?.installed?.version ?? "完成"}`,
  },
  "db-reset": {
    command: "db-reset",
    title: "恢复内置病毒库",
    risk: "destructive",
    timeoutMs: 60000,
    description: "移除已安装的订阅/导入病毒库，回退到插件内置库。",
    parameters: { type: "object", properties: {} },
    approvalReason: "将放弃当前订阅/导入的病毒库，回退到内置版本。请确认。",
    summarize: (args, data) => data?.message ?? "已恢复内置病毒库",
  },
  "defender-update": {
    command: "defender-update",
    title: "升级 Defender 病毒库",
    risk: "write",
    timeoutMs: 330000,
    description: "调用 Windows Update 升级 Microsoft Defender 官方病毒库。",
    parameters: { type: "object", properties: {} },
    approvalReason: "将通过 Windows Update 升级 Defender 病毒库，可能持续数分钟。请确认。",
    summarize: (args, data) => `Defender 签名已更新：${data?.result?.signatureVersion ?? "完成"}`,
  },
  "defender-scan": {
    command: "defender-scan",
    title: "Defender 快速扫描",
    risk: "read",
    timeoutMs: 660000,
    description: "调用 Microsoft Defender 执行快速扫描，返回耗时与最近威胁记录。耗时较长。",
    parameters: { type: "object", properties: {} },
    summarize: (args, data) => `Defender 扫描完成（${data?.result?.elapsedSec ?? 0} 秒），威胁记录 ${data?.result?.threats?.length ?? 0} 条`,
  },
  "ai-diagnose": {
    command: "ai-diagnose",
    title: "云端 AI 深度诊断",
    risk: "read",
    timeoutMs: 240000,
    description: "把本机安全状态与体检结果交给若道云端大模型，返回安全评估、风险点与建议操作。适合需要完整解读时使用。",
    parameters: {
      type: "object",
      properties: { focus: { type: "string", description: "用户关注点，如“开机变慢”“最近弹出广告”" } },
      required: [],
    },
    summarize: (args, data) => `AI 诊断完成，输出 ${String(data?.result ?? "").length} 字`,
  },
};

export function preparePayload(name, args) {
  const input = { ...(args ?? {}) };
  if (name === "fix") return { fixIds: Array.isArray(input.fixIds) ? input.fixIds : [], confirm: true };
  if (name === "quarantine") return { items: Array.isArray(input.items) ? input.items : [], confirm: true };
  if (name === "quarantine-restore" || name === "quarantine-delete") return { id: String(input.id ?? ""), confirm: true };
  if (name === "db-update") {
    const url = String(input.url ?? process.env.RUODAO_GUARD_DB_URL ?? "").trim();
    return { url, confirm: true };
  }
  if (name === "db-import") return { file: String(input.file ?? ""), confirm: true };
  if (name === "db-reset") return { confirm: true };
  if (name === "scan") {
    return {
      mode: String(input.mode ?? "quick"),
      ...(Array.isArray(input.paths) && input.paths.length ? { paths: input.paths } : {}),
      includeProcesses: input.includeProcesses !== false,
      includeStartup: input.includeStartup !== false,
      ...(input.maxSeconds ? { maxSeconds: input.maxSeconds } : {}),
    };
  }
  return input;
}

function compactStatus(status) {
  if (!status) return null;
  return {
    supported: status.supported,
    partial: status.partial,
    admin: status.admin,
    os: status.os,
    score: status.score,
    level: status.level,
    headline: status.headline,
    engine: status.engine,
    defender: status.defender ? {
      present: status.defender.present,
      antivirusEnabled: status.defender.antivirusEnabled,
      realtimeEnabled: status.defender.realtimeEnabled,
      behaviorMonitorEnabled: status.defender.behaviorMonitorEnabled,
      tamperProtected: status.defender.tamperProtected,
      signatureVersion: status.defender.signatureVersion,
      signatureAgeDays: status.defender.signatureAgeDays,
    } : null,
    firewall: status.firewall,
    hosts: { entries: status.hosts?.entries ?? 0, suspicious: (status.hosts?.suspicious ?? []).slice(0, 5), oversized: status.hosts?.oversized },
    risks: (status.risks ?? []).slice(0, 20),
    pendingFixes: (status.pendingFixes ?? []).slice(0, 20),
    db: status.db ? {
      version: status.db.version,
      hashes: status.db.hashes,
      rules: status.db.rules,
      releasedAt: status.db.releasedAt,
      signed: Boolean(status.db.meta?.signature),
    } : null,
    quarantine: status.quarantine,
    lastScan: status.lastScan ? {
      mode: status.lastScan.mode,
      finishedAt: status.lastScan.finishedAt,
      scannedFiles: status.lastScan.scannedFiles,
      summary: status.lastScan.summary,
      top: (status.lastScan.top ?? []).slice(0, 10),
    } : null,
  };
}

export function compact(name, data) {
  if (!data) return null;
  if (name === "doctor") {
    return {
      summary: data.summary,
      checks: (data.checks ?? []).filter((check) => check.status !== "pass"),
      warning: data.warning,
    };
  }
  if (name === "status") return compactStatus(data.status);
  if (name === "audit") {
    const audit = data.audit ?? {};
    return {
      summary: audit.summary,
      checks: (audit.checks ?? [])
        .filter((check) => check.status !== "pass")
        .slice(0, 30)
        .map((check) => ({
          id: check.id, title: check.title, category: check.category, status: check.status,
          detail: check.detail, advice: check.advice, fixable: check.fixable, fixId: check.fixId,
          requiresAdmin: check.requiresAdmin, requiresReboot: check.requiresReboot,
        })),
    };
  }
  if (name === "scan") {
    const result = data.result ?? {};
    return {
      mode: result.mode,
      scannedFiles: result.scannedFiles,
      elapsedMs: result.elapsedMs,
      limitsHit: result.limitsHit,
      summary: result.summary,
      db: result.db,
      detections: (result.detections ?? []).slice(0, 25).map((item) => ({
        id: item.id, kind: item.kind, ruleId: item.ruleId, title: item.title, severity: item.severity,
        path: item.path, name: item.name, size: item.size, sha256: item.sha256, detail: item.detail,
        pid: item.pid, canQuarantine: item.canQuarantine,
      })),
    };
  }
  if (name === "startup") {
    return {
      counts: data.counts,
      startup: (data.startup ?? []).slice(0, 30),
      tasks: (data.tasks ?? []).slice(0, 30),
      detections: (data.detections ?? []).slice(0, 20),
      error: data.error ?? "",
    };
  }
  if (name === "quarantine-list") {
    return {
      items: (data.items ?? []).slice(0, 20).map((item) => ({
        id: item.id, name: item.name, originalPath: item.originalPath, severity: item.severity,
        ruleId: item.ruleId, size: item.size, quarantinedAt: item.quarantinedAt, sha256: item.sha256,
        binExists: item.binExists,
      })),
      total: data.items?.length ?? 0,
    };
  }
  if (name === "db-info") {
    return {
      current: data.current,
      source: data.source,
      installed: data.installed,
      signed: data.signed,
      publicKey: data.publicKey,
      warnings: data.warnings,
    };
  }
  if (name === "ai-diagnose") {
    return { model: data.model, result: truncate(data.result, 12000) };
  }
  if (name === "defender-scan") {
    return {
      elapsedSec: data.result?.elapsedSec,
      threats: (data.result?.threats ?? []).slice(0, 10),
      signatureVersion: data.result?.signatureVersion,
    };
  }
  return data;
}

export function contextText(context) {
  if (!context) return "";
  const pieces = [];
  if (context.focus) pieces.push(`用户当前关注点：${truncate(context.focus, 500)}`);
  if (context.lastScanMode) pieces.push(`最近一次查杀模式：${context.lastScanMode}`);
  return pieces.length ? `【当前上下文】\n${pieces.join("\n")}` : "";
}

export const systemPrompt = [
  "你是若道安全卫士的 AI 管家，负责读懂本机安全状况并代替用户执行安全维护操作。",
  "",
  "能力与规则：",
  "1. 先读后判：给出任何安全结论前，先调用 status（必要时 audit/startup/scan）获取真实数据，不要凭空猜测。",
  "2. 只读操作（status/audit/scan/startup/quarantine-list/db-info/defender-scan/ai-diagnose）可直接执行。",
  "3. 修复、隔离、恢复、删除、病毒库安装/重置属于高风险操作，系统会先请用户确认；确认前绝不能说“已完成”。",
  "4. 不要主动发起全盘扫描或 Defender 扫描，除非用户明确要求；快速查杀也要先说明范围。",
  "5. 修复系统设置可能需要管理员权限；若 status.admin=false，先提示用户以管理员身份重启若道。",
  "6. 隔离区中的文件可恢复，不要建议直接永久删除，除非用户明确要求。",
  "7. 汇报用简洁中文：先给结论（是否安全/评分/主要风险），再给依据（关键检测项与数据），最后给下一步可执行操作；需要管理员权限或重启的步骤要标注。",
  "8. 不要调用 agent 自身，不要假设不存在的能力。",
].join("\n");

export { RISK_LABEL, SEVERITY_TEXT, riskOf };
