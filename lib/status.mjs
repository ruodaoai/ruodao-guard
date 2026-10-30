import { analyzeHosts, analyzeProxy, fixCatalog } from "./system.mjs";
import { analyzeStartupItems } from "./scanner.mjs";
import { PATHS } from "./store.mjs";

const FIX_META = fixCatalog();
const WEIGHT = { high: 20, medium: 9, low: 3, info: 0 };

function uniqueById(items) {
  const seen = new Set();
  return items.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function suspiciousExclusions(exclusions) {
  const patterns = [/[\\/]Temp[\\/]/i, /[\\/]Downloads[\\/]/i, /[\\/]Users[\\/]Public/i, /AppData[\\/]Local/i];
  return (exclusions.paths ?? []).filter((entry) => patterns.some((pattern) => pattern.test(entry)));
}

/** Windows 安全中心 productState 的 0x1000 位表示该杀毒产品已启用。 */
export function activeThirdPartyAv(snapshot) {
  return (snapshot?.avProducts ?? []).filter((entry) => {
    const name = String(entry?.name ?? "");
    if (!name || /windows defender|microsoft defender/i.test(name)) return false;
    return (Number(entry?.state ?? 0) & 0x1000) !== 0;
  });
}

function engineMode(snapshot) {
  const thirdParty = activeThirdPartyAv(snapshot);
  return {
    mode: snapshot.defender?.antivirusEnabled === true ? "defender" : thirdParty.length ? "third-party" : "none",
    defenderActive: snapshot.defender?.antivirusEnabled === true,
    thirdPartyActive: thirdParty.map((entry) => String(entry.name)).filter(Boolean),
  };
}

export function evaluate(snapshot, dbInfo, quarantineStats, lastScan) {
  const risks = [];
  const add = (id, level, title, detail, fixId) => {
    const fix = fixId && FIX_META[fixId] ? fixId : undefined;
    risks.push({ id, level, title, detail, fixId: fix });
  };
  const defender = snapshot.defender;
  const engine = engineMode(snapshot);

  if (!snapshot.supported) {
    return { score: null, level: "unknown", headline: "当前系统不支持完整防护检查", risks, pendingFixes: [], engine };
  }
  if (snapshot.partial) {
    return { score: null, level: "unknown", headline: "系统检查不完整，请重试", risks, pendingFixes: [], engine };
  }
  if (engine.defenderActive) {
    if (!defender.realtimeEnabled) add("realtime-disabled", "high", "实时防护未开启", "下载、解压和运行文件时不会实时拦截威胁。", "defender-realtime");
    if (defender.behaviorMonitorEnabled === false) add("behavior-disabled", "medium", "行为监控未开启", "Defender 行为监控关闭，勒索/无文件攻击更难被拦截。");
    if (defender.signatureAgeDays != null && defender.signatureAgeDays > 30) add("signature-stale", "high", "病毒库严重过期", `Defender 病毒库已有 ${defender.signatureAgeDays} 天未更新。`);
    else if (defender.signatureAgeDays != null && defender.signatureAgeDays > 7) add("signature-old", "medium", "病毒库需要更新", `Defender 病毒库已有 ${defender.signatureAgeDays} 天未更新。`);
    if (defender.tamperProtected === false) add("tamper-off", "low", "篡改防护未开启", "恶意程序可能通过修改设置关闭 Defender。");
  } else if (!engine.thirdPartyActive.length) {
    add(
      defender?.present ? "defender-disabled" : "no-av",
      "high",
      defender?.present ? "Defender 杀毒未开启" : "未检测到可用的杀毒引擎",
      defender?.present
        ? "Windows Defender 防病毒引擎处于关闭状态，且没有检测到其他已启用的杀毒软件。"
        : "系统未启用 Windows Defender，也没有检测到已启用的第三方杀毒软件。",
      defender?.present ? "defender-realtime" : undefined,
    );
  }
  const firewall = snapshot.firewall;
  if (firewall?.known && !firewall.enabled) add("firewall-off", "high", "Windows 防火墙存在关闭的配置文件", "域/专用/公用网络配置中至少有一个未开启防火墙。", "firewall");
  if (snapshot.uac?.known && !snapshot.uac.enabled) add("uac-off", "high", "用户账户控制（UAC）已关闭", "程序可在无提示的情况下获得管理员权限。", "uac");
  if (snapshot.smb?.supported && snapshot.smb.smb1Enabled) add("smb1-on", "high", "SMBv1 已启用", "SMBv1 存在 EternalBlue 等远程攻击面。", "smb1");
  if (snapshot.autorun?.disabled === false) add("autorun-on", "medium", "自动运行已开启", "U 盘/移动介质接入后可能自动执行程序。", "autorun");
  if (snapshot.rdp?.enabled && !snapshot.rdp.nla) add("rdp-no-nla", "medium", "远程桌面未强制网络级身份验证", "RDP 暴露时更容易受到暴力破解和漏洞攻击。", "rdp-nla");
  if (snapshot.guest?.supported && snapshot.guest.enabled) add("guest-on", "medium", "Guest 来宾账户已启用", "来宾账户通常无密码，容易被远程利用。", "guest");
  if (snapshot.wdigest?.enabled) add("wdigest-on", "high", "WDigest 明文凭据缓存已开启", "攻击者可更容易从内存中读取登录凭据。", "wdigest");
  if (snapshot.lsa && Number(snapshot.lsa.runAsPPL ?? 0) < 1) add("lsa-unprotected", "medium", "LSA 进程保护未开启", "开启后更难被窃取登录凭据（需重启生效）。", "lsa");
  if (engine.defenderActive) {
    const exclusions = suspiciousExclusions(snapshot.defenderExclusions ?? {});
    if (exclusions.length) add("suspicious-exclusions", "medium", "Defender 存在高风险排除目录", `${exclusions.length} 条排除项位于临时目录/下载目录/公共目录。`);
  }
  if ((snapshot.threats ?? []).length) add("threat-history", "high", "Defender 最近记录了威胁", `最近 ${snapshot.threats.length} 条拦截/检测记录，建议立即全盘扫描。`);
  const hosts = analyzeHosts(snapshot.hosts);
  if (hosts.suspicious.length) add("hosts-hijack", "high", "hosts 文件疑似劫持系统域名", hosts.suspicious.slice(0, 4).map((entry) => `${entry.ip} ${entry.host}`).join("；"));
  if (hosts.oversized) add("hosts-oversized", "medium", "hosts 文件异常庞大", `共 ${hosts.entries} 条记录。`);
  const proxy = analyzeProxy(snapshot.proxy);
  if (proxy) add("proxy-configured", proxy.level, proxy.title, proxy.detail);
  if (lastScan?.summary && Number(lastScan.summary.high) + Number(lastScan.summary.medium) > 0) {
    add("last-scan-findings", "high", "上次扫描发现待处理威胁", `高风险 ${lastScan.summary.high ?? 0} 项，中风险 ${lastScan.summary.medium ?? 0} 项。`);
  }
  if (dbInfo?.builtin && dbInfo?.installed && dbInfo.installed.version && dbInfo.builtin.version) {
    // 内置库随插件升级更新；已安装库更旧时提示，不计入风险分。
  }

  const unique = uniqueById(risks);
  const penalty = unique.reduce((sum, risk) => sum + (WEIGHT[risk.level] ?? 0), 0);
  const score = clamp(100 - penalty, 0, 100);
  const highCount = unique.filter((risk) => risk.level === "high").length;
  const level = score >= 90 ? "safe" : score >= 70 ? "attention" : "risk";
  const headline = level === "safe"
    ? "防护状态良好"
    : level === "attention"
      ? `有 ${unique.length} 项建议处理`
      : `发现 ${highCount} 项高风险`;
  const pendingFixes = [...new Set(unique.map((risk) => risk.fixId).filter(Boolean))];
  return { score, level, headline, risks: unique, pendingFixes, hosts, proxy, engine };
}

export function summarizeLastScan(lastScan) {
  if (!lastScan) return null;
  return {
    mode: lastScan.mode,
    finishedAt: lastScan.finishedAt ?? lastScan.startedAt ?? null,
    scannedFiles: Number(lastScan.scannedFiles ?? 0),
    elapsedMs: Number(lastScan.elapsedMs ?? 0),
    summary: lastScan.summary ?? { total: 0, high: 0, medium: 0, low: 0, info: 0 },
    limitsHit: Boolean(lastScan.limitsHit),
    top: Array.isArray(lastScan.detections)
      ? lastScan.detections.slice(0, 5).map((item) => ({
        id: item.id,
        title: item.title,
        severity: item.severity,
        path: item.path,
        name: item.name,
        canQuarantine: Boolean(item.canQuarantine),
        sha256: item.sha256 ?? null,
      }))
      : [],
  };
}

function check(id, title, category, status, level, detail, advice, options = {}) {
  return {
    id,
    title,
    category,
    status,
    level,
    detail,
    advice,
    fixable: Boolean(options.fixId && FIX_META[options.fixId]),
    fixId: options.fixId && FIX_META[options.fixId] ? options.fixId : undefined,
    requiresAdmin: Boolean(options.fixId && FIX_META[options.fixId]),
    requiresReboot: Boolean(options.fixId && FIX_META[options.fixId]?.requiresReboot),
  };
}

export function buildAudit(snapshot, startupSnapshot, lastScan) {
  const checks = [];
  const defender = snapshot.defender;
  const thirdPartyNames = activeThirdPartyAv(snapshot).map((entry) => String(entry.name)).filter(Boolean);
  const defenderActive = defender?.present === true && defender.antivirusEnabled === true;
  const startupDetections = analyzeStartupItems(startupSnapshot?.startup ?? [], startupSnapshot?.tasks ?? []);

  if (!snapshot.supported) {
    checks.push(check("platform", "系统防护检查", "system", "unknown", "info", snapshot.error || "当前系统不是 Windows", "仅 Windows 支持系统防护检查。"));
  } else if (snapshot.partial) {
    checks.push(check("powershell", "系统检查", "system", "unknown", "medium", snapshot.error || "PowerShell 检查失败", "请确认系统 PowerShell 可正常运行，然后重新体检。"));
  } else {
    if (defenderActive) {
      checks.push(check("av-engine", "防病毒引擎", "engine", "pass", "info",
        `Windows Defender 已启用（引擎 ${defender.engineVersion || "-"}）`, "保持开启。"));
      checks.push(check("realtime", "实时防护", "engine", defender.realtimeEnabled ? "pass" : "fail", defender.realtimeEnabled ? "info" : "high",
        defender.realtimeEnabled ? "下载、解压、运行文件时实时拦截已开启。" : "实时防护关闭，威胁运行前不会被拦截。",
        defender.realtimeEnabled ? "无需处理。" : "开启实时防护，这是抵御主流病毒最重要的防线。", { fixId: defender.realtimeEnabled ? undefined : "defender-realtime" }));
      checks.push(check("behavior", "行为监控", "engine", defender.behaviorMonitorEnabled ? "pass" : "warn", defender.behaviorMonitorEnabled ? "info" : "medium",
        defender.behaviorMonitorEnabled ? "行为监控已开启。" : "行为监控关闭。", defender.behaviorMonitorEnabled ? "无需处理。" : "在 Windows 安全中心开启行为监控。"));
      const age = defender.signatureAgeDays;
      const signatureStatus = age == null ? "unknown" : age > 30 ? "fail" : age > 7 ? "warn" : "pass";
      checks.push(check("signatures", "Defender 病毒库", "engine", signatureStatus, age > 30 ? "high" : age > 7 ? "medium" : "info",
        `${defender.signatureVersion || "未知版本"}${age == null ? "" : ` · ${age} 天前更新`}`,
        signatureStatus === "pass" ? "无需处理。" : "在“病毒库”页升级 Defender 病毒库。"));
      checks.push(check("tamper", "篡改防护", "engine", defender.tamperProtected ? "pass" : "warn", defender.tamperProtected ? "info" : "low",
        defender.tamperProtected ? "篡改防护已开启。" : "篡改防护未开启或系统不支持。",
        defender.tamperProtected ? "无需处理。" : "建议在 Windows 安全中心开启篡改防护。"));
    } else if (thirdPartyNames.length) {
      const names = thirdPartyNames.join("、");
      checks.push(check("av-engine", "防病毒引擎", "engine", "pass", "info",
        `Windows Defender 处于被动模式，实时防护由 ${names} 接管。`, "保持第三方杀毒软件实时防护开启；本插件可与其共存。"));
      checks.push(check("realtime", "实时防护", "engine", "pass", "info",
        `${names} 已在 Windows 安全中心注册并启用。`, "无需处理。"));
      checks.push(check("behavior", "行为监控", "engine", "unknown", "info",
        `行为监控由 ${names} 负责。`, "无需处理。"));
      checks.push(check("signatures", "病毒库", "engine", "pass", "info",
        `${names} 自行维护病毒库；Defender 病毒库不参与实时防护。`, "在第三方杀毒软件中保持自动更新。"));
      checks.push(check("tamper", "篡改防护", "engine", "unknown", "info",
        `篡改防护由 ${names} 负责。`, "无需处理。"));
    } else {
      checks.push(check("av-engine", "防病毒引擎", "engine", "fail", "high",
        defender?.present ? "Windows Defender 防病毒引擎已关闭，且没有其他已启用的杀毒软件。" : "系统未检测到已启用的杀毒引擎。",
        "启用 Windows Defender 或安装可信杀毒软件。", { fixId: defender?.present ? "defender-realtime" : undefined }));
      checks.push(check("realtime", "实时防护", "engine", "fail", "high",
        "当前没有可用的实时防护。", "开启实时防护，这是抵御主流病毒最重要的防线。", { fixId: defender?.present ? "defender-realtime" : undefined }));
    }

    const exclusions = suspiciousExclusions(snapshot.defenderExclusions ?? {});
    const allExclusions = (snapshot.defenderExclusions?.paths?.length ?? 0) + (snapshot.defenderExclusions?.extensions?.length ?? 0) + (snapshot.defenderExclusions?.processes?.length ?? 0);
    const passive = !defenderActive && thirdPartyNames.length > 0;
    checks.push(check("exclusions", "Defender 排除项", "engine",
      passive ? (exclusions.length ? "warn" : "pass") : exclusions.length ? "fail" : allExclusions ? "warn" : "pass",
      exclusions.length ? "medium" : allExclusions ? "low" : "info",
      passive
        ? (exclusions.length ? `Defender 已被动，但仍发现 ${exclusions.length} 条高风险排除目录：${exclusions.slice(0, 3).join("；")}` : "Defender 处于被动模式，未发现高风险排除项。")
        : exclusions.length ? `${exclusions.length} 条高风险排除目录：${exclusions.slice(0, 3).join("；")}` : allExclusions ? `存在 ${allExclusions} 条排除项（目录/扩展名/进程）。` : "未发现排除项。",
      exclusions.length ? "请人工确认这些排除项是否可信；恶意软件常通过排除目录躲避查杀。" : allExclusions ? "定期检查排除项，删除不再需要的目录。" : "无需处理。"));

    checks.push(check("threat-history", "威胁拦截记录", "engine", (snapshot.threats ?? []).length ? "fail" : "pass", (snapshot.threats ?? []).length ? "high" : "info",
      (snapshot.threats ?? []).length ? `最近记录：${snapshot.threats.slice(0, 3).map((entry) => entry.name).join("、")}` : "没有新的 Defender 威胁记录。",
      (snapshot.threats ?? []).length ? "立即执行一次快速查杀，并检查隔离区。" : "无需处理。"));

    const firewall = snapshot.firewall;
    checks.push(check("firewall", "Windows 防火墙", "network", !firewall?.known ? "unknown" : firewall.enabled ? "pass" : "fail",
      !firewall?.known ? "info" : firewall.enabled ? "info" : "high",
      !firewall?.known ? "无法读取防火墙状态。" : firewall.enabled ? "域、专用、公用网络防火墙均已开启。" : `关闭的配置文件：${firewall.profiles.filter((entry) => !entry.enabled).map((entry) => entry.name).join("、") || "未知"}`,
      firewall?.enabled ? "无需处理。" : "开启全部网络配置文件的防火墙。", { fixId: !firewall?.known || firewall.enabled ? undefined : "firewall" }));

    checks.push(check("uac", "用户账户控制（UAC）", "system", !snapshot.uac?.known ? "unknown" : snapshot.uac.enabled ? "pass" : "fail",
      !snapshot.uac?.known ? "info" : snapshot.uac.enabled ? "info" : "high",
      !snapshot.uac?.known ? "无法读取 UAC 配置。" : snapshot.uac.enabled ? "UAC 已开启。" : "UAC 已关闭，程序可获得无提示提权。",
      snapshot.uac?.enabled ? "无需处理。" : "开启 UAC（需重启）。", { fixId: !snapshot.uac?.known || snapshot.uac.enabled ? undefined : "uac" }));

    checks.push(check("smb1", "SMBv1 协议", "network", !snapshot.smb?.supported ? "unknown" : snapshot.smb.smb1Enabled ? "fail" : "pass",
      !snapshot.smb?.supported ? "info" : snapshot.smb.smb1Enabled ? "high" : "info",
      !snapshot.smb?.supported ? "无法读取 SMB 配置。" : snapshot.smb.smb1Enabled ? "SMBv1 已启用，存在远程攻击面。" : "SMBv1 已关闭。",
      snapshot.smb?.smb1Enabled ? "关闭 SMBv1（部分老旧 NAS/打印机可能受影响）。" : "无需处理。", { fixId: snapshot.smb?.smb1Enabled ? "smb1" : undefined }));

    checks.push(check("autorun", "自动运行", "system", snapshot.autorun?.disabled === null ? "unknown" : snapshot.autorun.disabled ? "pass" : "fail",
      snapshot.autorun?.disabled === null ? "info" : snapshot.autorun.disabled ? "info" : "medium",
      snapshot.autorun?.disabled === null ? "无法读取自动运行策略。" : snapshot.autorun.disabled ? "自动运行已禁用。" : "移动介质接入时可能自动执行程序。",
      snapshot.autorun?.disabled === false ? "关闭所有驱动器的自动运行。" : "无需处理。", { fixId: snapshot.autorun?.disabled === false ? "autorun" : undefined }));

    checks.push(check("rdp", "远程桌面", "network", !snapshot.rdp?.enabled ? "pass" : snapshot.rdp.nla ? "pass" : "warn",
      !snapshot.rdp?.enabled ? "info" : snapshot.rdp.nla ? "info" : "medium",
      !snapshot.rdp?.enabled ? "远程桌面未开启。" : snapshot.rdp.nla ? "远程桌面已开启，且强制 NLA。" : "远程桌面已开启，但未强制网络级身份验证。",
      !snapshot.rdp?.enabled || snapshot.rdp.nla ? "无需处理。" : "强制 NLA，或在不使用远程桌面时关闭。", { fixId: snapshot.rdp?.enabled && !snapshot.rdp.nla ? "rdp-nla" : undefined }));

    checks.push(check("guest", "来宾账户", "system", !snapshot.guest?.supported ? "unknown" : snapshot.guest.enabled ? "fail" : "pass",
      !snapshot.guest?.supported ? "info" : snapshot.guest.enabled ? "medium" : "info",
      !snapshot.guest?.supported ? "当前系统不支持读取本地账户。" : snapshot.guest.enabled ? "Guest 来宾账户已启用。" : "Guest 来宾账户已禁用。",
      snapshot.guest?.enabled ? "禁用 Guest 来宾账户。" : "无需处理。", { fixId: snapshot.guest?.enabled ? "guest" : undefined }));

    checks.push(check("wdigest", "凭据保护（WDigest）", "system", snapshot.wdigest?.enabled ? "fail" : "pass",
      snapshot.wdigest?.enabled ? "high" : "info",
      snapshot.wdigest?.enabled ? "WDigest 明文凭据缓存已开启。" : "WDigest 明文凭据缓存未开启。",
      snapshot.wdigest?.enabled ? "关闭 WDigest 明文凭据缓存（需重启）。" : "无需处理。", { fixId: snapshot.wdigest?.enabled ? "wdigest" : undefined }));

    checks.push(check("lsa", "LSA 进程保护", "system", Number(snapshot.lsa?.runAsPPL ?? 0) >= 1 ? "pass" : "warn",
      Number(snapshot.lsa?.runAsPPL ?? 0) >= 1 ? "info" : "medium",
      Number(snapshot.lsa?.runAsPPL ?? 0) >= 1 ? "LSA 进程保护已开启。" : "LSA 进程保护未开启。",
      Number(snapshot.lsa?.runAsPPL ?? 0) >= 1 ? "无需处理。" : "开启 LSA 进程保护（需重启）。", { fixId: Number(snapshot.lsa?.runAsPPL ?? 0) >= 1 ? undefined : "lsa" }));

    const hosts = analyzeHosts(snapshot.hosts);
    checks.push(check("hosts", "hosts 文件", "network", hosts.suspicious.length ? "fail" : hosts.oversized ? "warn" : "pass",
      hosts.suspicious.length ? "high" : hosts.oversized ? "medium" : "info",
      hosts.suspicious.length ? `疑似劫持：${hosts.suspicious.slice(0, 3).map((entry) => `${entry.ip} ${entry.host}`).join("；")}` : hosts.oversized ? `hosts 记录异常多（${hosts.entries} 条）。` : `hosts 共 ${hosts.entries} 条记录，未发现系统域名劫持。`,
      hosts.suspicious.length ? "人工检查并删除异常 hosts 记录。" : hosts.oversized ? "检查是否有广告/恶意软件批量写入 hosts。" : "无需处理。"));

    const proxy = analyzeProxy(snapshot.proxy);
    checks.push(check("proxy", "系统代理", "network", proxy ? "warn" : "pass", proxy?.level ?? "info",
      proxy ? proxy.detail : "未启用系统代理或代理配置正常。",
      proxy ? "确认代理来源可信；不使用时可关闭系统代理。" : "无需处理。"));

    const startupHigh = startupDetections.filter((item) => item.kind !== "task" && item.severity === "high");
    const startupMedium = startupDetections.filter((item) => item.kind !== "task" && item.severity === "medium");
    checks.push(check("startup", "开机启动项", "persistence",
      startupHigh.length ? "fail" : startupMedium.length ? "warn" : "pass",
      startupHigh.length ? "high" : startupMedium.length ? "medium" : "info",
      startupHigh.length || startupMedium.length ? `${startupHigh.length + startupMedium.length} 条可疑启动项：${[...startupHigh, ...startupMedium].slice(0, 3).map((item) => item.name).join("、")}` : `已检查 ${startupSnapshot?.startup?.length ?? 0} 条启动项，未发现明显可疑命令。`,
      startupHigh.length || startupMedium.length ? "在“病毒查杀”中查看详情，并确认启动项来源。" : "无需处理。"));

    const taskHigh = startupDetections.filter((item) => item.kind === "task" && item.severity === "high");
    const taskMedium = startupDetections.filter((item) => item.kind === "task" && item.severity === "medium");
    checks.push(check("tasks", "计划任务", "persistence",
      taskHigh.length ? "fail" : taskMedium.length ? "warn" : "pass",
      taskHigh.length ? "high" : taskMedium.length ? "medium" : "info",
      taskHigh.length || taskMedium.length ? `${taskHigh.length + taskMedium.length} 条可疑计划任务：${[...taskHigh, ...taskMedium].slice(0, 3).map((item) => item.name).join("、")}` : `已检查 ${startupSnapshot?.tasks?.length ?? 0} 个非系统计划任务，未发现明显可疑命令。`,
      taskHigh.length || taskMedium.length ? "在任务计划程序中确认来源，必要时禁用。" : "无需处理。"));

    checks.push(check("secure-boot", "安全启动", "system",
      snapshot.secureBoot === true ? "pass" : snapshot.secureBoot === false ? "warn" : "unknown",
      snapshot.secureBoot === false ? "low" : "info",
      snapshot.secureBoot === true ? "Secure Boot 已开启。" : snapshot.secureBoot === false ? "Secure Boot 未开启或不受支持。" : "无法读取 Secure Boot 状态（可能为传统 BIOS）。",
      snapshot.secureBoot === false ? "在主板 UEFI 设置中开启 Secure Boot。" : "无需处理。"));
  }

  const lastScanSummary = lastScan?.summary ?? null;
  const lastAt = lastScan?.finishedAt ?? lastScan?.startedAt ?? null;
  const ageDays = lastAt ? Math.floor((Date.now() - Date.parse(lastAt)) / 86400000) : null;
  checks.push(check("last-scan", "最近一次查杀", "scan",
    !lastAt ? "warn" : lastScanSummary && Number(lastScanSummary.high) + Number(lastScanSummary.medium) > 0 ? "fail" : "pass",
    !lastAt ? "low" : lastScanSummary && Number(lastScanSummary.high) + Number(lastScanSummary.medium) > 0 ? "high" : "info",
    !lastAt ? "还没有执行过插件查杀。" : `${lastScan.mode ?? "快速"}扫描 · ${lastScanSummary?.total ?? 0} 项结果${ageDays != null ? ` · ${ageDays} 天前` : ""}`,
    !lastAt || (lastScanSummary && Number(lastScanSummary.high) + Number(lastScanSummary.medium) > 0) ? "执行快速查杀并处理检测结果。" : "无需处理。"));

  const summary = { pass: 0, warn: 0, fail: 0, unknown: 0, total: checks.length };
  for (const entry of checks) {
    if (summary[entry.status] != null) summary[entry.status] += 1;
  }
  return { checks, summary };
}

export function buildStatus(snapshot, dbInfo, quarantine, lastScan) {
  const evaluation = evaluate(snapshot, dbInfo.installed, quarantine, lastScan);
  const hosts = evaluation.hosts ?? analyzeHosts(snapshot.hosts);
  return {
    supported: snapshot.supported,
    partial: Boolean(snapshot.partial),
    platform: snapshot.platform,
    admin: snapshot.admin === true,
    os: snapshot.os,
    defender: snapshot.defender,
    avProducts: snapshot.avProducts,
    engine: evaluation.engine ?? null,
    firewall: snapshot.firewall,
    hardening: {
      uac: snapshot.uac,
      smb1: snapshot.smb,
      autorun: snapshot.autorun,
      rdp: snapshot.rdp,
      guest: snapshot.guest,
      wdigest: snapshot.wdigest,
      lsa: snapshot.lsa,
      secureBoot: snapshot.secureBoot,
    },
    defenderExclusions: snapshot.defenderExclusions,
    threats: snapshot.threats,
    hosts: { entries: hosts.entries, suspicious: hosts.suspicious.slice(0, 8), oversized: hosts.oversized },
    proxy: snapshot.proxy,
    score: evaluation.score,
    level: evaluation.level,
    headline: evaluation.headline,
    risks: evaluation.risks,
    pendingFixes: evaluation.pendingFixes,
    db: {
      version: dbInfo.db.version,
      hashes: dbInfo.db.rules.hashes.length,
      rules: dbInfo.db.rules.heuristics.length,
      releasedAt: dbInfo.db.releasedAt,
      publisher: dbInfo.db.publisher,
      source: dbInfo.source,
      builtin: dbInfo.builtin,
      installed: dbInfo.installed,
      meta: dbInfo.meta,
      publicKeyFingerprint: dbInfo.publicKeyFingerprint,
      publicKeySource: dbInfo.publicKeySource,
      warnings: dbInfo.warnings,
    },
    quarantine: { count: quarantine.count, bytes: quarantine.bytes, dir: PATHS.quarantine },
    lastScan: summarizeLastScan(lastScan),
    recentEvents: [],
    dataDir: PATHS.root,
    fixes: FIX_META,
    error: snapshot.error || "",
  };
}
