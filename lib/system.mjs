import { spawn } from "node:child_process";
import fs from "node:fs";

const IS_WIN = process.platform === "win32";
let adminCache = null;

function decodeOutput(buffer) {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.toString("utf16le");
  return buffer.toString("utf8").replace(/^\uFEFF/, "");
}

function parseJson(text) {
  const value = String(text ?? "").trim();
  if (!value) return null;
  try { return JSON.parse(value); } catch { /* 继续尝试逐行解析 */ }
  const lines = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index];
    if (!line.startsWith("{") && !line.startsWith("[")) continue;
    try { return JSON.parse(line); } catch { /* 继续 */ }
  }
  return null;
}

export function runPowerShell(script, timeoutMs = 30000) {
  if (!IS_WIN) {
    return Promise.resolve({ ok: false, unsupported: true, stdout: "", stderr: "当前系统不是 Windows", code: null });
  }
  return new Promise((resolve) => {
    const child = spawn("powershell.exe", [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", script,
    ], { windowsHide: true, env: { ...process.env, PSModulePath: process.env.PSModulePath ?? "" } });
    const stdout = [];
    const stderr = [];
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      resolve({ ok: false, stdout: decodeOutput(Buffer.concat(stdout)), stderr: `PowerShell 超时（${timeoutMs}ms）`, code: null });
    }, Math.max(2000, timeoutMs));
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ok: false, stdout: "", stderr: String(error?.message ?? error), code: null });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const out = decodeOutput(Buffer.concat(stdout));
      const err = decodeOutput(Buffer.concat(stderr));
      resolve({ ok: code === 0, stdout: out, stderr: err, code });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end();
  });
}

export async function runPowerShellJson(script, timeoutMs = 30000) {
  const result = await runPowerShell(script, timeoutMs);
  return { ...result, json: parseJson(result.stdout) };
}

const PRELUDE = [
  "$ErrorActionPreference='SilentlyContinue'",
  "$ProgressPreference='SilentlyContinue'",
  "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)",
  "$OutputEncoding=[Text.UTF8Encoding]::new($false)",
].join("; ");

const STATUS_SCRIPT = `${PRELUDE};
$out=[ordered]@{}
$out.admin=$false
try {
  $wi=[Security.Principal.WindowsIdentity]::GetCurrent()
  $wp=New-Object Security.Principal.WindowsPrincipal($wi)
  $out.admin=$wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
$os=Get-CimInstance Win32_OperatingSystem
if ($os) {
  $out.os=[ordered]@{ caption=[string]$os.Caption; version=[string]$os.Version; build=[int]$os.BuildNumber; architecture=[string]$os.OSArchitecture }
}
$d=Get-MpComputerStatus
if ($d) {
  $sigDate=$null
  if ($d.AntivirusSignatureLastUpdated) { $sigDate=$d.AntivirusSignatureLastUpdated.ToString('o') }
  $quick=$null
  if ($d.QuickScanStartTime) { $quick=$d.QuickScanStartTime.ToString('o') }
  $full=$null
  if ($d.FullScanStartTime) { $full=$d.FullScanStartTime.ToString('o') }
  $tamper=$false
  if ($null -ne $d.IsTamperProtected) { $tamper=[bool]$d.IsTamperProtected }
  $out.defender=[ordered]@{
    present=$true
    antivirusEnabled=[bool]$d.AntivirusEnabled
    realtimeEnabled=[bool]$d.RealTimeProtectionEnabled
    behaviorMonitorEnabled=[bool]$d.BehaviorMonitorEnabled
    ioavEnabled=[bool]$d.IoavProtectionEnabled
    onAccessEnabled=[bool]$d.OnAccessProtectionEnabled
    tamperProtected=$tamper
    signatureVersion=[string]$d.AntivirusSignatureVersion
    signatureUpdated=$sigDate
    engineVersion=[string]$d.AMEngineVersion
    lastQuickScan=$quick
    lastFullScan=$full
  }
}
$out.avProducts=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [ordered]@{ name=[string]$_.displayName; state=$_.productState } })
$out.firewall=@(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name=[string]$_.Name; enabled=[bool]$_.Enabled } })
$sys=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
if ($sys) {
  $out.uac=[ordered]@{ enabled=($sys.EnableLUA -eq 1); consentPrompt=[int]$sys.ConsentPromptBehaviorAdmin }
}
$smb=$null
try { $smb=Get-SmbServerConfiguration -ErrorAction Stop } catch {}
$out.smb=[ordered]@{ supported=($null -ne $smb); smb1Enabled=$false }
if ($smb) { $out.smb.smb1Enabled=[bool]$smb.EnableSMB1Protocol }
$hkcuExplorer=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer'
$hklmPolicy=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'
$noAutorun=$null
$ndta=$null
if ($hklmPolicy) { $noAutorun=$hklmPolicy.NoAutorun; $ndta=$hklmPolicy.NoDriveTypeAutoRun }
if ($null -eq $ndta -and $hkcuExplorer) { $ndta=$hkcuExplorer.NoDriveTypeAutoRun }
$out.autorun=[ordered]@{ noAutorun=$noAutorun; noDriveTypeAutoRun=$ndta }
$rdp=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'
$rdpTcp=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'
$rdpEnabled=$false
$nla=$false
if ($rdp) { $rdpEnabled=($rdp.fDenyTSConnections -eq 0) }
if ($rdpTcp) { $nla=($rdpTcp.UserAuthentication -eq 1) }
$out.rdp=[ordered]@{ enabled=$rdpEnabled; nla=$nla }
$out.guest=[ordered]@{ supported=$false; enabled=$false }
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
  $out.guest.supported=$true
  $guest=Get-LocalUser -Name Guest
  if ($guest) { $out.guest.enabled=[bool]$guest.Enabled }
}
$wd=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest'
$wdigest=$false
if ($wd -and $wd.UseLogonCredential -eq 1) { $wdigest=$true }
$out.wdigest=[ordered]@{ enabled=$wdigest }
$lsa=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
$ppl=0
if ($lsa -and $null -ne $lsa.RunAsPPL) { $ppl=[int]$lsa.RunAsPPL }
$out.lsa=[ordered]@{ runAsPPL=$ppl }
$pref=Get-MpPreference
if ($pref) {
  $out.defenderExclusions=[ordered]@{
    paths=@($pref.ExclusionPath | Where-Object { $_ })
    extensions=@($pref.ExclusionExtension | Where-Object { $_ })
    processes=@($pref.ExclusionProcess | Where-Object { $_ })
    puaProtection=[int]$pref.PUAProtection
  }
}
$out.threats=@(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 8 | ForEach-Object {
  $time=$null
  if ($_.InitialDetectionTime) { $time=$_.InitialDetectionTime.ToString('o') }
  [ordered]@{ name=[string]$_.ThreatName; time=$time; resources=@($_.Resources | Where-Object { $_ }) }
})
$hostsPath="$env:SystemRoot\\System32\\drivers\\etc\\hosts"
if (Test-Path -LiteralPath $hostsPath) { $out.hosts=[string](Get-Content -LiteralPath $hostsPath -Raw) }
$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
if ($p) {
  $out.proxy=[ordered]@{ enabled=($p.ProxyEnable -eq 1); server=[string]$p.ProxyServer; autoConfigUrl=[string]$p.AutoConfigURL }
}
$secure=$null
try { $secure=Confirm-SecureBootUEFI -ErrorAction Stop } catch {}
$out.secureBoot=$secure
$out | ConvertTo-Json -Depth 8 -Compress
`;

const STARTUP_SCRIPT = `${PRELUDE};
$items=@()
$keys=@(
  @{ path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'; label='HKCU Run' },
  @{ path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'; label='HKCU RunOnce' },
  @{ path='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'; label='HKLM Run' },
  @{ path='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'; label='HKLM RunOnce' },
  @{ path='HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'; label='HKLM Run (x86)' }
)
foreach ($key in $keys) {
  $props=Get-ItemProperty -Path $key.path
  if ($props) {
    $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
      $items += [ordered]@{ name=[string]$_.Name; command=[string]$_.Value; source=$key.label }
    }
  }
}
$folders=@("$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
foreach ($folder in $folders) {
  if (Test-Path -LiteralPath $folder) {
    Get-ChildItem -LiteralPath $folder -File | ForEach-Object {
      $items += [ordered]@{ name=$_.Name; command=$_.FullName; source='Startup Folder' }
    }
  }
}
$tasks=@(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object {
  $commands=@($_.Actions | Where-Object { $_.Execute } | ForEach-Object { ("{0} {1}" -f $_.Execute, $_.Arguments).Trim() })
  [ordered]@{ name=[string]$_.TaskName; path=[string]$_.TaskPath; command=($commands -join ' | ') }
})
$out=[ordered]@{ startup=$items; tasks=$tasks }
$out | ConvertTo-Json -Depth 6 -Compress
`;

const PROCESS_SCRIPT = `${PRELUDE};
$items=@(Get-CimInstance Win32_Process | Where-Object { $_.Name -and $_.Name -notin @('System','Idle','Registry') } | ForEach-Object {
  [ordered]@{ pid=[int]$_.ProcessId; name=[string]$_.Name; path=[string]$_.ExecutablePath; commandLine=[string]$_.CommandLine }
})
ConvertTo-Json -InputObject $items -Depth 5 -Compress
`;

export async function getSystemSnapshot() {
  if (!IS_WIN) {
    return {
      supported: false,
      platform: process.platform,
      admin: false,
      os: null,
      defender: null,
      avProducts: [],
      firewall: { known: false, profiles: [], enabled: false },
      uac: { known: false, enabled: null },
      smb: { supported: false, smb1Enabled: false },
      autorun: { known: false, disabled: null },
      rdp: { known: false, enabled: false, nla: false },
      guest: { supported: false, enabled: false },
      wdigest: { enabled: false },
      lsa: { runAsPPL: 0 },
      defenderExclusions: { paths: [], extensions: [], processes: [] },
      threats: [],
      hosts: "",
      proxy: { enabled: false, server: "", autoConfigUrl: "" },
      secureBoot: null,
      error: "当前系统不是 Windows，仅支持文件查杀与开放病毒库。",
    };
  }
  const result = await runPowerShellJson(STATUS_SCRIPT, 45000);
  if (!result.json) {
    return {
      supported: true,
      platform: process.platform,
      admin: false,
      partial: true,
      error: result.stderr || "PowerShell 系统检查失败",
      os: null,
      defender: null,
      avProducts: [],
      firewall: { known: false, profiles: [], enabled: false },
      uac: { known: false, enabled: null },
      smb: { supported: false, smb1Enabled: false },
      autorun: { known: false, disabled: null },
      rdp: { known: false, enabled: false, nla: false },
      guest: { supported: false, enabled: false },
      wdigest: { enabled: false },
      lsa: { runAsPPL: 0 },
      defenderExclusions: { paths: [], extensions: [], processes: [] },
      threats: [],
      hosts: "",
      proxy: { enabled: false, server: "", autoConfigUrl: "" },
      secureBoot: null,
    };
  }
  const raw = result.json;
  const defender = raw.defender ? {
    present: true,
    antivirusEnabled: raw.defender.antivirusEnabled === true,
    realtimeEnabled: raw.defender.realtimeEnabled === true,
    behaviorMonitorEnabled: raw.defender.behaviorMonitorEnabled === true,
    ioavEnabled: raw.defender.ioavEnabled === true,
    onAccessEnabled: raw.defender.onAccessEnabled === true,
    tamperProtected: raw.defender.tamperProtected === true,
    signatureVersion: String(raw.defender.signatureVersion ?? ""),
    signatureUpdated: raw.defender.signatureUpdated ?? null,
    signatureAgeDays: ageDays(raw.defender.signatureUpdated),
    engineVersion: String(raw.defender.engineVersion ?? ""),
    lastQuickScan: raw.defender.lastQuickScan ?? null,
    lastFullScan: raw.defender.lastFullScan ?? null,
  } : null;
  const profiles = asArray(raw.firewall).map((entry) => ({
    name: String(entry?.name ?? ""),
    enabled: entry?.enabled === true,
  })).filter((entry) => entry.name);
  const avProducts = asArray(raw.avProducts).map((entry) => ({
    name: String(entry?.name ?? ""),
    state: Number(entry?.state ?? 0),
  })).filter((entry) => entry.name);
  const ndta = raw.autorun?.noDriveTypeAutoRun;
  const noAutorun = raw.autorun?.noAutorun;
  let autorunDisabled = null;
  if (Number.isFinite(Number(ndta))) autorunDisabled = Number(ndta) >= 0x91;
  if (noAutorun === 1) autorunDisabled = true;
  if (Number(ndta) === 0 && noAutorun !== 1) autorunDisabled = false;
  return {
    supported: true,
    platform: process.platform,
    partial: false,
    admin: raw.admin === true,
    os: raw.os ? {
      caption: String(raw.os.caption ?? ""),
      version: String(raw.os.version ?? ""),
      build: Number(raw.os.build ?? 0),
      architecture: String(raw.os.architecture ?? ""),
    } : null,
    defender,
    avProducts,
    firewall: { known: profiles.length > 0, profiles, enabled: profiles.length > 0 && profiles.every((entry) => entry.enabled) },
    uac: { known: Boolean(raw.uac), enabled: raw.uac ? raw.uac.enabled === true : null, consentPrompt: Number(raw.uac?.consentPrompt ?? -1) },
    smb: { supported: raw.smb?.supported === true, smb1Enabled: raw.smb?.smb1Enabled === true },
    autorun: { known: autorunDisabled !== null, disabled: autorunDisabled, noAutorun, noDriveTypeAutoRun: ndta },
    rdp: { known: true, enabled: raw.rdp?.enabled === true, nla: raw.rdp?.nla === true },
    guest: { supported: raw.guest?.supported === true, enabled: raw.guest?.enabled === true },
    wdigest: { enabled: raw.wdigest?.enabled === true },
    lsa: { runAsPPL: Number(raw.lsa?.runAsPPL ?? 0) },
    defenderExclusions: {
      paths: asArray(raw.defenderExclusions?.paths).map(String),
      extensions: asArray(raw.defenderExclusions?.extensions).map(String),
      processes: asArray(raw.defenderExclusions?.processes).map(String),
      puaProtection: Number(raw.defenderExclusions?.puaProtection ?? 0),
    },
    threats: asArray(raw.threats).map((entry) => ({
      name: String(entry?.name ?? "未知威胁"),
      time: entry?.time ?? null,
      resources: asArray(entry?.resources).map(String),
    })),
    hosts: String(raw.hosts ?? ""),
    proxy: {
      enabled: raw.proxy?.enabled === true,
      server: String(raw.proxy?.server ?? ""),
      autoConfigUrl: String(raw.proxy?.autoConfigUrl ?? ""),
    },
    secureBoot: typeof raw.secureBoot === "boolean" ? raw.secureBoot : null,
    error: result.ok ? "" : (result.stderr || ""),
  };
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value == null) return [];
  return [value];
}

function ageDays(value) {
  const time = Date.parse(String(value ?? ""));
  if (!Number.isFinite(time)) return null;
  return Math.max(0, Math.floor((Date.now() - time) / 86400000));
}

export async function isAdmin() {
  if (!IS_WIN) return false;
  if (adminCache !== null) return adminCache;
  const result = await runPowerShellJson(`${PRELUDE};
$admin=$false
try { $wi=[Security.Principal.WindowsIdentity]::GetCurrent(); $wp=New-Object Security.Principal.WindowsPrincipal($wi); $admin=$wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
[ordered]@{ admin=$admin } | ConvertTo-Json -Compress`, 15000);
  adminCache = result.json?.admin === true;
  return adminCache;
}

export async function getStartupSnapshot() {
  if (!IS_WIN) return { startup: [], tasks: [], error: "当前系统不是 Windows" };
  const result = await runPowerShellJson(STARTUP_SCRIPT, 45000);
  if (!result.json) return { startup: [], tasks: [], error: result.stderr || "启动项读取失败" };
  return {
    startup: asArray(result.json.startup).map((entry) => ({
      name: String(entry?.name ?? ""),
      command: String(entry?.command ?? ""),
      source: String(entry?.source ?? ""),
    })).filter((entry) => entry.name || entry.command),
    tasks: asArray(result.json.tasks).map((entry) => ({
      name: String(entry?.name ?? ""),
      path: String(entry?.path ?? ""),
      command: String(entry?.command ?? ""),
    })).filter((entry) => entry.name || entry.command),
    error: "",
  };
}

export async function getProcesses() {
  if (!IS_WIN) return [];
  const result = await runPowerShellJson(PROCESS_SCRIPT, 30000);
  return asArray(result.json).map((entry) => ({
    pid: Number(entry?.pid ?? 0),
    name: String(entry?.name ?? ""),
    path: String(entry?.path ?? ""),
    commandLine: String(entry?.commandLine ?? ""),
  })).filter((entry) => entry.name);
}

const FIXES = {
  "defender-realtime": {
    title: "开启 Defender 实时防护",
    requiresReboot: false,
    script: `Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop`,
  },
  firewall: {
    title: "开启 Windows 防火墙",
    requiresReboot: false,
    script: `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop`,
  },
  autorun: {
    title: "关闭所有驱动器自动运行",
    requiresReboot: false,
    script: `New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoAutorun -Value 1 -Type DWord -Force`,
  },
  uac: {
    title: "开启用户账户控制（UAC）",
    requiresReboot: true,
    script: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord -Force`,
  },
  smb1: {
    title: "关闭 SMBv1",
    requiresReboot: false,
    script: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop`,
  },
  "rdp-nla": {
    title: "远程桌面强制网络级身份验证",
    requiresReboot: false,
    script: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord -Force`,
  },
  guest: {
    title: "禁用 Guest 来宾账户",
    requiresReboot: false,
    script: `if (Get-LocalUser -Name Guest -ErrorAction SilentlyContinue) { Disable-LocalUser -Name Guest -ErrorAction Stop }`,
  },
  wdigest: {
    title: "禁止 WDigest 明文凭据缓存",
    requiresReboot: true,
    script: `New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0 -Type DWord -Force`,
  },
  lsa: {
    title: "开启 LSA 进程保护",
    requiresReboot: true,
    script: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord -Force`,
  },
};

export function fixCatalog() {
  return Object.fromEntries(Object.entries(FIXES).map(([id, entry]) => [id, { title: entry.title, requiresReboot: entry.requiresReboot }]));
}

export async function applyFix(id) {
  const entry = FIXES[String(id)];
  if (!entry) throw new Error(`未知修复项：${id}`);
  if (!(await isAdmin())) {
    const error = new Error("该修复需要管理员权限。请关闭若道 Agent，右键“以管理员身份运行”后重试。");
    error.needsAdmin = true;
    throw error;
  }
  const script = `${PRELUDE};
$ErrorActionPreference='Stop'
try {
  ${entry.script}
  [ordered]@{ ok=$true; message='${entry.title}已应用' } | ConvertTo-Json -Compress
} catch {
  [ordered]@{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress
}`;
  const result = await runPowerShellJson(script, 120000);
  if (!result.json) throw new Error(result.stderr || "修复命令执行失败");
  if (!result.json.ok) throw new Error(String(result.json.error ?? "修复失败"));
  return { id, title: entry.title, requiresReboot: entry.requiresReboot, message: String(result.json.message ?? "已应用") };
}

export async function updateDefenderSignatures() {
  if (!IS_WIN) throw new Error("仅 Windows 支持 Defender 病毒库升级");
  const script = `${PRELUDE};
$ErrorActionPreference='Stop'
try {
  Update-MpSignature -ErrorAction Stop
  $d=Get-MpComputerStatus
  $sig=$null
  if ($d.AntivirusSignatureLastUpdated) { $sig=$d.AntivirusSignatureLastUpdated.ToString('o') }
  [ordered]@{ ok=$true; signatureVersion=[string]$d.AntivirusSignatureVersion; signatureUpdated=$sig; engineVersion=[string]$d.AMEngineVersion } | ConvertTo-Json -Compress
} catch {
  [ordered]@{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress
}`;
  const result = await runPowerShellJson(script, 300000);
  if (!result.json) throw new Error(result.stderr || "Defender 病毒库升级失败");
  if (!result.json.ok) throw new Error(String(result.json.error ?? "Defender 病毒库升级失败"));
  return {
    signatureVersion: String(result.json.signatureVersion ?? ""),
    signatureUpdated: result.json.signatureUpdated ?? null,
    engineVersion: String(result.json.engineVersion ?? ""),
  };
}

export async function runDefenderQuickScan() {
  if (!IS_WIN) throw new Error("仅 Windows 支持 Defender 扫描");
  const script = `${PRELUDE};
$ErrorActionPreference='Stop'
$start=Get-Date
try {
  Start-MpScan -ScanType QuickScan -ErrorAction Stop
  $threats=@(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10 | ForEach-Object {
    $time=$null
    if ($_.InitialDetectionTime) { $time=$_.InitialDetectionTime.ToString('o') }
    [ordered]@{ name=[string]$_.ThreatName; time=$time }
  })
  [ordered]@{ ok=$true; elapsedSec=[int]((Get-Date)-$start).TotalSeconds; threats=$threats } | ConvertTo-Json -Depth 5 -Compress
} catch {
  [ordered]@{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress
}`;
  const result = await runPowerShellJson(script, 600000);
  if (!result.json) throw new Error(result.stderr || "Defender 扫描失败");
  if (!result.json.ok) throw new Error(String(result.json.error ?? "Defender 扫描失败"));
  return {
    elapsedSec: Number(result.json.elapsedSec ?? 0),
    threats: asArray(result.json.threats).map((entry) => ({
      name: String(entry?.name ?? "未知威胁"),
      time: entry?.time ?? null,
    })),
  };
}

export function analyzeHosts(raw) {
  const lines = String(raw ?? "").split(/\r?\n/);
  const entries = [];
  for (const line of lines) {
    const text = line.trim();
    if (!text || text.startsWith("#")) continue;
    const parts = text.split(/\s+/);
    if (parts.length < 2) continue;
    const ip = parts[0];
    for (const host of parts.slice(1)) entries.push({ ip, host: host.toLowerCase() });
  }
  const protectedPatterns = [
    /(^|\.)windowsupdate\.com$/,
    /(^|\.)update\.microsoft\.com$/,
    /(^|\.)windowsdefender\.microsoft\.com$/,
    /(^|\.)microsoft\.com$/,
    /(^|\.)microsoftonline\.com$/,
    /(^|\.)live\.com$/,
    /(^|\.)office\.com$/,
    /(^|\.)msftconnecttest\.com$/,
    /(^|\.)msftncsi\.com$/,
    /(^|\.)smartscreen\.microsoft\.com$/,
  ];
  const suspicious = [];
  for (const entry of entries) {
    if (entry.ip === "127.0.0.1" || entry.ip === "::1" || entry.ip === "0.0.0.0") {
      if (protectedPatterns.some((pattern) => pattern.test(entry.host))) suspicious.push(entry);
    }
  }
  return {
    entries: entries.length,
    lines: lines.length,
    suspicious,
    oversized: entries.length > 5000,
  };
}

export function analyzeProxy(proxy) {
  if (!proxy?.enabled) return null;
  const server = String(proxy.server ?? "").trim();
  const autoConfigUrl = String(proxy.autoConfigUrl ?? "").trim();
  if (autoConfigUrl && /^http:\/\//i.test(autoConfigUrl)) {
    return { level: "low", title: "代理自动配置使用 HTTP", detail: `AutoConfigURL：${autoConfigUrl}` };
  }
  if (server && !/^(127\.0\.0\.1|localhost)/i.test(server)) {
    return { level: "info", title: "系统正在使用代理", detail: `代理服务器：${server}` };
  }
  return null;
}
