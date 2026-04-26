const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const fs = require("fs/promises");
const { spawn } = require("child_process");

const CONFIG_FILE = "settings.json";
const KB_DIR = path.join(__dirname, "../../data/attack-kb");

const defaultSettings = {
  apiBaseUrl: "https://api.openai.com/v1",
  apiKey: "",
  model: "gpt-4.1-mini",
  organization: "",
  allowLocalTools: false,
  allowCommandAdapters: false,
  scopedTargets: [],
  postgres: {
    enabled: true,
    connectionString: "postgres://aip:aip_dev_password@localhost:5432/crosshair"
  },
  toolPaths: {
    nmap: "nmap",
    amass: "amass",
    naabu: "naabu",
    httpx: "httpx"
  }
};

const reconToolProfiles = {
  nmap: {
    id: "nmap",
    name: "Nmap Service Discovery",
    phase: "recon",
    tactic: "TA0043",
    technique: "T1595 Active Scanning",
    pathKey: "nmap",
    targetType: "cidr-ip-host",
    description: "Enumerates live hosts and common service banners in authorized ranges.",
    buildArgs: (target, options = {}) => {
      const port = normalizedPort(options.port);
      if (port === "all") return ["-sV", "-p-", target];
      return port ? ["-sV", "-p", port, target] : ["-sV", "--top-ports", "100", target];
    },
    parse: nmapToNetwork
  },
  amass: {
    id: "amass",
    name: "Amass Passive Asset Discovery",
    phase: "recon",
    tactic: "TA0043",
    technique: "T1596 Search Open Technical Databases",
    pathKey: "amass",
    targetType: "domain",
    description: "Collects passive DNS and certificate-derived assets for authorized domains.",
    buildArgs: (target) => ["enum", "-passive", "-d", target],
    parse: linesToReconNetwork
  },
  naabu: {
    id: "naabu",
    name: "Naabu Fast Port Discovery",
    phase: "recon",
    tactic: "TA0043",
    technique: "T1595 Active Scanning",
    pathKey: "naabu",
    targetType: "cidr-ip-host",
    description: "Runs fast port discovery against authorized targets.",
    buildArgs: (target) => ["-host", target, "-top-ports", "100"],
    parse: linesToReconNetwork
  },
  httpx: {
    id: "httpx",
    name: "HTTPX Web Fingerprinting",
    phase: "recon",
    tactic: "TA0043",
    technique: "T1595 Active Scanning",
    pathKey: "httpx",
    targetType: "url-host",
    description: "Fingerprints HTTP services and status codes for authorized hosts.",
    buildArgs: (target) => ["-u", target, "-title", "-tech-detect", "-status-code"],
    parse: linesToReconNetwork
  }
};

const toolExecutableHints = {
  win32: {
    nmap: [
      "C:\\Program Files\\Nmap\\nmap.exe",
      "C:\\Program Files (x86)\\Nmap\\nmap.exe"
    ],
    amass: [],
    naabu: [],
    httpx: []
  },
  darwin: {
    nmap: ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap"],
    amass: ["/opt/homebrew/bin/amass", "/usr/local/bin/amass"],
    naabu: ["/opt/homebrew/bin/naabu", "/usr/local/bin/naabu"],
    httpx: ["/opt/homebrew/bin/httpx", "/usr/local/bin/httpx"]
  },
  linux: {
    nmap: ["/usr/bin/nmap", "/usr/local/bin/nmap", "/snap/bin/nmap"],
    amass: ["/usr/bin/amass", "/usr/local/bin/amass", "/snap/bin/amass"],
    naabu: ["/usr/bin/naabu", "/usr/local/bin/naabu", "/snap/bin/naabu"],
    httpx: ["/usr/bin/httpx", "/usr/local/bin/httpx", "/snap/bin/httpx"]
  }
};

const platformToolInstallHints = {
  nmap: {
    win32: "Install Nmap from nmap.org or set Settings > Nmap Path to its full executable path, for example C:\\Program Files\\Nmap\\nmap.exe.",
    darwin: "Install Nmap with Homebrew (`brew install nmap`) or set Settings > Nmap Path to its full executable path.",
    linux: "Install Nmap with your distribution package manager or set Settings > Nmap Path to its full executable path."
  },
  amass: {
    win32: "Install Amass and set Settings > Amass Path to the installed executable path.",
    darwin: "Install Amass with Homebrew (`brew install amass`) or set Settings > Amass Path to its full executable path.",
    linux: "Install Amass with your distribution package manager, Snap, or a release binary, then set Settings > Amass Path if it is not on PATH."
  },
  naabu: {
    win32: "Install Naabu and set Settings > Naabu Path to the installed executable path.",
    darwin: "Install Naabu with Homebrew or a ProjectDiscovery release binary, then set Settings > Naabu Path if it is not on PATH.",
    linux: "Install Naabu with your package manager or a ProjectDiscovery release binary, then set Settings > Naabu Path if it is not on PATH."
  },
  httpx: {
    win32: "Install ProjectDiscovery HTTPX and set Settings > HTTPX Path to the installed executable path.",
    darwin: "Install ProjectDiscovery HTTPX with Homebrew or a release binary, then set Settings > HTTPX Path if it is not on PATH.",
    linux: "Install ProjectDiscovery HTTPX with your package manager or a release binary, then set Settings > HTTPX Path if it is not on PATH."
  }
};

const emptyNetwork = {
  hosts: [],
  links: [],
  findings: []
};

let mainWindow;
let startupDependencyReport = null;

function userDataPath() {
  return path.join(app.getPath("userData"), CONFIG_FILE);
}

async function readSettings() {
  try {
    const raw = await fs.readFile(userDataPath(), "utf8");
    const parsed = JSON.parse(raw);
    const merged = {
      ...defaultSettings,
      ...parsed,
      postgres: { ...defaultSettings.postgres, ...(parsed.postgres || {}) },
      toolPaths: { ...defaultSettings.toolPaths, ...(parsed.toolPaths || {}) }
    };
    const legacyDatabase = ["aip", "pur" + "ple", "team"].join("_");
    const legacyConnections = [
      `postgres://aip:aip@localhost:5432/${legacyDatabase}`,
      `postgres://aip:aip_dev_password@localhost:5432/${legacyDatabase}`
    ];
    if (!parsed.postgres || legacyConnections.includes(parsed.postgres.connectionString)) {
      merged.postgres = { ...defaultSettings.postgres };
    }
    return merged;
  } catch {
    return defaultSettings;
  }
}

async function writeSettings(settings) {
  const merged = {
    ...defaultSettings,
    ...settings,
    postgres: { ...defaultSettings.postgres, ...(settings.postgres || {}) },
    toolPaths: { ...defaultSettings.toolPaths, ...(settings.toolPaths || {}) }
  };
  await fs.mkdir(app.getPath("userData"), { recursive: true });
  await fs.writeFile(userDataPath(), JSON.stringify(merged, null, 2));
  return merged;
}

async function readJsonFile(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

async function readAttackKnowledge() {
  const files = [];

  async function collect(dir) {
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const entryPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          await collect(entryPath);
        } else if (entry.name.endsWith(".json")) {
          files.push(entryPath);
        }
      }
    } catch {
      return;
    }
  }

  await collect(KB_DIR);
  const docs = await Promise.all(files.map(readJsonFile));
  const phases = docs.flatMap((doc) => doc.phases || []);
  return {
    version: "0.1.0",
    files: files.map((file) => path.relative(path.join(__dirname, "../.."), file)),
    phases
  };
}

async function loadAttackPhases() {
  const knowledge = await readAttackKnowledge();
  return knowledge.phases.map((phase) => ({
    id: phase.id,
    name: phase.name,
    tactic: phase.tactic,
    techniques: (phase.techniques || []).map((technique) => `${technique.id} ${technique.name}`),
    description: (phase.defensiveUse || [])[0] || ""
  }));
}

function getPg() {
  return require("pg");
}

async function withPostgres(settings, callback) {
  if (!settings.postgres?.enabled || !settings.postgres.connectionString) {
    return { ok: false, message: "Postgres evidence storage is disabled." };
  }

  const { Client } = getPg();
  const client = new Client({ connectionString: settings.postgres.connectionString });
  await client.connect();
  try {
    return await callback(client);
  } finally {
    await client.end();
  }
}

async function ensureEvidenceSchema(client) {
  await client.query(`
    create table if not exists recon_runs (
      id bigserial primary key,
      created_at timestamptz not null default now(),
      tool text not null,
      target text not null,
      attack_tactic text not null,
      attack_technique text not null,
      stdout text,
      network jsonb not null
    )
  `);
  await client.query(`
    create table if not exists findings (
      id text primary key,
      recon_run_id bigint references recon_runs(id) on delete set null,
      host text,
      severity text,
      title text not null,
      status text not null,
      technique text not null,
      evidence jsonb not null default '{}'::jsonb,
      updated_at timestamptz not null default now()
    )
  `);
}

async function saveReconEvidence(settings, payload) {
  if (!settings.postgres?.enabled) {
    return { ok: true, skipped: true, message: "Postgres storage disabled." };
  }

  try {
    return await withPostgres(settings, async (client) => {
      await ensureEvidenceSchema(client);
      const run = await client.query(
        `insert into recon_runs (tool, target, attack_tactic, attack_technique, stdout, network)
         values ($1, $2, $3, $4, $5, $6)
         returning id`,
        [
          payload.tool.id,
          payload.target,
          payload.tool.tactic,
          payload.tool.technique,
          payload.stdout || "",
          JSON.stringify(payload.network)
        ]
      );

      const reconRunId = run.rows[0].id;
      for (const finding of payload.network.findings || []) {
        await client.query(
          `insert into findings (id, recon_run_id, host, severity, title, status, technique, evidence)
           values ($1, $2, $3, $4, $5, $6, $7, $8)
           on conflict (id) do update set
             recon_run_id = excluded.recon_run_id,
             host = excluded.host,
             severity = excluded.severity,
             title = excluded.title,
             status = excluded.status,
             technique = excluded.technique,
             evidence = excluded.evidence,
             updated_at = now()`,
          [
            finding.id,
            reconRunId,
            finding.host || "",
            finding.severity || "low",
            finding.title,
            finding.status || "needs validation",
            finding.technique,
            JSON.stringify({ source: payload.tool.name, target: payload.target })
          ]
        );
      }

      return { ok: true, reconRunId };
    });
  } catch (error) {
    return { ok: false, message: error.message };
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 620,
    title: "Crosshair Terminal",
    backgroundColor: "#111820",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, "../renderer/index.html"));
}

async function runCommand(command, args, timeoutMs = 120000) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { shell: false, windowsHide: true });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ ok: false, stdout, stderr: `${stderr}\nCommand timed out.`.trim() });
    }, timeoutMs);

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ ok: false, stdout, stderr: error.message, errorCode: error.code });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, code, stdout, stderr });
    });
  });
}

async function commandExistsOnPath(command) {
  if (!command || hasPathSeparator(command)) return false;

  if (process.platform === "win32") {
    const result = await runCommand("where.exe", [command], 5000);
    return result.ok;
  }

  const result = await runCommand("which", [command], 5000);
  return result.ok;
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function hasPathSeparator(value) {
  return /[\\/]/.test(value);
}

async function resolveToolCommand(tool, configuredPath) {
  const command = String(configuredPath || tool.pathKey).trim();
  if (!command) return tool.pathKey;

  if (path.isAbsolute(command) || hasPathSeparator(command)) {
    if (await fileExists(command)) return command;
    if (process.platform === "win32" && !command.toLowerCase().endsWith(".exe") && await fileExists(`${command}.exe`)) {
      return `${command}.exe`;
    }
    return command;
  }

  const platformHints = toolExecutableHints[process.platform] || toolExecutableHints.linux;
  for (const candidate of platformHints[tool.id] || []) {
    if (await fileExists(candidate)) return candidate;
  }

  return command;
}

async function checkToolDependency(tool, settings) {
  const configuredPath = settings.toolPaths?.[tool.pathKey] || tool.pathKey;
  const command = await resolveToolCommand(tool, configuredPath);
  const absoluteOrRelativePath = path.isAbsolute(command) || hasPathSeparator(command);
  const exists = absoluteOrRelativePath ? await fileExists(command) : await commandExistsOnPath(command);

  return {
    id: tool.id,
    name: tool.name,
    configuredPath,
    resolvedPath: command,
    ok: exists,
    required: Boolean(settings.allowLocalTools),
    message: exists ? "Found" : missingToolMessage(tool, command)
  };
}

async function checkPostgresDependency(settings) {
  if (!settings.postgres?.enabled) {
    return {
      id: "postgres",
      name: "Postgres Evidence Store",
      ok: true,
      required: false,
      message: "Disabled in Settings"
    };
  }

  try {
    return await withPostgres(settings, async (client) => {
      await ensureEvidenceSchema(client);
      return {
        id: "postgres",
        name: "Postgres Evidence Store",
        ok: true,
        required: true,
        message: "Connection OK"
      };
    });
  } catch (error) {
    return {
      id: "postgres",
      name: "Postgres Evidence Store",
      ok: false,
      required: true,
      message: `Postgres connection failed: ${error.message}`
    };
  }
}

async function checkStartupDependencies() {
  const settings = await readSettings();
  const toolResults = await Promise.all(
    Object.values(reconToolProfiles).map((tool) => checkToolDependency(tool, settings))
  );
  const postgresResult = await checkPostgresDependency(settings);
  const results = [...toolResults, postgresResult];

  return {
    checkedAt: new Date().toISOString(),
    allowLocalTools: Boolean(settings.allowLocalTools),
    results,
    missing: results.filter((result) => !result.ok),
    blocking: results.filter((result) => !result.ok && result.required)
  };
}

function startupDependencyDetail(report) {
  const rows = report.results.map((result) => {
    const status = result.ok ? "OK" : result.required ? "MISSING" : "NOT FOUND";
    const pathText = result.resolvedPath ? ` (${result.resolvedPath})` : "";
    return `${status}: ${result.name}${pathText}\n${result.message}`;
  });

  return [
    `Checked ${report.results.length} dependencies before startup.`,
    report.allowLocalTools
      ? "Local tool execution is enabled, so missing recon tools pause startup."
      : "Local tool execution is disabled; missing recon tools are listed but only Postgres can block if enabled.",
    "",
    ...rows
  ].join("\n");
}

async function confirmStartupDependencies() {
  while (true) {
    startupDependencyReport = await checkStartupDependencies();

    if (!startupDependencyReport.missing.length) {
      await dialog.showMessageBox({
        type: "info",
        buttons: ["Start Crosshair"],
        defaultId: 0,
        title: "Dependency Check Complete",
        message: "All configured startup dependencies are available.",
        detail: startupDependencyDetail(startupDependencyReport)
      });
      return true;
    }

    const blocking = startupDependencyReport.blocking.length;
    const result = await dialog.showMessageBox({
      type: blocking ? "warning" : "info",
      buttons: blocking ? ["Retry Check", "Open Anyway", "Quit"] : ["Start Crosshair", "Retry Check", "Quit"],
      defaultId: 0,
      cancelId: blocking ? 2 : 2,
      title: "Dependency Check Needs Attention",
      message: blocking
        ? `${blocking} required startup dependency ${blocking === 1 ? "is" : "are"} missing.`
        : "Some optional recon tools are not installed.",
      detail: startupDependencyDetail(startupDependencyReport)
    });

    if (blocking) {
      if (result.response === 0) continue;
      if (result.response === 1) return true;
      return false;
    }

    if (result.response === 0) return true;
    if (result.response === 1) continue;
    return false;
  }
}

function missingToolMessage(tool, command) {
  const hint = platformToolInstallHints[tool.id]?.[process.platform]
    || `Install ${tool.name} or set its full executable path in Settings.`;
  return `${tool.name} executable was not found (${command}). ${hint}`;
}

function normalizedPort(port) {
  const value = String(port || "").trim();
  if (/^(all|-p-|1-65535)$/i.test(value)) return "all";
  if (!/^\d{1,5}$/.test(value)) return null;
  const number = Number(value);
  return number >= 1 && number <= 65535 ? value : null;
}

function latestPortSelection(values) {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const value = String(values[index] || "");
    if (/\b(?:all|full)\s+ports?\b|1\s*-\s*65535|\bnmap\b[^\n`]*\s-p-\b|\s-p-\s/i.test(value)) {
      return "all";
    }
    const match = value.match(/(?:\bport\s+|-p\s*)(\d{1,5})\b/i);
    if (match) return match[1];
  }
  return null;
}

function targetIsScoped(target, scopedTargets) {
  if (!target || typeof target !== "string") return false;
  const trimmed = target.trim();
  return scopedTargets.some((scope) => {
    const cleanScope = String(scope).trim();
    if (!cleanScope) return false;
    if (trimmed === cleanScope) return true;
    if (cleanScope.includes("/") && ipv4TargetInCidr(trimmed, cleanScope)) return true;
    return trimmed === cleanScope || trimmed.endsWith(cleanScope);
  });
}

function ipToInt(ip) {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return parts.reduce((sum, part) => ((sum << 8) + part) >>> 0, 0);
}

function ipv4TargetInCidr(target, cidr) {
  const targetIp = target.includes("/") ? target.split("/")[0] : target;
  const [baseIp, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  const targetInt = ipToInt(targetIp);
  const baseInt = ipToInt(baseIp);

  if (targetInt === null || baseInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (targetInt & mask) === (baseInt & mask);
}

function nmapToNetwork(stdout, target) {
  const hosts = [];
  const links = [];
  const findings = [];
  const hostBlocks = stdout.split(/\nNmap scan report for /).slice(1);

  hostBlocks.forEach((block, index) => {
    const lines = block.split(/\r?\n/);
    const first = lines[0] || target;
    const ipMatch = first.match(/\(([^)]+)\)/);
    const ip = ipMatch ? ipMatch[1] : first.trim();
    const openPorts = lines.filter((line) => /open\s+\w+/.test(line));
    const services = openPorts.map((line) => {
      const parts = line.trim().match(/^(\d+)\/(\w+)\s+open\s+(\S+)\s*(.*)$/);
      return parts
        ? {
          port: parts[1],
          protocol: parts[2],
          name: parts[3],
          version: parts[4].trim(),
          raw: line.trim()
        }
        : {
          port: "",
          protocol: "",
          name: line.trim(),
          version: "",
          raw: line.trim()
        };
    });
    const risk = openPorts.some((line) => /(3389|445|22|5985|5900)\/tcp/.test(line))
      ? "high"
      : openPorts.length > 4
        ? "medium"
        : "low";
    const id = `scan-${index + 1}`;
    hosts.push({
      id,
      label: first.replace(/\s*\([^)]+\)/, "") || ip,
      ip,
      role: services.length ? services.map((service) => service.name).filter(Boolean).slice(0, 2).join(", ") : "host",
      services,
      risk,
      x: 18 + ((index * 17) % 68),
      y: 24 + ((index * 23) % 52)
    });
    if (index > 0) links.push(["scan-1", id]);
    openPorts.slice(0, 3).forEach((line, portIndex) => {
      findings.push({
        id: `scan-finding-${index + 1}-${portIndex + 1}`,
        host: id,
        severity: risk,
        title: `Open service detected: ${line.trim()}`,
        status: "needs validation",
        technique: "T1046 Network Service Discovery"
      });
    });
  });

  return hosts.length ? { hosts, links, findings } : { ...emptyNetwork };
}

function linesToReconNetwork(stdout, target) {
  const values = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 80);

  const hosts = values.map((value, index) => {
    const clean = value.replace(/^https?:\/\//, "").split(/[\/\s[]/)[0];
    return {
      id: `recon-${index + 1}`,
      label: clean || value,
      ip: clean || target,
      role: value.includes("http") || value.includes("[") ? "web surface" : "recon asset",
      risk: value.match(/(401|403|500|admin|vpn|rdp|ssh|sso)/i) ? "medium" : "low",
      x: 14 + ((index * 19) % 72),
      y: 20 + ((index * 17) % 55)
    };
  });

  const links = hosts.length ? hosts.slice(1).map((host) => [hosts[0].id, host.id]) : [];
  const findings = hosts.map((host, index) => ({
    id: `recon-finding-${index + 1}`,
    host: host.id,
    severity: host.risk,
    title: `Recon asset discovered: ${host.label}`,
    status: "needs enrichment",
    technique: "T1596 Search Open Technical Databases"
  }));

  return hosts.length ? { hosts, links, findings } : { ...emptyNetwork };
}

function serializeReconTools() {
  return Object.values(reconToolProfiles).map(({ buildArgs, parse, ...tool }) => tool);
}

ipcMain.handle("settings:load", async () => readSettings());
ipcMain.handle("settings:save", async (_event, settings) => writeSettings(settings));
ipcMain.handle("attack:knowledge", async () => readAttackKnowledge());
ipcMain.handle("attack:phases", async () => loadAttackPhases());
ipcMain.handle("recon:tools", async () => serializeReconTools());
ipcMain.handle("network:empty", async () => ({ ...emptyNetwork }));
ipcMain.handle("startup:dependencies", async () => startupDependencyReport || checkStartupDependencies());
ipcMain.handle("db:test", async () => {
  const settings = await readSettings();
  try {
    return await withPostgres(settings, async (client) => {
      await ensureEvidenceSchema(client);
      const result = await client.query("select now() as checked_at");
      return { ok: true, checkedAt: result.rows[0].checked_at };
    });
  } catch (error) {
    return { ok: false, message: error.message };
  }
});

ipcMain.handle("api:test", async () => {
  const settings = await readSettings();
  const apiBaseUrl = String(settings.apiBaseUrl || "").trim().replace(/\/$/, "");

  if (!apiBaseUrl) {
    return { ok: false, message: "API base URL is required." };
  }
  if (!settings.apiKey) {
    return { ok: false, message: "API key is required for the endpoint check." };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(`${apiBaseUrl}/models`, {
      method: "GET",
      signal: controller.signal,
      headers: {
        authorization: `Bearer ${settings.apiKey}`,
        ...(settings.organization ? { "OpenAI-Organization": settings.organization } : {})
      }
    });
    const text = await response.text();
    let data = null;

    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        message: data?.error?.message || text || `Endpoint returned HTTP ${response.status}.`
      };
    }

    return {
      ok: true,
      status: response.status,
      models: Array.isArray(data?.data)
        ? data.data
          .map((model) => model.id)
          .filter((id) => typeof id === "string" && id.trim())
          .sort((a, b) => a.localeCompare(b))
        : [],
      modelCount: Array.isArray(data?.data) ? data.data.length : null,
      message: "API endpoint responded successfully."
    };
  } catch (error) {
    return {
      ok: false,
      message: error.name === "AbortError" ? "API endpoint check timed out." : error.message
    };
  } finally {
    clearTimeout(timeout);
  }
});

ipcMain.handle("scan:run", async (_event, payload) => {
  const settings = await readSettings();
  const target = String(payload?.target || "").trim();
  const tool = reconToolProfiles[payload?.toolId || "nmap"] || reconToolProfiles.nmap;
  const port = normalizedPort(payload?.port);

  if (!settings.allowLocalTools) {
    return {
      ok: false,
      message: "Local recon tools are disabled. Enable them in Settings after configuring authorized targets and tool paths."
    };
  }

  if (!targetIsScoped(target, settings.scopedTargets || [])) {
    return {
      ok: false,
      message: "Target is outside the configured authorized scope. Add it in Settings before running tools."
    };
  }

  if (!payload?.approved) {
    const approval = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Run Recon"],
      defaultId: 0,
      cancelId: 0,
      title: "Approve Recon Action",
      message: `Run ${tool.name}?`,
      detail: `Target: ${target}${port ? `\nPort: ${port}` : ""}\nTechnique: ${tool.technique}\n\nThis will execute a local recon command only against configured authorized scope.`
    });

    if (approval.response !== 1) {
      return { ok: false, message: "Recon action cancelled by operator." };
    }
  }

  const command = await resolveToolCommand(tool, settings.toolPaths?.[tool.pathKey] || tool.pathKey);
  const result = await runCommand(command, tool.buildArgs(target, { port }));
  if (!result.ok) {
    return {
      ok: false,
      message: result.errorCode === "ENOENT" ? missingToolMessage(tool, command) : result.stderr || "Scan command failed.",
      stdout: result.stdout
    };
  }

  const network = tool.parse(result.stdout, target);
  const dbResult = await saveReconEvidence(settings, {
    tool,
    target,
    stdout: result.stdout,
    network
  });

  return {
    ok: true,
    mode: tool.id,
    message: dbResult.ok && !dbResult.skipped
      ? `Recon completed and stored in Postgres run ${dbResult.reconRunId}.`
      : dbResult.ok
        ? "Recon completed and mapped to the workspace."
        : `Recon completed, but Postgres storage failed: ${dbResult.message}`,
    stdout: result.stdout,
    network,
    db: dbResult
  };
});

function chatSystemPrompt() {
  return [
    "You are the authorized Crosshair copilot inside a defensive security platform.",
    "Help plan and validate assessments only for systems listed in context.authorization.authorizedTargets.",
    "Treat context.authorization.authorizedTargets as the source of truth for configured scope.",
    "If a requested target is listed there, do not claim it is unauthorized.",
    "Use context.conversationHistory and context.actionIntent to resolve follow-up requests like 'execute it', 'validate that', 'retest it', or 'continue'.",
    "If context.actionIntent has enough tool, phase, target, or finding details, do not ask the user to repeat them.",
    "When a local command should run, propose the exact command and wait for the Crosshair Accept or Deny control instead of claiming it already ran.",
    "If local tool execution is disabled, say the target is authorized but local recon tools must be enabled before Crosshair can run the scan.",
    "Do not provide destructive payloads, credential theft steps, stealth guidance, or real data exfiltration instructions.",
    "Prefer safe validation, detection engineering, remediation, and retest workflows mapped to MITRE ATT&CK."
  ].join(" ");
}

function scopedTargetMatch(target, scopedTargets) {
  if (!target) return false;
  return targetIsScoped(target, scopedTargets || []);
}

function requestedTargets(message) {
  return String(message || "").match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
}

function latestMatch(values, pattern) {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const match = String(values[index] || "").match(pattern);
    if (match) return match[1] || match[0];
  }
  return null;
}

function actionIntent(context, message) {
  const history = Array.isArray(context.conversationHistory) ? context.conversationHistory : [];
  const entries = [...history.map((entry) => entry.content), message];
  const tool = latestMatch(entries, /\b(nmap|naabu|httpx|amass)\b/i);
  const target = latestMatch(entries, /\b((?:\d{1,3}\.){3}\d{1,3})\b/);
  const port = latestPortSelection(entries);
  const phase = latestMatch(entries, /\b(reconnaissance|recon|discovery|validation|validate|privilege escalation|lateral movement|collection|exfiltration|retest|remediation)\b/i);
  const action = latestMatch(entries, /\b(scan|execute|run|validate|verify|retest|enumerate|map|plan|continue)\b/i);
  const finding = context.selectedFinding?.id || latestMatch(entries, /\b(finding-[\w-]+|scan-finding-[\w-]+|recon-finding-[\w-]+)\b/i);

  return {
    tool: tool ? tool.toLowerCase() : null,
    phase: phase ? phase.toLowerCase() : null,
    action: action ? action.toLowerCase() : null,
    target,
    port,
    finding,
    hasRunnableDetails: Boolean(tool && target),
    hasActionContext: Boolean(tool || phase || action || target || port || finding)
  };
}

function chatContext(settings, context, message) {
  const targets = requestedTargets(message);
  const intent = actionIntent(context, message);
  return {
    ...context,
    actionIntent: {
      ...intent,
      targetAuthorized: intent.target ? scopedTargetMatch(intent.target, settings.scopedTargets || []) : false
    },
    reconIntent: {
      tool: intent.tool,
      target: intent.target,
      port: intent.port,
      hasRunnableDetails: intent.hasRunnableDetails,
      targetAuthorized: intent.target ? scopedTargetMatch(intent.target, settings.scopedTargets || []) : false
    },
    authorization: {
      authorizedTargets: settings.scopedTargets || [],
      localToolsEnabled: Boolean(settings.allowLocalTools),
      requestedTargets: targets.map((target) => ({
        target,
        authorized: scopedTargetMatch(target, settings.scopedTargets || [])
      }))
    }
  };
}

function chatMessages(message, context) {
  return [
    { role: "system", content: chatSystemPrompt() },
    { role: "user", content: `Context:\n${JSON.stringify(context, null, 2)}\n\nUser request:\n${message}` }
  ];
}

function localChatResponse() {
  return "API settings are not configured yet. I can still draft a safe assessment plan locally: start with scope confirmation, run discovery scans, map exposed services to ATT&CK techniques, validate findings with operator-approved checks, and retest after remediation.";
}

function sendChatEvent(sender, requestId, type, payload = {}) {
  sender.send("chat:stream:event", { requestId, type, ...payload });
}

async function streamLocalText(sender, requestId, text) {
  for (const chunk of text.match(/.{1,18}(\s|$)/g) || [text]) {
    sendChatEvent(sender, requestId, "chunk", { content: chunk });
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  sendChatEvent(sender, requestId, "done");
}

async function streamOpenAiChat(sender, requestId, settings, message, context) {
  const preparedContext = chatContext(settings, context, message);
  const response = await fetch(`${settings.apiBaseUrl.replace(/\/$/, "")}/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${settings.apiKey}`,
      ...(settings.organization ? { "OpenAI-Organization": settings.organization } : {})
    },
    body: JSON.stringify({
      model: settings.model,
      messages: chatMessages(message, preparedContext),
      temperature: 0.2,
      stream: true
    })
  });

  if (!response.ok) {
    const text = await response.text();
    sendChatEvent(sender, requestId, "error", { message: `LLM request failed: ${response.status} ${text}` });
    return;
  }

  const decoder = new TextDecoder();
  const reader = response.body.getReader();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split(/\r?\n/);
    buffer = lines.pop() || "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("data:")) continue;

      const data = trimmed.slice(5).trim();
      if (data === "[DONE]") {
        sendChatEvent(sender, requestId, "done");
        return;
      }

      try {
        const parsed = JSON.parse(data);
        const content = parsed.choices?.[0]?.delta?.content || "";
        if (content) sendChatEvent(sender, requestId, "chunk", { content });
      } catch {
        continue;
      }
    }
  }

  sendChatEvent(sender, requestId, "done");
}

ipcMain.on("chat:stream:start", async (event, payload) => {
  const requestId = String(payload?.requestId || "");
  const settings = await readSettings();
  const message = String(payload?.message || "").trim();
  const context = payload?.context || {};

  if (!requestId) return;
  if (!message) {
    sendChatEvent(event.sender, requestId, "error", { message: "No message provided." });
    return;
  }

  try {
    if (!settings.apiKey || !settings.apiBaseUrl || !settings.model) {
      await streamLocalText(event.sender, requestId, localChatResponse());
      return;
    }

    await streamOpenAiChat(event.sender, requestId, settings, message, context);
  } catch (error) {
    sendChatEvent(event.sender, requestId, "error", { message: error.message });
  }
});

ipcMain.handle("chat:send", async (_event, payload) => {
  const settings = await readSettings();
  const message = String(payload?.message || "").trim();
  const context = payload?.context || {};
  const preparedContext = chatContext(settings, context, message);

  if (!message) return { ok: false, message: "No message provided." };
  if (!settings.apiKey || !settings.apiBaseUrl || !settings.model) {
    return {
      ok: true,
      message: localChatResponse()
    };
  }

  try {
    const response = await fetch(`${settings.apiBaseUrl.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${settings.apiKey}`,
        ...(settings.organization ? { "OpenAI-Organization": settings.organization } : {})
      },
      body: JSON.stringify({
        model: settings.model,
        messages: chatMessages(message, preparedContext),
        temperature: 0.2
      })
    });

    if (!response.ok) {
      const text = await response.text();
      return { ok: false, message: `LLM request failed: ${response.status} ${text}` };
    }

    const data = await response.json();
    return {
      ok: true,
      message: data.choices?.[0]?.message?.content || "The model returned an empty response."
    };
  } catch (error) {
    return { ok: false, message: error.message };
  }
});

ipcMain.handle("operator:confirm", async (_event, payload) => {
  const result = await dialog.showMessageBox(mainWindow, {
    type: "warning",
    buttons: ["Cancel", "Confirm"],
    defaultId: 0,
    cancelId: 0,
    title: "Operator Approval Required",
    message: payload?.title || "Confirm this assessment action",
    detail: payload?.detail || "Only run actions against systems you are authorized to test."
  });
  return { confirmed: result.response === 1 };
});

app.whenReady().then(async () => {
  const shouldStart = await confirmStartupDependencies();
  if (!shouldStart) {
    app.quit();
    return;
  }
  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
