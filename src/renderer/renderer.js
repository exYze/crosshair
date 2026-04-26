const state = {
  settings: null,
  attackPhases: [],
  attackKnowledge: null,
  reconTools: [],
  network: null,
  selectedFindingId: null,
  expandedHostId: null,
  chatHistory: [],
  pendingActionId: 0
};

const els = {
  chatLog: document.querySelector("#chatLog"),
  chatForm: document.querySelector("#chatForm"),
  chatInput: document.querySelector("#chatInput"),
  chatSubmit: document.querySelector("#chatForm button[type='submit']"),
  settingsButton: document.querySelector("#settingsButton"),
  settingsDialog: document.querySelector("#settingsDialog"),
  settingsForm: document.querySelector("#settingsForm"),
  apiBaseUrl: document.querySelector("#apiBaseUrl"),
  apiKey: document.querySelector("#apiKey"),
  model: document.querySelector("#model"),
  settingsStatus: document.querySelector("#settingsStatus"),
  organization: document.querySelector("#organization"),
  scopedTargets: document.querySelector("#scopedTargets"),
  postgresConnectionString: document.querySelector("#postgresConnectionString"),
  postgresEnabled: document.querySelector("#postgresEnabled"),
  nmapPath: document.querySelector("#nmapPath"),
  amassPath: document.querySelector("#amassPath"),
  naabuPath: document.querySelector("#naabuPath"),
  httpxPath: document.querySelector("#httpxPath"),
  allowLocalTools: document.querySelector("#allowLocalTools"),
  allowCommandAdapters: document.querySelector("#allowCommandAdapters"),
  toolStatus: document.querySelector("#toolStatus"),
  modelStatus: document.querySelector("#modelStatus"),
  runScan: document.querySelector("#runScan"),
  reconTool: document.querySelector("#reconTool"),
  scanTarget: document.querySelector("#scanTarget"),
  networkMap: document.querySelector("#networkMap"),
  attackChain: document.querySelector("#attackChain"),
  toolList: document.querySelector("#toolList"),
  findingsList: document.querySelector("#findingsList"),
  validateFinding: document.querySelector("#validateFinding"),
  retestFinding: document.querySelector("#retestFinding"),
  testApi: document.querySelector("#testApi"),
  testDatabase: document.querySelector("#testDatabase")
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function truncateText(value, maxLength = 58) {
  const text = String(value || "");
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}...` : text;
}

function appendMessage(role, content, card = false) {
  const article = document.createElement("article");
  article.className = `message ${role}`;
  article.innerHTML = `
    ${avatarMarkup(role)}
    <div class="${card ? "analysis-card" : "bubble"}">${content}</div>
  `;
  els.chatLog.append(article);
  els.chatLog.scrollTop = els.chatLog.scrollHeight;
}

function avatarMarkup(role) {
  if (role === "assistant") {
    return `
      <div class="avatar assistant-mark" aria-label="Crosshair assistant">
        <svg class="crosshair-avatar" viewBox="0 0 32 32" aria-hidden="true">
          <circle cx="16" cy="16" r="9"></circle>
          <path d="M16 3v8M16 21v8M3 16h8M21 16h8"></path>
          <circle cx="16" cy="16" r="2"></circle>
        </svg>
      </div>
    `;
  }
  return `<div class="avatar">YOU</div>`;
}

function appendStreamingMessage() {
  const article = document.createElement("article");
  article.className = "message assistant";
  article.innerHTML = `
    ${avatarMarkup("assistant")}
    <div class="bubble streaming-bubble">
      <span class="thinking-dots" aria-label="LLM processing">
        <i></i><i></i><i></i>
      </span>
      <span class="stream-text"></span>
    </div>
  `;
  els.chatLog.append(article);
  els.chatLog.scrollTop = els.chatLog.scrollHeight;
  return {
    text: article.querySelector(".stream-text"),
    dots: article.querySelector(".thinking-dots"),
    bubble: article.querySelector(".streaming-bubble")
  };
}

function setChatBusy(isBusy) {
  els.chatInput.disabled = isBusy;
  els.chatSubmit.disabled = isBusy;
}

function actionEntries(message, assistantText = "") {
  return [
    ...state.chatHistory.map((entry) => entry.content),
    message,
    assistantText
  ];
}

function latestMatch(values, pattern) {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const match = String(values[index] || "").match(pattern);
    if (match) return match[1] || match[0];
  }
  return null;
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

function inferToolAction(message, assistantText = "") {
  const entries = actionEntries(message, assistantText);
  const tool = latestMatch(entries, /\b(nmap|naabu|httpx|amass)\b/i);
  const target = latestMatch(entries, /\b((?:\d{1,3}\.){3}\d{1,3})\b/);
  const port = latestPortSelection(entries);
  const action = latestMatch(entries, /\b(scan|execute|run|enumerate|fingerprint)\b/i);
  const assistantWantsAction = /\b(ready to proceed|proposed command|execute the scan|run the scan|run this command|I can proceed|ready to run)\b/i.test(assistantText);
  const assistantBlockedAction = /\b(disabled|cannot run|can't run|not enabled|must be enabled)\b/i.test(assistantText);

  if (!tool || !target || assistantBlockedAction || (!action && !assistantWantsAction)) return null;

  const reconTool = state.reconTools.find((item) => item.id === tool.toLowerCase());
  if (!reconTool) return null;

  return {
    id: `action-${Date.now()}-${state.pendingActionId += 1}`,
    toolId: reconTool.id,
    toolName: reconTool.name,
    target,
    port,
    technique: reconTool.technique,
    command: commandPreview(reconTool.id, target, port)
  };
}

function commandPreview(toolId, target, port) {
  if (toolId === "nmap" && port === "all") return `nmap -sV -p- ${target}`;
  if (toolId === "nmap" && port) return `nmap -sV -p ${port} ${target}`;
  if (toolId === "nmap") return `nmap -sV --top-ports 100 ${target}`;
  if (toolId === "naabu") return `naabu -host ${target} -top-ports 100`;
  if (toolId === "httpx") return `httpx -u ${target} -title -tech-detect -status-code`;
  if (toolId === "amass") return `amass enum -passive -d ${target}`;
  return `${toolId} ${target}`;
}

function rememberChat(role, content) {
  const cleanContent = String(content || "").trim();
  if (!cleanContent) return;
  state.chatHistory.push({ role, content: cleanContent });
  state.chatHistory = state.chatHistory.slice(-30);
}

function chatContext() {
  return {
    attackPhases: state.attackPhases,
    attackKnowledge: state.attackKnowledge,
    reconTools: state.reconTools,
    network: state.network,
    selectedFinding: selectedFinding(),
    conversationHistory: state.chatHistory
  };
}

function appendActionApproval(action) {
  const article = document.createElement("article");
  article.className = "message assistant";
  article.innerHTML = `
    ${avatarMarkup("assistant")}
    <div class="action-approval" data-action-id="${escapeHtml(action.id)}">
      <div class="card-header">
        <strong>Approve Command</strong>
        <span>${escapeHtml(action.technique)}</span>
      </div>
      <div class="mini-grid">
        <span>Tool</span><strong>${escapeHtml(action.toolName)}</strong>
        <span>Target</span><strong>${escapeHtml(action.target)}</strong>
        <span>Command</span><strong>${escapeHtml(action.command)}</strong>
      </div>
      <div class="approval-actions">
        <button type="button" class="approve-command">Accept</button>
        <button type="button" class="deny-command">Deny</button>
      </div>
      <div class="approval-status"></div>
    </div>
  `;
  els.chatLog.append(article);
  els.chatLog.scrollTop = els.chatLog.scrollHeight;

  const card = article.querySelector(".action-approval");
  const acceptButton = article.querySelector(".approve-command");
  const denyButton = article.querySelector(".deny-command");
  const status = article.querySelector(".approval-status");

  acceptButton.addEventListener("click", () => approveToolAction(action, card, acceptButton, denyButton, status));
  denyButton.addEventListener("click", () => denyToolAction(action, card, acceptButton, denyButton, status));
  return card;
}

async function approveToolAction(action, card, acceptButton, denyButton, status) {
  card.classList.add("decision-accepted");
  acceptButton.disabled = true;
  denyButton.disabled = true;
  acceptButton.setAttribute("aria-pressed", "true");
  denyButton.setAttribute("aria-pressed", "false");
  status.textContent = "Accepted. Running command...";
  rememberChat("user", `Accepted command: ${action.command}`);

  const result = await window.aip.runScan({
    target: action.target,
    toolId: action.toolId,
    port: action.port,
    approved: true
  });

  if (!result.ok) {
    status.textContent = `Command failed: ${result.message}`;
    status.classList.add("error");
    rememberChat("assistant", `Command failed: ${result.message}`);
    appendMessage("assistant", escapeHtml(result.message));
    return;
  }

  drawNetwork(result.network);
  status.textContent = "Command completed.";
  status.classList.add("ok");
  const summary = `Command completed. ${result.network.hosts.length} hosts and ${result.network.findings.length} findings mapped.`;
  rememberChat("assistant", summary);
  appendMessage("assistant", `
    <div class="card-header"><strong>Command Complete</strong><span>${escapeHtml(result.mode || "recon")}</span></div>
    <p>${escapeHtml(result.message)}</p>
    <div class="mini-grid">
      <span>Command</span><strong>${escapeHtml(action.command)}</strong>
      <span>Hosts</span><strong>${result.network.hosts.length}</strong>
      <span>Findings</span><strong>${result.network.findings.length}</strong>
      <span>Storage</span><strong>${escapeHtml(storageStatus(result))}</strong>
    </div>
  `, true);
}

function denyToolAction(action, card, acceptButton, denyButton, status) {
  card.classList.add("decision-denied");
  acceptButton.disabled = true;
  denyButton.disabled = true;
  acceptButton.setAttribute("aria-pressed", "false");
  denyButton.setAttribute("aria-pressed", "true");
  status.textContent = "Denied. Sending decision back to Crosshair...";
  status.classList.add("error");
  const denial = `Operator denied command: ${action.command}. Ask what they want to do instead or suggest a safer alternative.`;
  rememberChat("user", denial);
  sendChatMessage(denial, { displayUser: false });
}

function setSettingsStatus(message, type = "") {
  els.settingsStatus.textContent = message;
  els.settingsStatus.className = `settings-status ${type}`.trim();
}

function modelOptionsFrom(values, selectedModel) {
  const unique = [...new Set(values.filter(Boolean))];
  if (selectedModel && !unique.includes(selectedModel)) {
    unique.unshift(selectedModel);
  }
  if (!unique.length) {
    unique.push("gpt-4.1-mini");
  }
  return unique;
}

function populateModelDropdown(models, selectedModel) {
  const options = modelOptionsFrom(models, selectedModel);
  els.model.innerHTML = options.map((model) => `
    <option value="${escapeHtml(model)}">${escapeHtml(model)}</option>
  `).join("");
  els.model.value = selectedModel && options.includes(selectedModel) ? selectedModel : options[0];
}

function updateStatus() {
  const toolText = state.settings?.allowLocalTools ? "Enabled" : "Disabled";
  const modelText = state.settings?.apiKey ? state.settings.model : "Not configured";
  if (els.toolStatus) els.toolStatus.textContent = toolText;
  if (els.modelStatus) els.modelStatus.textContent = modelText;
}

function fillSettingsForm() {
  const settings = state.settings;
  els.apiBaseUrl.value = settings.apiBaseUrl || "";
  els.apiKey.value = settings.apiKey || "";
  populateModelDropdown([settings.model], settings.model);
  setSettingsStatus("Use Test API to load available models.");
  els.organization.value = settings.organization || "";
  els.scopedTargets.value = (settings.scopedTargets || []).join("\n");
  els.postgresConnectionString.value = settings.postgres?.connectionString || "";
  els.postgresEnabled.checked = Boolean(settings.postgres?.enabled);
  els.nmapPath.value = settings.toolPaths?.nmap || "nmap";
  els.amassPath.value = settings.toolPaths?.amass || "amass";
  els.naabuPath.value = settings.toolPaths?.naabu || "naabu";
  els.httpxPath.value = settings.toolPaths?.httpx || "httpx";
  els.allowLocalTools.checked = Boolean(settings.allowLocalTools);
  els.allowCommandAdapters.checked = Boolean(settings.allowCommandAdapters);
}

function settingsFromForm() {
  return {
    apiBaseUrl: els.apiBaseUrl.value.trim(),
    apiKey: els.apiKey.value.trim(),
    model: els.model.value.trim(),
    organization: els.organization.value.trim(),
    scopedTargets: els.scopedTargets.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    postgres: {
      enabled: els.postgresEnabled.checked,
      connectionString: els.postgresConnectionString.value.trim()
    },
    allowLocalTools: els.allowLocalTools.checked,
    allowCommandAdapters: els.allowCommandAdapters.checked,
    toolPaths: {
      nmap: els.nmapPath.value.trim() || "nmap",
      amass: els.amassPath.value.trim() || "amass",
      naabu: els.naabuPath.value.trim() || "naabu",
      httpx: els.httpxPath.value.trim() || "httpx"
    }
  };
}

function riskClass(risk) {
  return `risk-${String(risk || "low").toLowerCase()}`;
}

function emptyNetwork() {
  return { hosts: [], links: [], findings: [] };
}

function drawNetwork(network) {
  const normalized = {
    hosts: network?.hosts || [],
    links: network?.links || [],
    findings: network?.findings || []
  };
  state.network = normalized;

  if (!normalized.hosts.length) {
    els.networkMap.innerHTML = `
      <text class="empty-map-label" x="500" y="305">No network map yet</text>
      <text class="empty-map-detail" x="500" y="330">Configure settings and run recon against an authorized target.</text>
    `;
    drawFindings([]);
    return;
  }

  const hostById = new Map(normalized.hosts.map((host) => [host.id, host]));
  const links = normalized.links.map(([from, to]) => {
    const a = hostById.get(from);
    const b = hostById.get(to);
    if (!a || !b) return "";
    return `<line class="network-link" x1="${a.x * 10}" y1="${a.y * 6.5}" x2="${b.x * 10}" y2="${b.y * 6.5}"></line>`;
  });

  const nodes = normalized.hosts.map((host) => {
    const x = host.x * 10;
    const y = host.y * 6.5;
    const size = host.risk === "critical" ? 20 : host.risk === "high" ? 17 : 14;
    const serviceText = host.services?.length
      ? host.services.map((service) => service.name).slice(0, 2).join(", ")
      : host.role;
    const detailLines = host.services?.length
      ? host.services.slice(0, 8).map((service) => {
        const version = service.version ? ` ${service.version}` : "";
        return `${service.port}/${service.protocol} ${service.name}${version}`;
      })
      : [];
    const detailHeight = detailLines.length ? 34 + (detailLines.length * 18) + (host.services.length > detailLines.length ? 18 : 0) : 0;
    const detailWidth = 390;
    const detailX = Math.min(x + size + 6, 1000 - detailWidth - 16);
    const detailY = Math.min(y + 28, 650 - detailHeight - 16);
    const detailBox = state.expandedHostId === host.id && detailLines.length
      ? `
        <g class="host-details" transform="translate(${detailX} ${detailY})">
          <rect width="${detailWidth}" height="${detailHeight}" rx="5"></rect>
          <text class="host-detail-title" x="12" y="20">Services on ${escapeHtml(host.ip || host.label)}</text>
          ${detailLines.map((line, index) => `
            <text class="host-detail-line" x="12" y="${44 + (index * 18)}">${escapeHtml(truncateText(line))}</text>
          `).join("")}
          ${host.services.length > detailLines.length
            ? `<text class="host-detail-more" x="12" y="${44 + (detailLines.length * 18)}">+ ${host.services.length - detailLines.length} more services</text>`
            : ""}
        </g>
      `
      : "";
    return `
      <g class="host-group ${state.expandedHostId === host.id ? "expanded" : ""}" data-host="${escapeHtml(host.id)}" tabindex="0" role="button" aria-label="Show services for ${escapeHtml(host.label)}">
        <circle class="host-node ${riskClass(host.risk)}" cx="${x}" cy="${y}" r="${size}"></circle>
        <text class="host-label" x="${x + size + 7}" y="${y - 2}">${escapeHtml(host.label)}</text>
        <text class="host-ip" x="${x + size + 7}" y="${y + 15}">${escapeHtml(host.ip)} | ${escapeHtml(serviceText)}</text>
        ${detailBox}
      </g>
    `;
  });

  els.networkMap.innerHTML = `
    <defs>
      <filter id="glow" x="-40%" y="-40%" width="180%" height="180%">
        <feGaussianBlur stdDeviation="3" result="blur"></feGaussianBlur>
        <feMerge>
          <feMergeNode in="blur"></feMergeNode>
          <feMergeNode in="SourceGraphic"></feMergeNode>
        </feMerge>
      </filter>
    </defs>
    ${links.join("")}
    ${nodes.join("")}
  `;
  drawFindings(normalized.findings);
}

function toggleHostDetails(hostId) {
  if (!hostId) return;
  state.expandedHostId = state.expandedHostId === hostId ? null : hostId;
  drawNetwork(state.network);
}

function storageStatus(result) {
  if (result.db?.reconRunId) return `Postgres run ${result.db.reconRunId}`;
  if (result.db && result.db.ok === false) return "Postgres error";
  return "Workspace only";
}

function drawAttackChain() {
  els.attackChain.innerHTML = state.attackPhases.map((phase, index) => `
    <div class="attack-step ${index < 2 ? "active" : ""}">
      <strong>${escapeHtml(phase.name)} <span>${escapeHtml(phase.tactic)}</span></strong>
      <span>${escapeHtml(phase.techniques.join(" | "))}</span>
    </div>
  `).join("");
}

function drawReconTools() {
  els.reconTool.innerHTML = state.reconTools.map((tool) => `
    <option value="${escapeHtml(tool.id)}">${escapeHtml(tool.name)}</option>
  `).join("");

  els.toolList.innerHTML = state.reconTools.map((tool) => `
    <div class="tool-item">
      <strong>${escapeHtml(tool.name)}</strong>
      <span>${escapeHtml(tool.technique)} | ${escapeHtml(tool.description)}</span>
    </div>
  `).join("");
}

function appendStartupMessage() {
  appendMessage("assistant", `
    <div class="card-header">
      <strong>Workspace Ready</strong>
      <span>ATT&CK offline KB</span>
    </div>
    <p>Configure authorized targets, tool paths, Postgres, and LLM settings before running recon.</p>
    <div class="mini-grid">
      <span>Mode</span><strong>Controlled validation</strong>
      <span>Local tools</span><strong>${escapeHtml(state.settings?.allowLocalTools ? "Enabled" : "Disabled")}</strong>
      <span>LLM</span><strong>${escapeHtml(state.settings?.apiKey ? state.settings.model : "Not configured")}</strong>
      <span>Storage</span><strong>${escapeHtml(state.settings?.postgres?.enabled ? "Postgres enabled" : "Postgres disabled")}</strong>
    </div>
  `, true);
}

function appendDependencyMessage(report) {
  if (!report?.results?.length) return;

  const missing = report.results.filter((result) => !result.ok);
  if (!missing.length) return;

  appendMessage("assistant", `
    <div class="card-header">
      <strong>Startup Dependency Check</strong>
      <span>${missing.length} attention needed</span>
    </div>
    <p>Crosshair checked every configured dependency before opening. Install missing tools or update their paths in Settings.</p>
    <div class="mini-grid">
      ${report.results.map((result) => `
        <span>${escapeHtml(result.name)}</span>
        <strong>${escapeHtml(result.ok ? "Found" : result.message)}</strong>
      `).join("")}
    </div>
  `, true);
}

function drawFindings(findings) {
  if (!findings.length) {
    els.findingsList.innerHTML = `<div class="finding-item"><span>No findings yet. Run recon against an authorized target.</span></div>`;
    return;
  }

  els.findingsList.innerHTML = findings.map((finding) => `
    <div class="finding-item ${finding.id === state.selectedFindingId ? "selected" : ""}" data-finding-id="${escapeHtml(finding.id)}">
      <em class="severity ${riskClass(finding.severity)}">${escapeHtml(finding.severity)}</em>
      <strong>${escapeHtml(finding.title)}</strong>
      <span>${escapeHtml(finding.technique)} | ${escapeHtml(finding.status)}</span>
    </div>
  `).join("");
}

function selectedFinding() {
  return state.network?.findings?.find((finding) => finding.id === state.selectedFindingId) || state.network?.findings?.[0] || null;
}

async function createValidation(kind) {
  const finding = selectedFinding();
  if (!finding) {
    appendMessage("assistant", "Run discovery or select a finding first.");
    return;
  }

  const confirmed = await window.aip.confirmAction({
    title: kind === "retest" ? "Create remediation retest?" : "Plan safe validation?",
    detail: `${finding.title}\n\nThis creates an operator-reviewed plan and does not run exploit or exfiltration actions automatically.`
  });
  if (!confirmed.confirmed) return;

  const phase = kind === "retest" ? "Remediation Retest" : "Controlled Validation";
  appendMessage("assistant", `
    <div class="card-header"><strong>${phase}</strong><span>${escapeHtml(finding.severity)}</span></div>
    <p>${escapeHtml(finding.title)}</p>
    <div class="mini-grid">
      <span>Technique</span><strong>${escapeHtml(finding.technique)}</strong>
      <span>Evidence</span><strong>Capture command output, logs, and screenshots</strong>
      <span>Guardrail</span><strong>Operator approval and configured scope required</strong>
    </div>
  `, true);
}

async function runDiscovery() {
  const tool = state.reconTools.find((item) => item.id === els.reconTool.value);
  if (!els.scanTarget.value.trim()) {
    appendMessage("assistant", "Enter an authorized target before running recon.");
    return;
  }

  appendMessage("user", `Run ${escapeHtml(tool?.name || "recon")} for ${escapeHtml(els.scanTarget.value)}`);
  const result = await window.aip.runScan({ target: els.scanTarget.value, toolId: els.reconTool.value });
  if (!result.ok) {
    appendMessage("assistant", escapeHtml(result.message));
    return;
  }
  drawNetwork(result.network);
  appendMessage("assistant", `
    <div class="card-header"><strong>Recon Complete</strong><span>${escapeHtml(result.mode || "recon")}</span></div>
    <p>${escapeHtml(result.message)}</p>
    <div class="mini-grid">
      <span>Hosts</span><strong>${result.network.hosts.length}</strong>
      <span>Findings</span><strong>${result.network.findings.length}</strong>
      <span>Storage</span><strong>${escapeHtml(storageStatus(result))}</strong>
      <span>Next</span><strong>Review ATT&CK mapping and plan validation</strong>
    </div>
  `, true);
}

els.settingsButton.addEventListener("click", () => {
  fillSettingsForm();
  els.settingsDialog.showModal();
});

els.settingsForm.addEventListener("submit", async (event) => {
  if (event.submitter?.value === "test-api") {
    event.preventDefault();
    els.testApi.disabled = true;
    setSettingsStatus("Testing API endpoint...");
    state.settings = await window.aip.saveSettings(settingsFromForm());
    updateStatus();
    const result = await window.aip.testApi();
    els.testApi.disabled = false;
    if (result.ok) {
      populateModelDropdown(result.models || [], state.settings.model);
      state.settings = await window.aip.saveSettings(settingsFromForm());
      updateStatus();
      setSettingsStatus(
        result.modelCount === null
          ? "API connection OK. Endpoint responded, but no model list was returned."
          : `API connection OK. Loaded ${result.modelCount} models into the dropdown.`,
        "ok"
      );
    } else {
      setSettingsStatus(`API connection failed: ${result.message}`, "error");
    }
    appendMessage("assistant", result.ok
      ? `API connection OK. ${result.modelCount === null ? "Endpoint responded successfully." : `${escapeHtml(result.modelCount)} models loaded into Settings.`}`
      : `API connection failed: ${escapeHtml(result.message)}`);
    return;
  }

  if (event.submitter?.value === "test-db") {
    event.preventDefault();
    els.testDatabase.disabled = true;
    setSettingsStatus("Testing Postgres connection...");
    state.settings = await window.aip.saveSettings(settingsFromForm());
    updateStatus();
    const result = await window.aip.testDatabase();
    els.testDatabase.disabled = false;
    setSettingsStatus(
      result.ok ? `Postgres connection OK. Checked at ${result.checkedAt}.` : `Postgres connection failed: ${result.message}`,
      result.ok ? "ok" : "error"
    );
    appendMessage("assistant", result.ok
      ? `Postgres connection OK. Schema is ready. Checked at ${escapeHtml(result.checkedAt)}.`
      : `Postgres connection failed: ${escapeHtml(result.message)}`);
    return;
  }

  if (event.submitter?.value !== "default") return;
  event.preventDefault();
  state.settings = await window.aip.saveSettings(settingsFromForm());
  updateStatus();
  els.settingsDialog.close();
  appendMessage("assistant", "Settings saved. Scope and model configuration are updated.");
});

function sendChatMessage(message, options = {}) {
  const displayUser = options.displayUser !== false;
  if (!message) return;
  if (displayUser) appendMessage("user", escapeHtml(message));
  rememberChat("user", message);
  setChatBusy(true);
  const requestId = `chat-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const assistant = appendStreamingMessage();
  let fullText = "";
  let stopListening = null;

  stopListening = window.aip.streamChat({
    requestId,
    message,
    context: chatContext()
  }, (streamEvent) => {
    if (streamEvent.type === "chunk") {
      if (assistant.dots) assistant.dots.remove();
      fullText += streamEvent.content || "";
      assistant.text.textContent = fullText;
      els.chatLog.scrollTop = els.chatLog.scrollHeight;
      return;
    }

    if (streamEvent.type === "error") {
      if (assistant.dots) assistant.dots.remove();
      assistant.bubble.classList.add("stream-error");
      assistant.text.textContent = streamEvent.message || "LLM request failed.";
      rememberChat("assistant", assistant.text.textContent);
      setChatBusy(false);
      if (stopListening) stopListening();
      return;
    }

    if (streamEvent.type === "done") {
      if (assistant.dots) assistant.dots.remove();
      if (!fullText.trim()) assistant.text.textContent = "No response returned.";
      rememberChat("assistant", fullText || assistant.text.textContent);
      const action = inferToolAction(message, fullText || assistant.text.textContent);
      if (action) appendActionApproval(action);
      setChatBusy(false);
      if (stopListening) stopListening();
    }
  });
}

els.chatForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = els.chatInput.value.trim();
  if (!message) return;
  els.chatInput.value = "";
  sendChatMessage(message);
});

els.runScan.addEventListener("click", runDiscovery);

els.networkMap.addEventListener("click", (event) => {
  const item = event.target.closest("[data-host]");
  if (!item) return;
  toggleHostDetails(item.dataset.host);
});

els.networkMap.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const item = event.target.closest("[data-host]");
  if (!item) return;
  event.preventDefault();
  toggleHostDetails(item.dataset.host);
});

els.findingsList.addEventListener("click", (event) => {
  const item = event.target.closest("[data-finding-id]");
  if (!item) return;
  state.selectedFindingId = item.dataset.findingId;
  drawFindings(state.network?.findings || []);
});

els.validateFinding.addEventListener("click", () => createValidation("validation"));
els.retestFinding.addEventListener("click", () => createValidation("retest"));

async function init() {
  state.settings = await window.aip.loadSettings();
  state.attackKnowledge = await window.aip.loadAttackKnowledge();
  state.attackPhases = await window.aip.loadAttackPhases();
  state.reconTools = await window.aip.loadReconTools();
  const network = await window.aip.loadEmptyNetwork();
  drawAttackChain();
  drawReconTools();
  drawNetwork(network);
  updateStatus();
  appendStartupMessage();
  appendDependencyMessage(await window.aip.loadStartupDependencies());
}

init();
