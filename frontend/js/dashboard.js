/**
 * Dashboard rendering + interactions (see docs/DESIGN_SPEC.md, Phase 6).
 *
 * Responsible for:
 * - Rendering the {vehicle, environment, telemetry, metrics} snapshot,
 *   whether it comes from the initial REST fetch or a WS broadcast.
 * - The X-SDK-Token field (kept in sessionStorage only — never hardcoded
 *   in source, never persisted beyond the browser tab's lifetime).
 * - The chat panel against POST /api/secure/chat. Chat history is purely
 *   cosmetic client-side state (never re-sent to the server as context,
 *   per the stateless-LLM design decision) and only ever displays the
 *   SDK's own deterministic `verdict`/`message`/`error_code` — never an
 *   LLM `reasoning` field (which `ActionResult` does not even expose).
 * - The operator Scenario Control Panel against POST /api/scenario/set.
 */

const TOKEN_STORAGE_KEY = "sdk_token";

const chatHistory = [];

function getToken() {
  return sessionStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

function setToken(value) {
  sessionStorage.setItem(TOKEN_STORAGE_KEY, value);
}

function boolLabel(value, onLabel, offLabel) {
  return value ? onLabel : offLabel;
}

function fmtPercent(value) {
  return typeof value === "number" ? `${value.toFixed(1)}%` : "—";
}

function fmtTemp(value) {
  return typeof value === "number" ? `${value}°C` : "—";
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function renderWsStatus(connected) {
  const el = document.getElementById("ws-status");
  if (!el) return;
  if (connected) {
    el.textContent = "Connected";
    el.className = "px-2 py-1 rounded bg-emerald-900 text-emerald-200";
  } else {
    el.textContent = "Disconnected";
    el.className = "px-2 py-1 rounded bg-red-900 text-red-200";
  }
}

function renderState(state) {
  const { vehicle, environment, telemetry, metrics } = state;

  // Climate
  setText("climate-power", boolLabel(vehicle.climate.power, "On", "Off"));
  setText("climate-temp", `${vehicle.climate.target_temp_c}°C`);
  setText("climate-fan", String(vehicle.climate.fan_speed));

  // Windows
  for (const w of ["front_left", "front_right", "rear_left", "rear_right"]) {
    setText(`window-${w}`, `${vehicle.windows[w]}%`);
  }

  // Lights
  setText("light-headlights", boolLabel(vehicle.lights.headlights, "On", "Off"));
  setText("light-interior", boolLabel(vehicle.lights.interior, "On", "Off"));
  setText("light-hazard", boolLabel(vehicle.lights.hazard, "On", "Off"));

  // Doors
  setText("door-driver", boolLabel(vehicle.doors.driver_locked, "Locked", "Unlocked"));
  setText("door-passenger", boolLabel(vehicle.doors.passenger_locked, "Locked", "Unlocked"));
  setText("door-rear_left", boolLabel(vehicle.doors.rear_left_locked, "Locked", "Unlocked"));
  setText("door-rear_right", boolLabel(vehicle.doors.rear_right_locked, "Locked", "Unlocked"));

  // Environment (speed + outside temp)
  setText("speed-value", `${environment.vehicle_speed_kmh} km/h`);
  const speedBar = document.getElementById("speed-bar");
  if (speedBar) speedBar.style.width = `${Math.min(100, (environment.vehicle_speed_kmh / 220) * 100)}%`;
  setText("outside-temp", fmtTemp(environment.outside_temp_c));

  // Real telemetry
  setText("cpu-percent", fmtPercent(telemetry.cpu_percent));
  setText("ram-percent", fmtPercent(telemetry.ram_percent));
  setText("cpu-temp", telemetry.cpu_temp_c !== null ? fmtTemp(telemetry.cpu_temp_c) : "N/A");
  setText("telemetry-timestamp", telemetry.timestamp || "—");

  // Metrics (both modes, side by side for comparison — Phase 7)
  setText("metrics-secure-allowed", String(metrics.secure.allowed));
  setText("metrics-secure-blocked", String(metrics.secure.blocked));
  setText("metrics-vulnerable-allowed", String(metrics.vulnerable.allowed));
  setText("metrics-vulnerable-blocked", String(metrics.vulnerable.blocked));
}

function renderChatHistory() {
  const container = document.getElementById("chat-history");
  if (!container) return;

  container.innerHTML = "";
  for (const entry of chatHistory) {
    const isAllowed = entry.verdict === "ALLOWED";
    const wrapper = document.createElement("div");
    wrapper.className = `rounded p-2 ${isAllowed ? "bg-emerald-900/40" : "bg-red-900/40"}`;

    const promptEl = document.createElement("div");
    promptEl.className = "text-slate-300 text-xs mb-1";
    const modeTag = entry.mode === "vulnerable" ? "[VULNERABLE] " : "";
    promptEl.textContent = `${modeTag}» ${entry.prompt}`;

    const resultEl = document.createElement("div");
    resultEl.className = `font-mono text-xs ${isAllowed ? "text-emerald-300" : "text-red-300"}`;
    const codePart = entry.error_code ? ` [${entry.error_code}]` : "";
    resultEl.textContent = `${entry.verdict}${codePart}: ${entry.message}`;

    wrapper.appendChild(promptEl);
    wrapper.appendChild(resultEl);
    container.appendChild(wrapper);
  }
  container.scrollTop = container.scrollHeight;
}

async function fetchInitialState() {
  try {
    const res = await fetch("/api/state");
    if (res.ok) {
      renderState(await res.json());
    }
  } catch (err) {
    console.error("dashboard: failed to fetch initial state", err);
  }
}

async function handleReset() {
  try {
    const res = await fetch("/api/reset", { method: "POST" });
    if (res.ok) {
      renderState(await res.json());
    }
  } catch (err) {
    console.error("dashboard: failed to reset state", err);
  }
}

async function handleScenarioSubmit(event) {
  event.preventDefault();
  const statusEl = document.getElementById("scenario-status");
  const speedInput = document.getElementById("scenario-speed");
  const tempInput = document.getElementById("scenario-temp");

  const body = {};
  if (speedInput.value !== "") body.vehicle_speed_kmh = Number(speedInput.value);
  if (tempInput.value !== "") body.outside_temp_c = Number(tempInput.value);

  try {
    const res = await fetch("/api/scenario/set", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-SDK-Token": getToken(),
      },
      body: JSON.stringify(body),
    });

    if (res.status === 401) {
      statusEl.textContent = "Token missing or invalid.";
      statusEl.className = "text-xs text-red-400";
      return;
    }

    if (res.ok) {
      renderState(await res.json());
      statusEl.textContent = "Scenario applied.";
      statusEl.className = "text-xs text-emerald-400";
    } else {
      statusEl.textContent = `Unexpected error (HTTP ${res.status}).`;
      statusEl.className = "text-xs text-red-400";
    }
  } catch (err) {
    console.error("dashboard: failed to set scenario", err);
    statusEl.textContent = "Network error.";
    statusEl.className = "text-xs text-red-400";
  }
}

function isVulnerableMode() {
  const toggle = document.getElementById("vulnerable-mode-toggle");
  return !!(toggle && toggle.checked);
}

async function handleChatSubmit(event) {
  event.preventDefault();
  const input = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send-btn");
  const pendingEl = document.getElementById("chat-pending");

  const prompt = input.value.trim();
  if (!prompt) return;

  const vulnerable = isVulnerableMode();
  const endpoint = vulnerable ? "/api/vulnerable/chat" : "/api/secure/chat";
  // The vulnerable endpoint ignores X-SDK-Token entirely; the toggle omits
  // it here too, to simulate a caller with no credentials at all — never
  // just an empty string, which would still be "sending" the header.
  const headers = { "Content-Type": "application/json" };
  if (!vulnerable) headers["X-SDK-Token"] = getToken();

  sendBtn.disabled = true;
  pendingEl.classList.remove("hidden");

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({ prompt }),
    });

    const result = await res.json();
    chatHistory.push({
      prompt,
      mode: vulnerable ? "vulnerable" : "secure",
      verdict: result.verdict,
      message: result.message,
      error_code: result.error_code,
    });
    renderChatHistory();
    input.value = "";

    // If the Admin/Debug tab is visible, refresh its history so the trace
    // of this very request shows up immediately. Both pipelines now produce
    // traces (tagged entry.pipeline), so this applies to both modes.
    const debugSection = document.getElementById("debug-section");
    if (debugSection && !debugSection.classList.contains("hidden")) {
      fetchDebugTraces();
    }
  } catch (err) {
    console.error("dashboard: failed to send chat prompt", err);
    chatHistory.push({
      prompt,
      mode: vulnerable ? "vulnerable" : "secure",
      verdict: "BLOCKED",
      message: "Network error contacting the server.",
      error_code: "INTERNAL_ERROR",
    });
    renderChatHistory();
  } finally {
    sendBtn.disabled = false;
    pendingEl.classList.add("hidden");
  }
}

function initVulnerableModeToggle() {
  const toggle = document.getElementById("vulnerable-mode-toggle");
  const title = document.getElementById("chat-panel-title");
  const warning = document.getElementById("vulnerable-mode-warning");
  const panel = document.getElementById("chat-panel");
  if (!toggle || !title || !warning || !panel) return;

  toggle.addEventListener("change", () => {
    const vulnerable = toggle.checked;
    title.textContent = vulnerable ? "Chat (vulnerable pipeline)" : "Chat (secure pipeline)";
    warning.classList.toggle("hidden", !vulnerable);
    panel.classList.toggle("border", vulnerable);
    panel.classList.toggle("border-red-700", vulnerable);
  });
}

function initTokenField() {
  const tokenInput = document.getElementById("token-input");
  const saveBtn = document.getElementById("token-save-btn");

  tokenInput.value = getToken();

  saveBtn.addEventListener("click", () => {
    setToken(tokenInput.value.trim());
  });
}

/**
 * Admin/Debug tab (developer tool, see docs/DESIGN_SPEC.md). Hidden unless
 * the server confirms SDK_DEBUG_MODE is on (GET /api/debug/status) — no
 * trace content is ever fetched or rendered otherwise.
 */
function debugBlock(label, content) {
  const wrap = document.createElement("div");
  const labelEl = document.createElement("div");
  labelEl.className = "text-slate-400";
  labelEl.textContent = label;
  const pre = document.createElement("pre");
  pre.className = "bg-slate-800 rounded p-2 overflow-x-auto whitespace-pre-wrap break-words";
  pre.textContent = content;
  wrap.appendChild(labelEl);
  wrap.appendChild(pre);
  return wrap;
}

function renderDebugTraceEntry(entry) {
  const stages = entry.stages || [];
  const blockedStage = stages.find((s) => s.status === "blocked");
  const outcomeLabel = blockedStage ? `BLOCKED (${blockedStage.name})` : "ALLOWED";
  const outcomeClass = blockedStage ? "text-red-300" : "text-emerald-300";
  const totalMs = typeof entry.sdk_total_duration_ms === "number"
    ? `${entry.sdk_total_duration_ms.toFixed(0)} ms`
    : "—";
  const isVulnerable = entry.pipeline === "vulnerable";
  const pipelineLabel = isVulnerable ? "VULNERABLE" : "SECURE";
  const pipelineClass = isVulnerable ? "text-red-400" : "text-sky-300";

  const details = document.createElement("details");
  details.className = "bg-slate-700 rounded p-2";

  const summary = document.createElement("summary");
  summary.className = "cursor-pointer font-mono text-xs flex justify-between gap-2";
  summary.innerHTML =
    `<span>[<span class="${pipelineClass}">${pipelineLabel}</span>] ${entry.timestamp || "—"} · trace ${(entry.trace_id || "").slice(0, 8)}</span>` +
    `<span class="${outcomeClass}">${outcomeLabel} · ${totalMs}</span>`;

  const body = document.createElement("div");
  body.className = "mt-2 space-y-2 text-xs";

  const stagesList = document.createElement("ul");
  stagesList.className = "space-y-0.5";
  for (const stage of stages) {
    const li = document.createElement("li");
    const color =
      stage.status === "blocked" ? "text-red-300" :
      stage.status === "skipped" ? "text-slate-500" : "text-emerald-300";
    li.className = `font-mono ${color}`;
    const durationPart = typeof stage.duration_ms === "number" ? ` (${stage.duration_ms.toFixed(1)} ms)` : "";
    const detailPart = stage.detail ? ` — ${stage.detail}` : "";
    li.textContent = `${stage.name}: ${stage.status}${durationPart}${detailPart}`;
    stagesList.appendChild(li);
  }
  body.appendChild(stagesList);

  if (entry.final_prompt) {
    body.appendChild(debugBlock("Final prompt sent to Ollama", entry.final_prompt));
  }
  if (entry.raw_llm_output) {
    body.appendChild(debugBlock("Raw LLM output", entry.raw_llm_output));
  }
  if (entry.parsed_llm_action) {
    body.appendChild(debugBlock("Parsed action", JSON.stringify(entry.parsed_llm_action, null, 2)));
  }
  if (entry.ollama_metrics) {
    body.appendChild(debugBlock("Ollama metrics (ns)", JSON.stringify(entry.ollama_metrics, null, 2)));
  }

  const resources = document.createElement("div");
  resources.className = "text-slate-400";
  resources.textContent =
    `CPU: ${entry.cpu_percent_start ?? "—"}% → ${entry.cpu_percent_end ?? "—"}% · ` +
    `RAM: ${entry.ram_percent_start ?? "—"}% → ${entry.ram_percent_end ?? "—"}%`;
  body.appendChild(resources);

  details.appendChild(summary);
  details.appendChild(body);
  return details;
}

async function fetchDebugTraces() {
  const container = document.getElementById("debug-traces-list");
  if (!container) return;

  try {
    const res = await fetch("/api/debug/traces?limit=20", {
      headers: { "X-SDK-Token": getToken() },
    });
    if (!res.ok) {
      container.innerHTML = `<p class="text-red-400">Could not load history (HTTP ${res.status}).</p>`;
      return;
    }
    const data = await res.json();
    container.innerHTML = "";
    for (const entry of data.traces) {
      container.appendChild(renderDebugTraceEntry(entry));
    }
  } catch (err) {
    console.error("dashboard: failed to fetch debug traces", err);
  }
}

async function clearDebugTraces() {
  if (!confirm("Clear the entire debug history? This action cannot be undone.")) {
    return;
  }
  try {
    const res = await fetch("/api/debug/traces", {
      method: "DELETE",
      headers: { "X-SDK-Token": getToken() },
    });
    if (!res.ok) {
      alert(`Could not clear history (HTTP ${res.status}).`);
      return;
    }
    fetchDebugTraces();
  } catch (err) {
    console.error("dashboard: failed to clear debug traces", err);
  }
}

async function initDebugSection() {
  try {
    const res = await fetch("/api/debug/status");
    if (!res.ok) return;
    const { debug_mode } = await res.json();
    if (!debug_mode) return;

    document.getElementById("debug-section").classList.remove("hidden");
    document.getElementById("debug-refresh-btn").addEventListener("click", fetchDebugTraces);
    document.getElementById("debug-clear-btn").addEventListener("click", clearDebugTraces);
    fetchDebugTraces();
  } catch (err) {
    console.error("dashboard: failed to check debug status", err);
  }
}

/**
 * Audit modal (Phase 8) — read-only view of the tamper-evident
 * `audit.log`, a production security feature (unlike the Admin/Debug
 * section above), so it is always reachable from the header, never gated
 * by SDK_DEBUG_MODE. Both endpoints require X-SDK-Token.
 */
function renderAuditEntry(entry) {
  const verdictClass = entry.verdict === "BLOCKED" ? "text-red-300" : "text-emerald-300";
  const modeClass = entry.mode === "vulnerable" ? "text-red-400" : "text-sky-300";

  const row = document.createElement("div");
  row.className = "bg-slate-700 rounded p-2 font-mono text-xs space-y-1";

  const line1 = document.createElement("div");
  line1.className = "flex justify-between gap-2";
  line1.innerHTML =
    `<span>#${entry.seq ?? "—"} · ${entry.timestamp || "—"} · [<span class="${modeClass}">${entry.mode || "—"}</span>]</span>` +
    `<span class="${verdictClass}">${entry.verdict || "—"}</span>`;

  const line2 = document.createElement("div");
  line2.className = "text-slate-400";
  line2.textContent =
    `action: ${entry.action || "—"} · error_code: ${entry.error_code || "—"} · trace ${(entry.trace_id || "").slice(0, 8)}`;

  const line3 = document.createElement("div");
  line3.className = "text-slate-500 break-all";
  line3.textContent =
    `hash: ${(entry.entry_hash || "").slice(0, 16)}… ← prev: ${(entry.prev_hash || "").slice(0, 16)}…`;

  row.appendChild(line1);
  row.appendChild(line2);
  row.appendChild(line3);
  return row;
}

async function fetchAuditEntries() {
  const container = document.getElementById("audit-entries-list");
  if (!container) return;

  try {
    const res = await fetch("/api/audit/entries?limit=20", {
      headers: { "X-SDK-Token": getToken() },
    });
    if (!res.ok) {
      container.innerHTML = `<p class="text-red-400">Could not load audit log (HTTP ${res.status}).</p>`;
      return;
    }
    const data = await res.json();
    container.innerHTML = "";
    for (const entry of data.entries) {
      container.appendChild(renderAuditEntry(entry));
    }
  } catch (err) {
    console.error("dashboard: failed to fetch audit entries", err);
  }
}

async function fetchVerifyChain() {
  const statusEl = document.getElementById("audit-verify-status");
  if (!statusEl) return;

  statusEl.textContent = "Verifying…";
  statusEl.className = "font-mono text-xs text-slate-400";
  try {
    const res = await fetch("/api/audit/verify", {
      headers: { "X-SDK-Token": getToken() },
    });
    if (!res.ok) {
      statusEl.textContent = `Error (HTTP ${res.status})`;
      statusEl.className = "font-mono text-xs text-red-400";
      return;
    }
    const { valid } = await res.json();
    statusEl.textContent = valid ? "Chain OK" : "Chain BROKEN";
    statusEl.className = `font-mono text-xs ${valid ? "text-emerald-300" : "text-red-400"}`;
  } catch (err) {
    console.error("dashboard: failed to verify audit chain", err);
    statusEl.textContent = "Network error";
    statusEl.className = "font-mono text-xs text-red-400";
  }
}

function initAuditModal() {
  const modal = document.getElementById("audit-modal");
  const openBtn = document.getElementById("audit-open-btn");
  const closeBtn = document.getElementById("audit-close-btn");
  const refreshBtn = document.getElementById("audit-refresh-btn");
  const verifyBtn = document.getElementById("audit-verify-btn");
  if (!modal || !openBtn || !closeBtn || !refreshBtn || !verifyBtn) return;

  openBtn.addEventListener("click", () => {
    modal.classList.remove("hidden");
    document.getElementById("audit-verify-status").textContent = "";
    fetchAuditEntries();
  });
  closeBtn.addEventListener("click", () => modal.classList.add("hidden"));
  modal.addEventListener("click", (event) => {
    if (event.target === modal) modal.classList.add("hidden");
  });
  refreshBtn.addEventListener("click", fetchAuditEntries);
  verifyBtn.addEventListener("click", fetchVerifyChain);
}

document.addEventListener("DOMContentLoaded", () => {
  initTokenField();

  document.getElementById("reset-btn").addEventListener("click", handleReset);
  document.getElementById("scenario-form").addEventListener("submit", handleScenarioSubmit);
  document.getElementById("chat-form").addEventListener("submit", handleChatSubmit);
  initVulnerableModeToggle();
  initAuditModal();

  fetchInitialState();
  connectTelemetry(renderState, renderWsStatus);
  initDebugSection();
});
