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
    el.textContent = "Conectado";
    el.className = "px-2 py-1 rounded bg-emerald-900 text-emerald-200";
  } else {
    el.textContent = "Desconectado";
    el.className = "px-2 py-1 rounded bg-red-900 text-red-200";
  }
}

function renderState(state) {
  const { vehicle, environment, telemetry, metrics } = state;

  // Climate
  setText("climate-power", boolLabel(vehicle.climate.power, "Encendido", "Apagado"));
  setText("climate-temp", `${vehicle.climate.target_temp_c}°C`);
  setText("climate-fan", String(vehicle.climate.fan_speed));

  // Windows
  for (const w of ["front_left", "front_right", "rear_left", "rear_right"]) {
    setText(`window-${w}`, `${vehicle.windows[w]}%`);
  }

  // Lights
  setText("light-headlights", boolLabel(vehicle.lights.headlights, "Encendidos", "Apagados"));
  setText("light-interior", boolLabel(vehicle.lights.interior, "Encendida", "Apagada"));
  setText("light-hazard", boolLabel(vehicle.lights.hazard, "Activada", "Desactivada"));

  // Doors
  setText("door-driver", boolLabel(vehicle.doors.driver_locked, "Bloqueado", "Abierto"));
  setText("door-passenger", boolLabel(vehicle.doors.passenger_locked, "Bloqueado", "Abierto"));
  setText("door-rear_left", boolLabel(vehicle.doors.rear_left_locked, "Bloqueado", "Abierto"));
  setText("door-rear_right", boolLabel(vehicle.doors.rear_right_locked, "Bloqueado", "Abierto"));

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

  // Metrics (secure mode only for now — vulnerable mode arrives in Phase 7)
  setText("metrics-secure-allowed", String(metrics.secure.allowed));
  setText("metrics-secure-blocked", String(metrics.secure.blocked));
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
    promptEl.textContent = `» ${entry.prompt}`;

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
      statusEl.textContent = "Token ausente o inválido.";
      statusEl.className = "text-xs text-red-400";
      return;
    }

    if (res.ok) {
      renderState(await res.json());
      statusEl.textContent = "Escenario aplicado.";
      statusEl.className = "text-xs text-emerald-400";
    } else {
      statusEl.textContent = `Error inesperado (HTTP ${res.status}).`;
      statusEl.className = "text-xs text-red-400";
    }
  } catch (err) {
    console.error("dashboard: failed to set scenario", err);
    statusEl.textContent = "Error de red.";
    statusEl.className = "text-xs text-red-400";
  }
}

async function handleChatSubmit(event) {
  event.preventDefault();
  const input = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send-btn");
  const pendingEl = document.getElementById("chat-pending");

  const prompt = input.value.trim();
  if (!prompt) return;

  sendBtn.disabled = true;
  pendingEl.classList.remove("hidden");

  try {
    const res = await fetch("/api/secure/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-SDK-Token": getToken(),
      },
      body: JSON.stringify({ prompt }),
    });

    const result = await res.json();
    chatHistory.push({
      prompt,
      verdict: result.verdict,
      message: result.message,
      error_code: result.error_code,
    });
    renderChatHistory();
    input.value = "";
  } catch (err) {
    console.error("dashboard: failed to send chat prompt", err);
    chatHistory.push({
      prompt,
      verdict: "BLOCKED",
      message: "Error de red al contactar el servidor.",
      error_code: "INTERNAL_ERROR",
    });
    renderChatHistory();
  } finally {
    sendBtn.disabled = false;
    pendingEl.classList.add("hidden");
  }
}

function initTokenField() {
  const tokenInput = document.getElementById("token-input");
  const saveBtn = document.getElementById("token-save-btn");

  tokenInput.value = getToken();

  saveBtn.addEventListener("click", () => {
    setToken(tokenInput.value.trim());
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initTokenField();

  document.getElementById("reset-btn").addEventListener("click", handleReset);
  document.getElementById("scenario-form").addEventListener("submit", handleScenarioSubmit);
  document.getElementById("chat-form").addEventListener("submit", handleChatSubmit);

  fetchInitialState();
  connectTelemetry(renderState, renderWsStatus);
});
