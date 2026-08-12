/**
 * Dashboard rendering + interactions (see docs/ARCHITECTURE.md).
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

/** Fuel/battery are always whole-number percentages (clamped server-side),
 *  unlike CPU/RAM which use one decimal of precision. */
function fmtLevel(value) {
  return typeof value === "number" ? `${value}%` : "—";
}

function fmtTemp(value) {
  return typeof value === "number" ? `${value}°C` : "—";
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

/**
 * Toast notifications (visual polish pass). Replace ad-hoc alert()/plain
 * inline status text with small auto-dismissing banners, consistent for
 * scenario feedback and destructive-action errors across the panel.
 */
function showToast(message, tone) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  if (tone === "error") {
    toast.className = "toast toast-error pointer-events-auto";
  } else if (tone === "warn") {
    toast.className = "toast toast-warn pointer-events-auto";
  } else {
    toast.className = "toast toast-ok pointer-events-auto";
  }
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = "opacity 0.3s ease, transform 0.3s ease";
    toast.style.opacity = "0";
    toast.style.transform = "translateY(6px)";
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

/**
 * Briefly highlights a card/element whose underlying value just changed
 * (diffed against the previous snapshot in `renderState`), independent of
 * the on/off color coding — a neutral "this just updated" cue.
 */
function flashElement(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove("flash-update");
  void el.offsetWidth; // force reflow so the animation can restart
  el.classList.add("flash-update");
  setTimeout(() => el.classList.remove("flash-update"), 700);
}

/**
 * Car HUD screen (above the chat panel): translates the SDK's own
 * deterministic `verdict`/`action`/`params` (never the LLM's `reasoning`)
 * into a short in-dash phrase, e.g. "Opening window" or "Request denied
 * by policy" — the visual equivalent of a real infotainment screen
 * reacting to a voice command.
 */
function describeDashEvent(entry) {
  if (entry.verdict !== "ALLOWED") {
    const byErrorCode = {
      UNAUTHENTICATED: "Access denied",
      POLICY_VIOLATION: "Request denied by policy",
      INVALID_INPUT: "Command not understood",
      RESOURCE_LIMIT: "Too many requests, try again",
      INTERNAL_ERROR: "System error",
    };
    return { icon: "⛔", text: byErrorCode[entry.error_code] || "Request blocked" };
  }

  const params = entry.params || {};
  switch (entry.action) {
    case "set_window": {
      const target = params.window && params.window !== "all" ? params.window.replace(/_/g, " ") : "windows";
      const verb = typeof params.position === "number" && params.position === 0 ? "Closing" : "Opening";
      return { icon: "🪟", text: `${verb} ${target}` };
    }
    case "set_lights": {
      const label = { headlights: "Headlights", interior: "Interior light", hazard: "Hazard lights" }[params.light] || "Lights";
      return { icon: "💡", text: `${label} ${params.state ? "on" : "off"}` };
    }
    case "set_door_lock": {
      const target = params.door && params.door !== "all" ? `${params.door.replace(/_/g, " ")} door` : "doors";
      return { icon: "🔒", text: `${params.locked ? "Locking" : "Unlocking"} ${target}` };
    }
    case "set_climate":
      return { icon: "❄️", text: `Climate ${params.power ? "on" : "off"}, ${params.target_temp_c}°C` };
    case "get_status":
      return { icon: "ℹ️", text: "Status checked" };
    default:
      return { icon: "✓", text: entry.message };
  }
}

function renderCarHud(entry) {
  const iconEl = document.getElementById("car-hud-icon");
  const textEl = document.getElementById("car-hud-text");
  if (!iconEl || !textEl) return;

  const { icon, text } = describeDashEvent(entry);
  iconEl.textContent = icon;
  textEl.textContent = text;
  flashElement("car-hud-screen");
}

/** Toggle a stateful actuator card (climate/lights/locks) between neutral,
 *  "active" (emerald) and "alert" (amber) visual treatments. */
function setStatCard(cardId, iconId, mode) {
  const card = document.getElementById(cardId);
  const icon = document.getElementById(iconId);
  if (card) {
    card.classList.remove("stat-card-active", "stat-card-alert");
    if (mode === "active") card.classList.add("stat-card-active");
    if (mode === "alert") card.classList.add("stat-card-alert");
  }
  if (icon) {
    icon.classList.remove("stat-icon-active", "stat-icon-alert");
    if (mode === "active") icon.classList.add("stat-icon-active");
    if (mode === "alert") icon.classList.add("stat-icon-alert");
  }
}

/** Swaps the open/closed padlock shackle path inside a lock icon. */
function setLockIcon(iconId, locked) {
  const icon = document.getElementById(iconId);
  if (!icon) return;
  const closedPath = icon.querySelector(".lock-shackle-closed");
  const openPath = icon.querySelector(".lock-shackle-open");
  if (closedPath) closedPath.classList.toggle("hidden", !locked);
  if (openPath) openPath.classList.toggle("hidden", locked);
}

/** Updates the cooling-fan tile: level text, threshold bar and a spin icon
 *  whose speed scales with the current level — the more it spins, the
 *  hotter the system, mirroring the real Pi 5 Active Cooler behavior. */
function setFanLevel(level, levelMax) {
  const icon = document.getElementById("icon-fan");
  const hasLevel = typeof level === "number" && typeof levelMax === "number" && levelMax > 0;

  setText("fan-level", hasLevel ? `${level} / ${levelMax}` : "N/A");
  setThresholdBar("fan-level-bar", hasLevel ? (level / levelMax) * 100 : 0, 50, 75);

  if (!icon) return;
  if (hasLevel && level > 0) {
    const duration = Math.max(0.6, 3.5 - level * 0.7); // faster spin at higher levels
    icon.style.animation = `spin-slow ${duration}s linear infinite`;
    icon.classList.toggle("text-sky-400", level < levelMax);
    icon.classList.toggle("text-red-400", level >= levelMax);
    icon.classList.toggle("text-slate-400", false);
  } else {
    icon.style.animation = "";
    icon.classList.add("text-slate-400");
    icon.classList.remove("text-sky-400", "text-red-400");
  }
}

/** Color-codes a telemetry progress bar by threshold (green/amber/red). */
function setThresholdBar(barId, percent, warnAt, dangerAt) {
  const bar = document.getElementById(barId);
  if (!bar) return;
  bar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
  bar.classList.remove("bg-emerald-500", "bg-amber-500", "bg-red-500", "bg-sky-500");
  if (percent >= dangerAt) {
    bar.classList.add("bg-red-500");
  } else if (percent >= warnAt) {
    bar.classList.add("bg-amber-500");
  } else {
    bar.classList.add("bg-emerald-500");
  }
}

/** Same idea as `setThresholdBar()` but inverted: used for "level" gauges
 *  (fuel, battery) where a LOW value is the dangerous one, not a high one. */
function setLevelBar(barId, percent, warnBelow, dangerBelow) {
  const bar = document.getElementById(barId);
  if (!bar) return;
  bar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
  bar.classList.remove("bg-emerald-500", "bg-amber-500", "bg-red-500", "bg-sky-500");
  if (percent <= dangerBelow) {
    bar.classList.add("bg-red-500");
  } else if (percent <= warnBelow) {
    bar.classList.add("bg-amber-500");
  } else {
    bar.classList.add("bg-emerald-500");
  }
}

/** Recolors the fuel pump icon (amber/red) as the tank runs low — same
 *  visual language as the fan icon's level-based coloring. */
function setFuelIcon(percent) {
  const icon = document.getElementById("icon-fuel");
  if (!icon) return;
  icon.classList.remove("text-slate-400", "text-amber-400", "text-red-400");
  if (typeof percent !== "number") {
    icon.classList.add("text-slate-400");
  } else if (percent <= 10) {
    icon.classList.add("text-red-400");
  } else if (percent <= 20) {
    icon.classList.add("text-amber-400");
  } else {
    icon.classList.add("text-slate-400");
  }
}

/** Updates the battery icon's internal fill rect width (proportional to
 *  charge level, like a real battery indicator) and its color. */
function setBatteryIcon(percent) {
  const icon = document.getElementById("icon-battery");
  const fill = document.getElementById("battery-fill-rect");
  if (!icon || !fill) return;
  const pct = typeof percent === "number" ? Math.max(0, Math.min(100, percent)) : 0;
  fill.setAttribute("width", (13 * pct / 100).toFixed(1));
  icon.classList.remove("text-slate-400", "text-amber-400", "text-red-400");
  if (typeof percent !== "number") {
    icon.classList.add("text-slate-400");
  } else if (percent <= 10) {
    icon.classList.add("text-red-400");
  } else if (percent <= 20) {
    icon.classList.add("text-amber-400");
  } else {
    icon.classList.add("text-slate-400");
  }
}

/** Updates the circular speed gauge (CSS conic-gradient donut ring). */
function setSpeedGauge(speedKmh) {
  const ring = document.getElementById("speed-gauge-ring");
  if (!ring) return;
  const pct = Math.max(0, Math.min(100, (speedKmh / 220) * 100));
  ring.style.background =
    `conic-gradient(#0ea5e9 ${pct}%, rgba(148,163,184,0.15) ${pct}%)`;
}

/** Toggles the schematic headlight indicators (glow when active). */
function setSchematicHeadlights(active) {
  for (const id of ["schema-headlight-left", "schema-headlight-right"]) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.classList.remove("bg-slate-600", "bg-amber-400", "shadow-[0_0_10px_3px_rgba(251,191,36,0.65)]");
    if (active) {
      el.classList.add("bg-amber-400", "shadow-[0_0_10px_3px_rgba(251,191,36,0.65)]");
    } else {
      el.classList.add("bg-slate-600");
    }
  }
}

/** Toggles a schematic door indicator between neutral (locked) and an
 *  attention-drawing amber highlight (unlocked). */
function setSchematicDoor(id, locked) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove("bg-slate-600", "bg-amber-400", "shadow-[0_0_8px_2px_rgba(251,191,36,0.55)]");
  if (locked) {
    el.classList.add("bg-slate-600");
  } else {
    el.classList.add("bg-amber-400", "shadow-[0_0_8px_2px_rgba(251,191,36,0.55)]");
  }
}

/** Toggles the schematic hazard indicator (blinking amber when active). */
function setSchematicHazard(active) {
  const el = document.getElementById("schema-hazard");
  if (!el) return;
  el.classList.remove(
    "bg-slate-700", "border-slate-600", "text-slate-500",
    "bg-amber-500", "border-amber-400", "text-slate-900", "animate-hazard-blink",
  );
  if (active) {
    el.classList.add("bg-amber-500", "border-amber-400", "text-slate-900", "animate-hazard-blink");
  } else {
    el.classList.add("bg-slate-700", "border-slate-600", "text-slate-500");
  }
}

function renderWsStatus(status) {
  const el = document.getElementById("ws-status");
  if (!el) return;
  if (status === "connected") {
    el.textContent = "Connected";
    el.className = "badge badge-ok";
  } else if (status === "reconnecting") {
    el.textContent = "Reconnecting…";
    el.className = "badge badge-warn";
  } else {
    el.textContent = "Disconnected";
    el.className = "badge badge-error";
  }
}

// Snapshot of the previous vehicle state, used only to diff which fields
// changed since the last render and trigger a brief "flash" highlight.
// Telemetry (cpu/ram/cpu_temp) is deliberately excluded — it ticks every
// ~1s from real host metrics and would flash constantly, which is noise
// rather than signal.
let previousVehicleState = null;
let previousEnvironmentState = null;

function renderState(state) {
  const { vehicle, environment, telemetry } = state;

  // Climate
  const climatePowerChanged = previousVehicleState && previousVehicleState.climate.power !== vehicle.climate.power;
  const climateTempChanged = previousVehicleState && previousVehicleState.climate.target_temp_c !== vehicle.climate.target_temp_c;
  const climateFanChanged = previousVehicleState && previousVehicleState.climate.fan_speed !== vehicle.climate.fan_speed;

  setText("climate-power", boolLabel(vehicle.climate.power, "On", "Off"));
  setText("climate-temp", `${vehicle.climate.target_temp_c}°C`);
  setText("climate-fan", String(vehicle.climate.fan_speed));
  setStatCard("card-climate-power", "icon-climate-power", vehicle.climate.power ? "active" : null);
  document.getElementById("icon-climate-power")?.classList.toggle("animate-spin-slow", vehicle.climate.power);
  if (climatePowerChanged) flashElement("card-climate-power");
  if (climateTempChanged) flashElement("climate-temp");
  if (climateFanChanged) flashElement("climate-fan");

  // Windows
  for (const w of ["front_left", "front_right", "rear_left", "rear_right"]) {
    const pct = vehicle.windows[w];
    const changed = previousVehicleState && previousVehicleState.windows[w] !== pct;
    setText(`window-${w}`, `${pct}%`);
    const bar = document.getElementById(`window-bar-${w}`);
    if (bar) bar.style.width = `${pct}%`;
    if (changed) flashElement(`window-${w}`);
  }

  // Lights
  const headlightsChanged = previousVehicleState && previousVehicleState.lights.headlights !== vehicle.lights.headlights;
  const interiorChanged = previousVehicleState && previousVehicleState.lights.interior !== vehicle.lights.interior;
  const hazardChanged = previousVehicleState && previousVehicleState.lights.hazard !== vehicle.lights.hazard;

  setText("light-headlights", boolLabel(vehicle.lights.headlights, "On", "Off"));
  setText("light-interior", boolLabel(vehicle.lights.interior, "On", "Off"));
  setText("light-hazard", boolLabel(vehicle.lights.hazard, "On", "Off"));
  setStatCard("card-light-headlights", "icon-light-headlights", vehicle.lights.headlights ? "active" : null);
  setStatCard("card-light-interior", "icon-light-interior", vehicle.lights.interior ? "active" : null);
  setStatCard("card-light-hazard", "icon-light-hazard", vehicle.lights.hazard ? "alert" : null);
  setSchematicHeadlights(vehicle.lights.headlights);
  setSchematicHazard(vehicle.lights.hazard);
  if (headlightsChanged) flashElement("card-light-headlights");
  if (interiorChanged) flashElement("card-light-interior");
  if (hazardChanged) flashElement("card-light-hazard");

  // Doors — "unlocked" is the state that should draw attention (amber),
  // "locked" is the safe/neutral baseline (emerald).
  const doors = [
    ["driver", vehicle.doors.driver_locked],
    ["passenger", vehicle.doors.passenger_locked],
    ["rear_left", vehicle.doors.rear_left_locked],
    ["rear_right", vehicle.doors.rear_right_locked],
  ];
  for (const [key, locked] of doors) {
    const changed = previousVehicleState && previousVehicleState.doors[`${key}_locked`] !== locked;
    setText(`door-${key}`, boolLabel(locked, "Locked", "Unlocked"));
    setStatCard(`card-door-${key}`, `icon-door-${key}`, locked ? "active" : "alert");
    setLockIcon(`icon-door-${key}`, locked);
    setSchematicDoor(`schema-door-${key}`, locked);
    if (changed) flashElement(`card-door-${key}`);
  }

  // Vehicle dashboard (speed + outside temp + fuel + battery) — only
  // changes via explicit scenario calls, so it is safe to include in the
  // flash-diff.
  const speedChanged = previousEnvironmentState && previousEnvironmentState.vehicle_speed_kmh !== environment.vehicle_speed_kmh;
  const outsideTempChanged = previousEnvironmentState && previousEnvironmentState.outside_temp_c !== environment.outside_temp_c;
  const fuelChanged = previousEnvironmentState && previousEnvironmentState.fuel_percent !== environment.fuel_percent;
  const batteryChanged = previousEnvironmentState && previousEnvironmentState.battery_percent !== environment.battery_percent;

  setText("speed-value", String(environment.vehicle_speed_kmh));
  setSpeedGauge(environment.vehicle_speed_kmh);
  setText("outside-temp", fmtTemp(environment.outside_temp_c));
  setThresholdBar("outside-temp-bar", ((environment.outside_temp_c + 20) / 70) * 100, 60, 85);
  if (speedChanged) flashElement("speed-value");
  if (outsideTempChanged) flashElement("outside-temp");

  setText("fuel-percent", fmtLevel(environment.fuel_percent));
  setLevelBar("fuel-percent-bar", environment.fuel_percent, 20, 10);
  setFuelIcon(environment.fuel_percent);
  if (fuelChanged) flashElement("fuel-percent");

  setText("battery-percent", fmtLevel(environment.battery_percent));
  setLevelBar("battery-percent-bar", environment.battery_percent, 20, 10);
  setBatteryIcon(environment.battery_percent);
  if (batteryChanged) flashElement("battery-percent");

  // Real telemetry (never flashed — updates every ~1s from the host).
  setText("cpu-percent", fmtPercent(telemetry.cpu_percent));
  setText("ram-percent", fmtPercent(telemetry.ram_percent));
  setText("cpu-temp", telemetry.cpu_temp_c !== null ? fmtTemp(telemetry.cpu_temp_c) : "N/A");
  setText("telemetry-timestamp", telemetry.timestamp || "—");
  if (typeof telemetry.cpu_percent === "number") setThresholdBar("cpu-percent-bar", telemetry.cpu_percent, 50, 80);
  if (typeof telemetry.ram_percent === "number") setThresholdBar("ram-percent-bar", telemetry.ram_percent, 50, 80);
  if (typeof telemetry.cpu_temp_c === "number") setThresholdBar("cpu-temp-bar", ((telemetry.cpu_temp_c) / 90) * 100, 60, 80);
  setFanLevel(telemetry.fan_level, telemetry.fan_level_max);

  previousVehicleState = JSON.parse(JSON.stringify(vehicle));
  previousEnvironmentState = JSON.parse(JSON.stringify(environment));
}


function renderChatHistory() {
  const container = document.getElementById("chat-history");
  if (!container) return;

  container.innerHTML = "";
  for (const entry of chatHistory) {
    const isAllowed = entry.verdict === "ALLOWED";
    const time = entry.timestamp
      ? new Date(entry.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
      : "";

    const group = document.createElement("div");
    group.className = "space-y-1";

    // User prompt bubble — right-aligned, conversational style.
    const promptWrap = document.createElement("div");
    promptWrap.className = "flex justify-end";
    const promptBubble = document.createElement("div");
    promptBubble.className = "max-w-[85%] rounded-2xl rounded-br-sm bg-sky-800/70 px-3 py-1.5 text-slate-100";
    const modeTag = entry.mode === "vulnerable" ? '<span class="text-red-300 font-semibold">[VULNERABLE] </span>' : "";
    promptBubble.innerHTML = `${modeTag}<span>${entry.prompt.replace(/</g, "&lt;")}</span>`;
    promptWrap.appendChild(promptBubble);

    // System result bubble — left-aligned, colored by verdict, with a
    // check/blocked glyph and a discrete timestamp.
    const resultWrap = document.createElement("div");
    resultWrap.className = "flex justify-start";
    const resultBubble = document.createElement("div");
    resultBubble.className = `max-w-[85%] rounded-2xl rounded-bl-sm px-3 py-1.5 font-mono text-xs ${isAllowed ? "bg-emerald-900/50 text-emerald-200" : "bg-red-900/50 text-red-200"}`;
    const codePart = entry.error_code ? ` [${entry.error_code}]` : "";
    const glyph = isAllowed ? "✓" : "⛔";
    resultBubble.innerHTML =
      `<span>${glyph} ${entry.verdict}${codePart}: ${entry.message}</span>` +
      (time ? `<span class="block text-[10px] text-slate-500 mt-0.5">${time}</span>` : "");
    resultWrap.appendChild(resultBubble);

    group.appendChild(promptWrap);
    group.appendChild(resultWrap);
    container.appendChild(group);
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
  const speedInput = document.getElementById("scenario-speed");
  const tempInput = document.getElementById("scenario-temp");
  const fuelInput = document.getElementById("scenario-fuel");
  const batteryInput = document.getElementById("scenario-battery");

  const body = {};
  if (speedInput.value !== "") body.vehicle_speed_kmh = Number(speedInput.value);
  if (tempInput.value !== "") body.outside_temp_c = Number(tempInput.value);
  if (fuelInput.value !== "") body.fuel_percent = Number(fuelInput.value);
  if (batteryInput.value !== "") body.battery_percent = Number(batteryInput.value);

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
      showToast("Token missing or invalid.", "error");
      return;
    }

    if (res.ok) {
      renderState(await res.json());
      showToast("Scenario applied.", "ok");
    } else {
      showToast(`Unexpected error (HTTP ${res.status}).`, "error");
    }
  } catch (err) {
    console.error("dashboard: failed to set scenario", err);
    showToast("Network error.", "error");
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
    const entry = {
      prompt,
      mode: vulnerable ? "vulnerable" : "secure",
      verdict: result.verdict,
      message: result.message,
      error_code: result.error_code,
      action: result.action,
      params: result.params,
      timestamp: new Date().toISOString(),
    };
    chatHistory.push(entry);
    renderChatHistory();
    renderCarHud(entry);
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
    const entry = {
      prompt,
      mode: vulnerable ? "vulnerable" : "secure",
      verdict: "BLOCKED",
      message: "Network error contacting the server.",
      error_code: "INTERNAL_ERROR",
      timestamp: new Date().toISOString(),
    };
    chatHistory.push(entry);
    renderChatHistory();
    renderCarHud(entry);
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
 * Admin/Debug tab (developer tool, see docs/ARCHITECTURE.md). Hidden unless
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
  const outcomeBadgeClass = blockedStage ? "badge badge-error" : "badge badge-ok";
  const totalMs = typeof entry.sdk_total_duration_ms === "number"
    ? `${entry.sdk_total_duration_ms.toFixed(0)} ms`
    : "—";
  const isVulnerable = entry.pipeline === "vulnerable";
  const pipelineLabel = isVulnerable ? "VULNERABLE" : "SECURE";
  const pipelineBadgeClass = isVulnerable ? "badge badge-warn" : "badge badge-neutral";

  const details = document.createElement("details");
  details.className = "bg-slate-700/70 rounded-lg p-2 ring-1 ring-white/5";

  const summary = document.createElement("summary");
  summary.className = "cursor-pointer font-mono text-xs flex items-center justify-between gap-2";
  summary.innerHTML =
    `<span class="flex items-center gap-2"><span class="${pipelineBadgeClass}">${pipelineLabel}</span> ${entry.timestamp || "—"} · trace ${(entry.trace_id || "").slice(0, 8)}</span>` +
    `<span class="flex items-center gap-2"><span class="${outcomeBadgeClass}">${outcomeLabel}</span> <span class="text-slate-400">${totalMs}</span></span>`;

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
    `RAM: ${entry.ram_percent_start ?? "—"}% → ${entry.ram_percent_end ?? "—"}% · ` +
    `Temp: ${entry.cpu_temp_c_start ?? "—"}°C → ${entry.cpu_temp_c_end ?? "—"}°C`;
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
      showToast(`Could not clear history (HTTP ${res.status}).`, "error");
      return;
    }
    fetchDebugTraces();
    showToast("Debug history cleared.", "ok");
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
 * Audit modal — read-only view of the tamper-evident
 * `audit.log`, a production security feature (unlike the Admin/Debug
 * section above), so it is always reachable from the header, never gated
 * by SDK_DEBUG_MODE. Both endpoints require X-SDK-Token.
 */
function renderAuditEntry(entry) {
  const verdictBadgeClass = entry.verdict === "BLOCKED" ? "badge badge-error" : "badge badge-ok";
  const modeBadgeClass = entry.mode === "vulnerable" ? "badge badge-warn" : "badge badge-neutral";

  const row = document.createElement("div");
  row.className = "bg-slate-700/70 rounded-lg p-2 font-mono text-xs space-y-1 ring-1 ring-white/5";

  const line1 = document.createElement("div");
  line1.className = "flex items-center justify-between gap-2";
  line1.innerHTML =
    `<span class="flex items-center gap-2">#${entry.seq ?? "—"} · ${entry.timestamp || "—"} · <span class="${modeBadgeClass}">${entry.mode || "—"}</span></span>` +
    `<span class="${verdictBadgeClass}">${entry.verdict || "—"}</span>`;

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
  statusEl.className = "badge badge-neutral";
  try {
    const res = await fetch("/api/audit/verify", {
      headers: { "X-SDK-Token": getToken() },
    });
    if (!res.ok) {
      statusEl.textContent = `Error (HTTP ${res.status})`;
      statusEl.className = "badge badge-error";
      return;
    }
    const { valid } = await res.json();
    statusEl.textContent = valid ? "Chain OK" : "Chain BROKEN";
    statusEl.className = valid ? "badge badge-ok" : "badge badge-error";
  } catch (err) {
    console.error("dashboard: failed to verify audit chain", err);
    statusEl.textContent = "Network error";
    statusEl.className = "badge badge-error";
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
