# Phase 6 — Minimal frontend

**Date:** 2026-08-08
**Status:** ✅ Completed (DoD validated)

## What was done

Implemented `frontend/index.html`, `frontend/js/ws_client.js`, and
`frontend/js/dashboard.js`, with Tailwind CSS compiled locally, and mounted
the whole `frontend/` directory as static files from the FastAPI app:

- **`app/server/main.py`**: mounts `frontend/` as `StaticFiles(html=True)`
  at `"/"`, registered after both API routers so explicit REST/WS routes
  take precedence over the catch-all static mount. Same-origin serving
  means no CORS configuration is needed.
- **Tailwind build tooling**: no Node/npm on the Raspberry Pi. Downloaded
  the standalone Tailwind v4 CLI binary (`tailwindcss-linux-arm64`) into a
  git-ignored `tools/` directory — no `sudo`, no Node install, no runtime
  CDN dependency (which would require internet access at demo time).
  `frontend/css/input.css` (`@import "tailwindcss";` + explicit `@source`
  directives for `index.html`/`js/*.js`) is compiled once into the
  committed, minified `frontend/css/tailwind.css`.
- **`frontend/index.html`**: header (WS status badge, `X-SDK-Token` input,
  Reset button), vehicle actuator panel (climate/windows/lights/doors,
  read-only), environment+telemetry panel (speedometer, outside temp, real
  `psutil` gauges, Scenario Control Panel form, secure-mode metrics), and a
  chat panel.
- **`frontend/js/ws_client.js`**: `connectTelemetry(onMessage,
  onStatusChange)` — opens the WS, forwards parsed messages, flips a
  connected/disconnected callback. No auto-reconnect/backoff (deferred to
  Phase 10 hardening, per the plan).
- **`frontend/js/dashboard.js`**: renders the `{vehicle, environment,
  telemetry, metrics}` snapshot from both the initial `GET /api/state` call
  and every WS broadcast; the `X-SDK-Token` is entered once per browser tab
  and kept only in `sessionStorage` (never hardcoded in source); drives
  Reset, the Scenario Control Panel, and the chat panel (with a "Verificando
  respuesta…" pending indicator); maintains a purely cosmetic client-side
  chat history that only ever displays the SDK's own `verdict`/`message`/
  `error_code`, never an LLM `reasoning` field.

## DoD validation

Tested end-to-end in a real browser (via the integrated browser tool)
against `uvicorn app.server.main:app` on the Raspberry Pi:

| Criterion | Result |
|---|---|
| Dashboard loads and renders initial state via `GET /api/state` | ✅ |
| WS connects, status badge shows "Conectado" | ✅ |
| Chat action ("enciende las luces interiores") updates the actuator card and `metrics.secure` | ✅ (first attempt hit a cold-start `RESOURCE_LIMIT`, consistent with prior phases' documented Ollama idle-unload behavior; retry succeeded with `ALLOWED`, `light-interior` → "Encendida") |
| Scenario panel (`vehicle_speed_kmh=120`, `outside_temp_c=35`) updates speedometer/outside-temp immediately | ✅ |
| Missing/invalid token surfaces a clear inline error, not a silent failure | ✅ `401` → "Token ausente o inválido." |
| Reset button restores all cards to defaults | ✅ |
| Real Pi telemetry (CPU/RAM/temp) visibly changes under load | ✅ CPU jumped to ~99% during LLM inference, visible live in the dashboard |

## Observed behavior (not a defect)

- The doors panel initially used `flex justify-between` rows, which caused
  the (longer) "Bloqueado"/"Abierto" value text to visually overflow next to
  the label in a 2-column grid. Fixed by switching to the same
  label-on-top/value-below, `text-center` card layout already used for the
  climate/lights panels. The lights panel's "Desactivada" (hazard state)
  value had the same overflow risk for a single long word with no break
  opportunity; added `break-words` to all light/climate value cells as a
  preventive fix.
- The first `/api/secure/chat` call after starting the server hit
  `RESOURCE_LIMIT` (cold-start Ollama timeout) — same documented, expected
  behavior as Phase 4/5, not specific to the frontend.

## Design decisions confirmed this phase

- Frontend served from the same FastAPI process/origin as the API (no
  separate static server, no CORS).
- Tailwind compiled locally via the standalone CLI binary (not Node/npm,
  not a CDN), matching the plan's explicit "Tailwind compilado localmente"
  requirement while respecting the Pi's offline-first constraints.
- `X-SDK-Token` is operator-entered per browser tab and kept in
  `sessionStorage` only — never embedded in shipped source, to avoid
  shipping a secret in static files (OWASP A02/A07 concerns).
- WS reconnection is intentionally minimal in this phase (status flip only,
  no retry/backoff) — full hardening is Phase 10 scope.
- The vehicle actuator panel remains strictly read-only from the operator's
  perspective; only the LLM (via chat) can change actuators, only the
  operator (via the Scenario Control Panel) can change `EnvironmentState` —
  mirroring the server-side separation already enforced since Phase 3.
- Chat history is purely cosmetic client-side state, never resent to the
  server, and only ever displays the SDK's deterministic verdict fields —
  never the LLM's own reasoning text.
