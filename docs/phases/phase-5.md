# Phase 5 — WebSocket telemetry

**Date:** 2026-08-08
**Status:** ✅ Completed (DoD validated)

## What was done

Added a push-based WebSocket telemetry channel on top of the Phase 4 REST
server, plus in-memory allowed/blocked metrics counters:

- **`app/server/ws_manager.py`** (new): `ConnectionManager` class and
  module-level singleton `manager`. Tracks active `WebSocket` connections and
  broadcasts a dict message to all of them, iterating a *copy* of the
  connection list (the live list is mutated by `disconnect()`) and treating
  any send failure (abrupt/ungraceful disconnect) as a disconnect rather
  than letting it propagate. Deliberately has no knowledge of HAL, metrics,
  or business logic, to avoid a circular import with `routes_common.py` and
  `main.py`, which both import `manager` from here.
- **`app/server/routes_common.py`**: renamed the private `_state_snapshot()`
  to public `build_state_snapshot(metrics: dict) -> dict`, now including a
  `"metrics"` key; `GET /api/state`, `POST /api/reset`, and
  `POST /api/scenario/set` all now accept `request: Request` and pass
  `request.app.state.metrics` through, so REST and WS share one snapshot
  shape. Added `GET /ws/telemetry`, which accepts the connection via
  `manager.connect()` and loops on `receive_text()` purely to detect
  `WebSocketDisconnect` (push-only channel — the server never expects client
  messages).
- **`app/server/routes_secure.py`**: after `SecureSDKCore.handle_request()`
  returns, increments `request.app.state.metrics["secure"]["allowed"]` or
  `["blocked"]` based on `result.verdict`.
- **`app/server/main.py`**: initializes
  `app.state.metrics = {"secure": {...}, "vulnerable": {...}}` in `lifespan`
  startup (vulnerable counters pre-declared but unused until Phase 7); adds
  `_telemetry_loop(app)`, a background `asyncio.Task` that sleeps
  `TELEMETRY_INTERVAL_S` (1.0 s) and broadcasts
  `routes_common.build_state_snapshot(app.state.metrics)` — skipping the
  broadcast entirely when `manager.active_connections` is empty, to avoid
  needless `psutil` reads. The task is created in `lifespan` startup and
  cancelled + awaited (suppressing `CancelledError`) in shutdown.

## DoD validation

Tested with a Python `websockets`-based test client against
`uvicorn app.server.main:app` on the Raspberry Pi (no `websocat` available
on the Pi, so a small ad hoc script was used instead):

| Criterion | Result |
|---|---|
| WS client connects to `/ws/telemetry` | ✅ `manager.connect()` accepts |
| Broadcast cadence ~1 s | ✅ 4 messages received at ~1 s intervals |
| Payload shape | ✅ `{vehicle, environment, telemetry, metrics}` |
| `/api/secure/chat` calls reflected in `metrics.secure` | ✅ confirmed via follow-up `GET /api/state` (eventually consistent within ~1 broadcast tick, not synchronous — acceptable for a dashboard) |
| Abrupt (non-graceful) client disconnect | ✅ connection process `SIGKILL`ed while WS open; no server exception, connection silently dropped from `active_connections` |
| Server stays responsive after abrupt disconnect | ✅ subsequent `GET /api/state` → `200` |

## Observed behavior (not a defect)

Metrics updates are only visible in the *next* broadcast tick, not
synchronously with the triggering `/api/secure/chat` call — since the
telemetry loop only reads/broadcasts once per second. A test that checked
metrics immediately after an action, from a short-lived process that exited
before the next tick, saw a stale value in its own 3 received messages, but
an independent `GET /api/state` immediately afterward showed the correct,
updated count. This is expected 1 Hz eventual consistency, not a bug.

## Design decisions confirmed this phase

- `build_state_snapshot()` is the single source of truth for the snapshot
  shape, shared by all REST endpoints and the WS broadcast loop.
- Metrics are plain in-memory counters on `app.state`, not derived by
  scanning the audit log — cheaper, and keeps the audit log scoped to
  tamper-evident forensics rather than a live dashboard feed.
- `GET /api/state` also gained the `metrics` field (in addition to
  `vehicle`/`environment`/`telemetry`), so a REST poller and the WS dashboard
  see identical data.
- Considered, and discarded, adding a HAL lock/deep-copy accessor for
  `build_state_snapshot()` to guard against reading mid-mutation state: not
  needed, since neither `apply_action()` nor the snapshot builder contains an
  internal `await` point, so Python's single-threaded cooperative asyncio
  scheduling prevents interleaving.
- `ws_manager.py` has zero dependencies on HAL/metrics/business logic, purely
  to break a would-be circular import between `routes_common.py` and
  `main.py`.
