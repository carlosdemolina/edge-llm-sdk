# Phase 4 — Minimal REST server

**Date:** 2026-08-08
**Status:** ✅ Completed (DoD validated)

## What was done

Implemented `app/server/main.py`, `app/server/routes_common.py`, and
`app/server/routes_secure.py` on top of the Phase 1-3 modules (`hal`,
`OllamaClient`, `SecureSDKCore`, `AuditLog`), with no changes to their
internal logic:

- **`app/hal/hal.py`**: added `async def reset()`, resetting both
  `VehicleState` and `EnvironmentState` to their defaults (under the
  existing lock) — needed for reproducible testing between requests and,
  later, Red Teaming runs (Phase 9).
- **`app/server/main.py`**: FastAPI app using the modern `lifespan` async
  context manager (not the deprecated `@app.on_event`). Startup creates a
  single `OllamaClient` (`ensure_model_available()` fail-fast check), a
  single `AuditLog`, and a single `SecureSDKCore`, all stored on
  `app.state`; shutdown closes the Ollama client. `hal` remains the existing
  module-level singleton, imported directly (not re-wired through
  `app.state`). No telemetry background task yet (Phase 5); no vulnerable
  router mounted yet (Phase 7).
- **`app/server/routes_common.py`**: `GET /api/state` (unauthenticated),
  `POST /api/reset` (unauthenticated), `POST /api/scenario/set`
  (authenticated via a dedicated `hmac.compare_digest` dependency, since this
  route does not go through `SecureSDKCore`).
- **`app/server/routes_secure.py`**: `POST /api/secure/chat` — no
  route-level auth guard; the `X-SDK-Token` header is passed straight
  through to `SecureSDKCore.handle_request()`, whose own step 0 already
  authenticates and audits (including failures).

## DoD validation

Tested manually via `curl` against `uvicorn app.server.main:app` on the
Raspberry Pi:

| Criterion | Result |
|---|---|
| `GET /api/state` returns full snapshot | ✅ actuators + environment + real telemetry |
| `POST /api/reset` resets state | ✅ vehicle/environment back to defaults |
| `POST /api/scenario/set` without token | ✅ HTTP `401` |
| `POST /api/scenario/set` with valid token | ✅ `200`, environment updated |
| `POST /api/secure/chat` without token | ✅ `200` body with `UNAUTHENTICATED` |
| `POST /api/secure/chat` with valid token (benign prompt) | ✅ `200` body with `ALLOWED`, `set_lights` executed |
| State persists across HTTP calls | ✅ confirmed via a follow-up `GET /api/state` |
| Audit log covers all 3 chat attempts, chain verifiable | ✅ `verify_chain()` → `True` |

## Observed behavior (not a defect)

The first `/api/secure/chat` call after starting the server returned
`RESOURCE_LIMIT` (Ollama transport timeout) — consistent with Ollama having
unloaded the model from memory after a period of inactivity since the last
Phase 3 test run. A retry a few seconds later succeeded normally
(`ALLOWED`), matching the cold-start behavior already documented in Phase 2
and Phase 3.

## Design decisions confirmed this phase

- Two distinct auth mechanisms, not unified: `/api/secure/chat` relies
  entirely on `SecureSDKCore`'s own step-0 check (preserving the audit trail
  for failed attempts); `/api/scenario/set` has its own FastAPI dependency,
  since it never reaches `SecureSDKCore`.
- `/api/secure/chat` always returns HTTP `200`; the verdict/error code live
  in the JSON body (the SDK's deterministic verdict is the single source of
  truth, not the HTTP layer). `/api/scenario/set` uses a conventional `401`
  for auth failures since it has no `ActionResult`-style contract.
- `dataclasses.asdict()` is used to serialize HAL state and `ActionResult`;
  Pydantic stays scoped to the LLM I/O boundary (`LLMAction`), with request
  bodies (`ChatRequest`, `ScenarioSetRequest`) as the one FastAPI-mandated
  exception (HTTP boundary, not LLM boundary).
- `hal.reset()` resets both `VehicleState` and `EnvironmentState`, not just
  actuators.
- `GET /api/state` and `POST /api/reset` are intentionally left
  unauthenticated, per the design spec's explicit auth scoping.
