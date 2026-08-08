# Phase 3 — Secure SDK core (`sdk_core.py`)

**Date:** 2026-08-08
**Status:** ✅ Completed (DoD validated)

## What was done

Implemented the full secure pipeline and its supporting modules:

- **`app/core/schemas.py`**: `ErrorCode` enum, strict `LLMAction` Pydantic
  model (`extra="forbid"`), `Ctx` and `ActionResult` dataclasses, and the
  `SECURITY_VIOLATION_PREFIX` constant.
- **`app/core/sanitizer.py`**: `sanitize()` — Unicode NFKC normalization,
  length cap, deny-pattern regex check (case-insensitive, English + Spanish
  patterns).
- **`app/core/dsl_validator.py`**: `validate()` — strict whitelist +
  type/range rejection against the DSL catalog (no clamping, unlike `hal.py`).
- **`app/core/audit_log.py`**: `AuditLog` — append-only, HMAC-SHA256
  hash-chained JSONL log, genesis hash of 64 zeros, `append()` and
  `verify_chain()`.
- **`app/core/sdk_core.py`**: `SecureSDKCore` — dependency-injected (not a
  singleton), orchestrates the full pipeline (`handle_request()`): auth,
  rate-limit cooldown, `Ctx` creation, sanitization, structural prompt
  encapsulation (`build_prompt()`, dynamically generated from the DSL
  catalog), the Ollama call, output validation (JSON parse with fallback,
  Pydantic schema, DSL whitelist/range, canary leak check, contextual
  policy), HAL execution, and audit logging.
- **`app/policies/dsl_actions.json`**: filled in with the 5-action catalog
  (`set_climate`, `set_window`, `set_lights`, `set_door_lock`, `get_status`).
- **`app/policies/vehicle_default.json`**: filled in with `policy_id`,
  `deadline_ms`, `rate_limit_cooldown_s`, `sanitizer` rules, and
  `contextual_rules` (speed lockout on `set_window`/`set_door_lock`).
- **`app/hal/hal.py`**: added `get_environment()`, returning a *copy*
  (`dataclasses.replace(...)`) of the live `EnvironmentState` — deliberately
  not a live reference, so the contextual policy check cannot mutate HAL
  state through it.
- **`app/config.py`**: added `SDK_TOKEN`, `AUDIT_LOG_HMAC_SECRET` (as
  `bytes.fromhex(...)`), `AUDIT_LOG_PATH`. `RATE_LIMIT_COOLDOWN_S` was
  deliberately **not** added here — it now lives exclusively in
  `vehicle_default.json` (an auditable, git-tracked policy value, not a
  secret), and the corresponding line was removed from `.env`.
- Manual CLI demo (`python -m app.core.sdk_core`): benign prompts, an
  unauthenticated request, a prompt-injection attempt, a contextual-policy
  violation (speed lockout), an out-of-catalog request, a concurrent
  two-request burst, and a final `verify_chain()` check.

## DoD validation

| Criterion | Result |
|---|---|
| Benign prompts mutate HAL state | ✅ `set_lights`, `set_window` executed and reflected in `hal.vehicle` |
| Unauthenticated request blocked | ✅ `UNAUTHENTICATED` |
| Prompt injection blocked | ✅ `POLICY_VIOLATION` (sanitizer deny-pattern) |
| Contextual policy violation blocked | ✅ `POLICY_VIOLATION` (speed > 30 km/h lockout on `set_window`) |
| Burst request blocked by rate limiter | ✅ 2nd of 2 concurrent requests -> `RESOURCE_LIMIT` |
| Audit hash chain verifiable | ✅ `verify_chain()` -> `True`; independently confirmed to detect tampering (returns `False` after manually editing one entry) |

## Observed model behavior (not a code defect — documented for the record)

- **Out-of-catalog request** (`"Acelera el coche a 200 km/h"`, which has no
  corresponding DSL action): the model did not invent an unknown action name;
  instead it mapped the request onto an unrelated, in-catalog, valid action
  (`set_climate`), which was then legitimately `ALLOWED` by the pipeline. The
  DSL whitelist correctly prevents arbitrary/unknown actions and out-of-range
  parameters, but it cannot (by design) judge whether the *chosen* action
  actually matches the user's semantic intent — that class of risk (semantic
  action-selection mismatch) is out of scope for Phase 3 and is a natural
  candidate for the Phase 9 Red Teaming campaign.
- **Rate-limit cooldown semantics**: the cooldown clock is set in step 0-bis
  for every *authenticated* request, even ones later blocked in microseconds
  by the sanitizer/DSL layers (no LLM call needed). This means sequential
  test prompts must be paced (`asyncio.sleep`) past the cooldown to each
  demonstrate their own defense layer; conversely, demonstrating the rate
  limiter itself requires firing requests *concurrently*
  (`asyncio.gather(...)`), since one sequential request's own inference
  latency (several seconds) already exceeds the 2s cooldown by the time the
  next one would start.

## Design decisions confirmed this phase

- `SecureSDKCore` is dependency-injected, not a module-level singleton
  (unlike `hal`) — constructed with `hal`, `ollama_client`, `audit_log`,
  `sdk_token`, `dsl_catalog`, `policy` as explicit arguments.
- `trace_id` is generated at the very start of `handle_request()`, before
  authentication — so even the earliest rejections (`UNAUTHENTICATED`,
  `RESOURCE_LIMIT`) are audited with a trace ID.
- `hal.get_environment()` returns a copy, not the live `EnvironmentState`
  reference, preserving HAL's encapsulation guarantees for read access too.
- `rate_limit_cooldown_s` and `deadline_ms` are versioned policy values in
  `vehicle_default.json`, not secrets in `.env`.
- The audit log's HMAC uses canonical JSON
  (`sort_keys=True, separators=(",", ":"), ensure_ascii=False`) so the same
  logical entry always serializes identically for hashing.
- The `@SECURITY_VIOLATION@` prefix is a named constant
  (`SECURITY_VIOLATION_PREFIX`), not a repeated string literal.
