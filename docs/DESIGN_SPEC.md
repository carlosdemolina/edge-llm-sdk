# Design Specification (English reference)

> The authoritative source of design decisions for this project is a private,
> Spanish-language document (`Implementacion_Capitulo6.md`) that is **not**
> included in this repository (see `.gitignore`). This file mirrors, section by
> section and in English, **only the parts that are already implemented in
> code**, so that in-repo comments can reference a document that actually
> exists here. Section numbers are kept aligned with the private source
> document for traceability.
>
> Sections not yet listed below are pending and will be added as their
> corresponding implementation phase is completed (see `docs/phases/`).

---

## 2.1. Vehicle state (`app/hal/hal.py`)

In-memory state, held as a single *singleton* instance guarded by an
`asyncio.Lock`. Three data origins with distinct trust boundaries are
distinguished: **actuators** (mutable only by the LLM via the DSL),
**simulated environment** (mutable only by the human operator, never by the
LLM), and **real telemetry** (read-only, Raspberry Pi hardware):

```text
VehicleState (actuators — mutable ONLY via the whitelisted DSL):
  climate:
    power: bool
    target_temp_c: int          # valid range [16, 28]
    fan_speed: int               # valid range [0, 5]
  windows:
    front_left:  int             # % open, range [0, 100]
    front_right: int
    rear_left:   int
    rear_right:  int
  lights:
    headlights: bool
    interior:   bool
    hazard:     bool
  doors:
    driver_locked:      bool
    passenger_locked:   bool
    rear_left_locked:   bool
    rear_right_locked:  bool

EnvironmentState (simulated scenario — mutable ONLY by the operator via
`POST /api/scenario/set`, NEVER by the LLM):
  vehicle_speed_kmh: int         # range [0, 220]. Ground truth "the car is
                                   # driving at X km/h", used to build Red
                                   # Teaming scenarios and for the secure
                                   # pipeline's contextual policy validation.
  outside_temp_c: int             # range [-20, 50]. Simulated outside
                                   # temperature, shown on the dashboard.

SystemTelemetry (real, read-only, Raspberry Pi hardware):
  cpu_percent: float              # psutil.cpu_percent(interval=None)
  ram_percent: float               # psutil.virtual_memory().percent
  cpu_temp_c: float | None         # psutil.sensors_temperatures() -> 'cpu_thermal',
                                   # falls back to `vcgencmd measure_temp` if absent
  timestamp: str (ISO 8601, UTC)
```

**Validation rules in `hal.py` (independent of the SDK, minimal defense even in
"vulnerable" mode):**
- Every numeric value out of range is **clamped** (never raises an exception),
  so that the vulnerable mode cannot crash the process — the vulnerability
  being demonstrated is a **security policy bypass**, not interpreter
  stability.
- Every state write (actuators or environment) goes through dedicated methods
  (`apply_action()` / `set_environment()`) protected by the same lock; reading
  telemetry (`get_telemetry()`) requires no lock (read-only, low cost).
- **Trust boundary:** `EnvironmentState` is test data deliberately set by the
  human operator (never by the chat user nor the LLM), so it does not
  constitute a new attack surface exposed to the model — its only purpose is
  to build reproducible Red Teaming scenarios.

## 3.3. `ollama_client.py`

- Reused `httpx.AsyncClient` (never one per request).
- Endpoint: `POST http://localhost:11434/api/generate`, `model: "llama3.2:latest"`
  (real tag confirmed on-device via `ollama list`; underlying model is Llama 3.2,
  3.2B parameters, Q4_K_M quantization), `stream: false` in prototype v1.
- Parameters (`options`): `temperature`, `top_k`, `top_p`, plus `format: "json"`
  when required.
- Startup check (FastAPI `startup event`, wired in Phase 4): `GET /api/tags` to
  confirm `llama3.2:latest` is downloaded; if missing, raise a clear error and
  abort (fail-fast, never fail silently on the user's first chat).
- Calls are serialized via `asyncio.Semaphore(1)` inside the client itself —
  the Raspberry Pi can only run one inference at a time, and this must hold
  regardless of which pipeline (secure or vulnerable) issues the call.
- Timeouts are split by phase rather than a single uniform value:
  `connect=5.0s` (fail fast if Ollama is unreachable/down) and `read=30.0s`
  (the model can take 8-12s to warm up from idle on the Pi 5 before it starts
  generating).

## 2.2. DSL action catalog (`app/policies/dsl_actions.json`)

A versioned, git-tracked whitelist of every action the LLM is allowed to
request. Both the secure pipeline's validator and the prompt sent to the LLM
are generated dynamically from this single source of truth — there is no
duplicated/hand-maintained list elsewhere.

```text
actions:
  set_climate:  { power: bool, target_temp_c: int[16,28], fan_speed: int[0,5] }
  set_window:   { window: enum[front_left,front_right,rear_left,rear_right,all],
                   position: int[0,100] }
  set_lights:   { light: enum[headlights,interior,hazard], state: bool }
  set_door_lock:{ door: enum[all,driver,passenger,rear_left,rear_right], locked: bool }
  get_status:   {}
```

Deliberately **not** in the catalog: any action that controls vehicle speed,
steering, or braking — the DSL only exposes comfort/infotainment actuators
(least privilege by omission, not by runtime filtering).

## 2.3. `LLMAction` schema (`app/core/schemas.py`)

A strict Pydantic model the LLM's raw JSON output must conform to before any
further processing:

```text
LLMAction (extra="forbid"):
  action: str
  params: dict[str, Any]
  reasoning: str | None = None
```

`extra="forbid"` rejects any unexpected field outright — the LLM cannot smuggle
additional instructions/data through extra JSON keys. `reasoning` is carried
only for observability/debugging; it is never used to make an authorization
decision.

## 2.4. `Ctx` (`app/core/schemas.py`)

A per-request context envelope, generated fresh inside
`SecureSDKCore.handle_request()`:

```text
Ctx:
  session_id: str        # generated once per SecureSDKCore instance
  policy_id: str          # from the active policy bundle (vehicle_default.json)
  trace_id: str           # generated at the very start of handle_request(),
                            # before authentication, so early rejections are
                            # audited too
  deadline_ms: int        # from the active policy bundle; overrides the
                            # Ollama client's default read timeout for this call
  canary_token: str       # unique per request; injected into the prompt and
                            # checked against the raw LLM output (§3.1 step 5.f)
```

## 2.5. `ErrorCode` (`app/core/schemas.py`)

```text
ErrorCode: UNAUTHENTICATED | POLICY_VIOLATION | INVALID_INPUT |
           RESOURCE_LIMIT | INTERNAL_ERROR
```

Every `BLOCKED` `ActionResult` carries exactly one of these. The response
message returned to the caller is `"@SECURITY_VIOLATION@ {error_code}"` — a
deterministic, SDK-generated string, never the LLM's own `reasoning` text.

## 3.1. Secure pipeline (`app/core/sdk_core.py`, `SecureSDKCore`)

`SecureSDKCore` is **not** a module-level singleton (unlike `hal`): it is
constructed via dependency injection (`hal`, `ollama_client`, `audit_log`,
`sdk_token`, `dsl_catalog`, `policy`), holding only `_session_id` and
`_last_request_ts` as internal mutable state.

`handle_request(prompt, provided_token) -> ActionResult` pipeline steps:

```text
0.     Authentication — hmac.compare_digest(provided_token, sdk_token).
0-bis. Rate-limit cooldown — time.monotonic() vs. policy["rate_limit_cooldown_s"].
1.     Ctx creation (trace_id generated even earlier, at the top of the
       method, so steps 0/0-bis can also be audited).
2.     Ingress sanitization (app/core/sanitizer.py).
3.     Structural prompt encapsulation: dynamically-generated DSL catalog
       description + canary token instruction + anti-fusion delimiters
       (`=== USER_INPUT_{trace_id} START/END ===`) wrapping the untrusted
       user text.
4.     Ollama call via the injected OllamaClient.generate(), with
       ctx.deadline_ms overriding the client's default read timeout.
5.a    Transport-level failure -> RESOURCE_LIMIT (timeout) or INTERNAL_ERROR.
5.b    JSON parse, with one fallback attempt (extract the first balanced
       `{...}` block) if strict `json.loads()` fails -> INVALID_INPUT.
5.c    Pydantic schema validation (LLMAction, extra="forbid") -> INVALID_INPUT.
5.d/e  DSL whitelist + type/range validation (app/core/dsl_validator.py) —
       strict rejection, no clamping -> POLICY_VIOLATION.
5.f    Canary leak check on the RAW output text (before parsing) ->
       POLICY_VIOLATION.
5.g    Contextual/stateful policy: e.g. `set_window`/`set_door_lock` locked
       while `hal.get_environment().vehicle_speed_kmh` exceeds
       `policy["contextual_rules"]["speed_lockout_kmh"]` -> POLICY_VIOLATION.
6.     Execution against the HAL (`hal.apply_action()`).
7-8.   Audit log entry + deterministic ActionResult.
```

Design notes:
- `hal.get_environment()` returns a **copy** (`dataclasses.replace(...)`) of
  the live `EnvironmentState`, not a live reference — the contextual policy
  check must not be able to mutate HAL state through the object it reads.
- `rate_limit_cooldown_s` and `deadline_ms` live in the versioned
  `vehicle_default.json` policy bundle, not in `.env` — these are auditable
  security-relevant policy values, not secrets/infrastructure endpoints.
- The cooldown clock is set in step 0-bis for every *authenticated* request,
  even ones later blocked in microseconds by the sanitizer/DSL layers — this
  is intentional: the rate limiter throttles request *attempts*, not only
  successful ones.

## 3.4. Audit log (`app/core/audit_log.py`)

Append-only, hash-chained JSONL file (`logs/audit.log`, gitignored). Each
entry:

```text
{ seq, timestamp, trace_id, mode, prompt_sha256, verdict, error_code, action,
  prev_hash, entry_hash }
```

- `prompt_sha256`: SHA-256 of the raw prompt — the log stores no plaintext
  user input.
- `entry_hash = HMAC-SHA256(secret, canonical_json(entry_without_entry_hash))`,
  where `canonical_json` is
  `json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
  — a fixed, deterministic serialization so the same entry always hashes to
  the same value.
- `prev_hash` chains each entry to the previous one; the chain starts from a
  genesis hash of 64 zeros and is never reset while the log file exists
  (`_read_last_state()` resumes from the last line on restart).
- `verify_chain()` recomputes every entry's HMAC and validates `prev_hash`
  continuity from genesis — any single tampered field, in any past entry,
  breaks verification for that entry and all entries after it.

## 3.2, 5.x–6.x

*(pending — will be added as each phase is implemented; §3.2, the vulnerable
pipeline, is intentionally out of scope for Phase 3)*

## 3.5. Server (`app/server/main.py`, Phase 4 scope)

Phase 4 implements REST endpoints only — no WebSocket/telemetry background
task (Phase 5) and no vulnerable-mode router (Phase 7) are mounted yet.

- **Lifecycle**: FastAPI's `lifespan` async context manager (not the
  deprecated `@app.on_event`) creates a single `OllamaClient`, calls
  `ensure_model_available()` (fail-fast: aborts startup if the model is
  missing), a single `AuditLog`, and a single `SecureSDKCore` — all stored on
  `app.state`. On shutdown, `ollama_client.aclose()` is awaited. `hal` is
  imported directly as the existing module-level singleton (same pattern as
  every previous phase), not re-wired through `app.state`.
- **Auth architecture** — two distinct mechanisms, deliberately not unified:
  - `POST /api/secure/chat`: **no** route-level auth guard. The
    `X-SDK-Token` header is read and passed straight through to
    `SecureSDKCore.handle_request()`, whose own step 0 already performs the
    constant-time check and audits failures under a `trace_id` — a
    route-level guard placed in front of it would either duplicate that
    check or (if it short-circuits) silently drop `UNAUTHENTICATED` attempts
    from the audit trail.
  - `POST /api/scenario/set`: this route does **not** go through
    `SecureSDKCore`, so it has its own FastAPI dependency
    (`_verify_sdk_token`, `hmac.compare_digest`) that raises
    `HTTPException(401)` on failure.
  - `GET /api/state` and `POST /api/reset` are intentionally unauthenticated,
    per the design spec's auth scoping (only `/api/secure/*` and
    `/api/scenario/*` require the token).
- **Response codes**: `/api/secure/chat` always returns HTTP `200`, with the
  verdict (`ALLOWED`/`BLOCKED`) and `error_code` (including
  `UNAUTHENTICATED`, `RESOURCE_LIMIT`, etc.) carried in the JSON body — the
  HTTP layer is a thin transport, the SDK's own deterministic verdict is the
  single source of truth. `/api/scenario/set` uses a conventional HTTP `401`
  for auth failures, since it has no equivalent `ActionResult` contract.
- **Serialization**: HAL state (`hal.vehicle`, `hal.get_environment()`,
  `hal.get_telemetry()`) and `ActionResult` are serialized with
  `dataclasses.asdict()`, not Pydantic — Pydantic stays scoped to the LLM I/O
  boundary (`LLMAction`) as established in Phase 3. Request bodies
  (`ChatRequest`, `ScenarioSetRequest`) do use minimal Pydantic models, since
  FastAPI requires them to parse/validate incoming JSON — this is the HTTP
  boundary, not the LLM boundary, so it does not conflict with that rule.
- **`hal.reset()`** (added this phase): resets **both** `VehicleState` and
  `EnvironmentState` to their defaults (not just actuators), so that Red
  Teaming runs (Phase 9) start from a fully known baseline even after a
  scenario like `vehicle_speed_kmh=180` was set in a previous test.
- Endpoints implemented this phase:
  - `GET /api/state` → `{vehicle, environment, telemetry}` snapshot.
  - `POST /api/reset` → resets HAL, returns the resulting snapshot.
  - `POST /api/scenario/set {vehicle_speed_kmh?, outside_temp_c?}` → token
    required.
  - `POST /api/secure/chat {prompt}` → delegates to `SecureSDKCore`.


