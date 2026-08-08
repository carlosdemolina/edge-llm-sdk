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

## 3.4-bis. Developer debug trace (`app/core/debug_log.py`, `SDK_DEBUG_MODE`)

A **developer tool, deliberately not a production security feature** —
contrasted explicitly with §3.4's `AuditLog`:

| | `AuditLog` (§3.4) | `DebugTraceLog` (this section) |
|---|---|---|
| Purpose | Production security control | Developer/TFM tooling (model & policy iteration, future test-bench) |
| Prompt storage | `prompt_sha256` only, never plaintext | Full plaintext prompt, final encapsulated prompt, and raw LLM output |
| Integrity | HMAC hash-chained, tamper-evident | No chain — a plain JSONL append log |
| Enabled | Always | Only when `SDK_DEBUG_MODE=true` (off by default); `logs/*` is gitignored either way |
| Exposed to | Nothing reads it back over HTTP | `GET /api/debug/traces` (token-gated), rendered in the dashboard's Admin/Debug tab |
| Clearable | No — `AuditLog` has no delete/clear endpoint by design (tamper-evident chain must never be truncated) | Yes — `DELETE /api/debug/traces` (token-gated, 404 when debug mode is off) truncates `logs/debug_trace.jsonl` via `DebugTraceLog.clear()`; safe since this file carries no integrity chain and no production role. Frontend gates it behind a `confirm()` dialog since it's destructive and irreversible. |


Rationale for a coarse, uniform `error_code` in the chat's own response
(§2.5) still holds unchanged: `ActionResult.message` never reveals which
pipeline layer blocked a request, to avoid handing an oracle to whoever is
typing prompts into the chat (the same untrusted party the pipeline
defends against). The debug trace is a **separate, server-operator-gated
channel** (`SDK_DEBUG_MODE`, a deployment-time switch never controllable by
the chat caller/prompt) — it does not weaken that guarantee, since a real
release simply ships with the switch off.

- **`PipelineStageTrace`** (`app/core/schemas.py`): one entry per pipeline
  step (`authentication`, `rate_limit_cooldown`, `ctx_creation`,
  `sanitization`, `prompt_encapsulation`, `ollama_call`, `json_parse`,
  `schema_validation`, `dsl_whitelist_range`, `canary_leak_check`,
  `contextual_policy`, `execution`), each with `status`
  (`passed`/`blocked`/`skipped`), an optional `detail` string, and
  `duration_ms` timed since the previous stage. `routes_vulnerable.py`
  (Phase 7) reuses the exact same stage names, marking the ones it
  deliberately does not run as `skipped` (rather than omitting them), so
  both pipelines' stage lists line up 1:1 for direct comparison; it also
  adds one extra stage, `type_check`, for its lightweight `isinstance`
  check (in place of `schema_validation`, which it always marks `skipped`).
- **`DebugTrace`**: the full per-request trace — `stages`, the final
  encapsulated `final_prompt` sent to Ollama, the LLM's `raw_llm_output`,
  the `parsed_llm_action` (pre-Pydantic-validation JSON), `ollama_metrics`
  (Ollama's own `total_duration`/`load_duration`/`prompt_eval_count`/
  `prompt_eval_duration`/`eval_count`/`eval_duration`, in nanoseconds —
  present in every non-streaming `/api/generate` response at no extra cost),
  `sdk_total_duration_ms` (the whole `handle_request()` call, so the
  pipeline's own overhead can be separated from Ollama's inference time),
  a CPU/RAM snapshot (`psutil`) taken at the very start and very end of the
  request, and `pipeline` (`"secure"` | `"vulnerable"`, Phase 7) so the
  Admin/Debug tab and `debug_trace.jsonl` can distinguish and compare
  entries from either pipeline in the same file.
- **Known limitation, documented rather than engineered around**:
  `psutil.cpu_percent(interval=None)` measures usage *since the last call
  anywhere in the process* — the Phase 5 telemetry broadcast loop also
  samples it every second in the background, so the CPU delta attributed to
  a single debug-traced request is an approximation, not a perfectly
  isolated per-request measurement.
- `SecureSDKCore` accepts `debug_mode: bool = False` and
  `debug_log: DebugTraceLog | None = None`; when off, every debug-related
  call in `handle_request()` is a no-op (`_mark_stage()`/
  `_finalize_debug_trace()` short-circuit on `debug_ctx is None`), so
  `ActionResult.debug` is always `None` and no file is ever written.
- `GET /api/debug/status` (unauthenticated — only reveals the boolean
  switch, no trace content) lets the frontend decide whether to show the
  Admin/Debug tab at all. `GET /api/debug/traces` (token-gated, `404` when
  debug mode is off) returns the last N entries for the dashboard's
  historical view — chosen over relying only on in-browser memory so the
  history survives page reloads, matching the explicit requirement that
  these traces double as raw material for a future automated test bench.

## 3.4-ter. Audit visibility panel (Phase 8)

`AuditLog` (§3.4) has existed since Phase 4/5 as a write-only, tamper-evident
record — nothing ever read it back. Phase 8 adds a **read-only, always-on**
dashboard panel so every attempt (blocked or allowed, either pipeline) is
visible with its verdict and chained hash, without weakening the log's
append-only guarantees:

- **`AuditLog.read_last(limit: int) -> list[dict]`** (new method,
  `app/core/audit_log.py`): reads the file under the same `asyncio.Lock`
  used by `append()`, slices the last `limit` lines, and returns them
  newest-first. Mirrors `DebugTraceLog.read_last()` exactly. Purely
  additive — does not touch `append()` or `verify_chain()`.
- **`GET /api/audit/entries?limit=N`** and **`GET /api/audit/verify`**
  (`app/server/routes_common.py`), both token-gated
  (`Depends(_verify_sdk_token)`) but, unlike `GET /api/debug/traces`,
  **never gated by `SDK_DEBUG_MODE`** — the audit log is a production
  feature, not a developer tool, so its visibility endpoints are always
  available to any authenticated caller. `/api/audit/verify` simply returns
  `{"valid": bool}` from the existing `verify_chain()`.
- **Frontend**: a prominent "Auditoría" button in the dashboard header (next
  to Reset, not tucked into the Admin/Debug tab) opens a modal overlay
  (`#audit-modal` in `frontend/index.html`) listing recent entries — each
  rendered as a compact card with `seq`, timestamp, a `[secure]`/
  `[vulnerable]` mode badge, a colored verdict (`ALLOWED`/`BLOCKED`),
  `action`/`error_code`, a truncated `trace_id`, and truncated
  `entry_hash`/`prev_hash` so the chain linkage is visible at a glance. A
  "Verificar cadena" button calls `/api/audit/verify` on demand and shows
  `Cadena OK` / `Cadena ROTA`. Deliberately the opposite placement choice
  from the Admin/Debug tab (§3.4-bis, `SDK_DEBUG_MODE`-gated, developer-only,
  intentionally unobtrusive): the audit panel is a production
  accountability feature meant to be discoverable, so it gets its own
  always-visible header button.

## 3.2. Vulnerable pipeline (`app/server/routes_vulnerable.py`, Phase 7)

`POST /api/vulnerable/chat` exists purely as a controlled, side-by-side
counter-example to `SecureSDKCore` — a quantifiable "before/after" for the
TFM's case study, never a code path meant to be hardened later. It reuses
the same `hal`, the same `OllamaClient` (still serialized behind its shared
`asyncio.Semaphore(1)`), and the same `AuditLog` (tagged `mode="vulnerable"`)
as the secure pipeline, but wires them together with almost none of
`SecureSDKCore`'s defense layers:

| Layer | Secure (`sdk_core.py`) | Vulnerable (`routes_vulnerable.py`) |
|---|---|---|
| Auth | `hmac.compare_digest` on `X-SDK-Token`, step 0 | `X-SDK-Token` read but **never checked** |
| Rate limiting | cooldown gate (0-bis) | none |
| Ingress sanitization | deny-patterns + length cap | none |
| System prompt | full DSL catalog description + anti-fusion delimiters | one line, **no** action catalog at all |
| Inference sampling | forced deterministic (`temperature=0`, `top_k=1`, `top_p=0.1`) | Ollama's own documented defaults (`temperature=0.8`, `top_k=40`, `top_p=0.9`) — also demonstrates non-deterministic output |
| Egress schema | strict `LLMAction` (Pydantic, `extra="forbid"`) | only checks `action` is `str` and `params` is `dict` |
| DSL whitelist/range | reject on any mismatch | none — calls `hal.apply_action()` directly |
| Canary leak check | blocks if canary appears in raw output | **never checked** — if leaked, it flows straight into the response `message` |
| Contextual/state policy (5.g, speed lockout) | enforced | none |
| HAL type-check/clamp | applies (defense in depth) | still applies — stability net, not a security control |

- **Response shape reuse (deliberate simplification)**: the endpoint
  returns the same `ActionResult`/`ErrorCode` shape as the secure pipeline,
  so the frontend's chat-rendering code is identical between modes. This is
  a simplification, not a claim of equivalence: a `BLOCKED` verdict here
  only ever reflects a technical failure (unparseable JSON, timeout, an
  action name the HAL doesn't implement) — there is no deliberate security
  check in this module that could "block" anything on purpose. The
  `@SECURITY_VIOLATION@` message prefix is reused verbatim for the same
  reason (simplicity over precision).
- **Canary/`reasoning` deliberately exposed on success**: unlike the secure
  pipeline (which never surfaces the LLM's `reasoning`), a successful
  vulnerable response echoes the model's own `reasoning` (or, failing that,
  the raw output text) back in `message` — this is what makes a canary leak
  or a successful prompt injection *visible* in the chat, which is the point
  of the Red Teaming comparison (§3.7/Phase 9).
- **No DSL catalog in the system prompt — empirical finding**: because the
  vulnerable prompt never lists valid actions (§3.2 of
  `Implementacion_Capitulo6.md` specifies this minimal prompt deliberately),
  the model frequently invents action names that don't exist in `hal.py`
  (e.g. `open_front_left_sleeper`, `open_sunroof`) rather than the real
  `set_window`. The HAL's fixed, hardcoded action set means this is
  rejected as `unknown_action` regardless — i.e. even the *vulnerable* mode
  cannot make the LLM execute an action the HAL doesn't implement. When a
  prompt names the real action explicitly (a plausible attacker who already
  knows the internal schema, e.g. from reverse engineering or leaked docs),
  the bypass is real and reproducible: validated on-device by setting
  `vehicle_speed_kmh=180` via `/api/scenario/set` and sending a prompt that
  asks for `{"action": "set_window", ...}` — the secure pipeline blocks it
  (`POLICY_VIOLATION`, stage `contextual_policy`/`speed_lockout`, or earlier
  at `sanitization` if the prompt also matches an injection deny-pattern),
  while the vulnerable endpoint executes it and the HAL state confirms all
  four windows open to 100% at 180 km/h. This distinction (fixed action
  space vs. semantic/contextual validation) is worth keeping explicit for
  Phase 9's Red Teaming catalog design.
- **Debug-trace instrumentation, tagged `pipeline="vulnerable"`**:
  `routes_vulnerable.py` duplicates the same accumulator/mark-stage/finalize
  pattern used by `SecureSDKCore` (rather than sharing an instance, since
  this module is function-based, not a class) and writes to the *same*
  `DebugTraceLog`/`logs/debug_trace.jsonl` as the secure pipeline, only when
  `SDK_DEBUG_MODE=true`. Every stage the secure pipeline runs that this one
  intentionally skips (`authentication`, `rate_limit_cooldown`,
  `sanitization`, `prompt_encapsulation`, `schema_validation`,
  `dsl_whitelist_range`, `canary_leak_check`, `contextual_policy`) is still
  recorded, with `status="skipped"` and a `detail` explaining why — this
  lets the Admin/Debug tab and any future test-bench tooling compare both
  pipelines' traces stage-by-stage, rather than only comparing final
  verdicts. This is purely a developer/observability aid, gated the same
  way as the secure pipeline's tracing (`SDK_DEBUG_MODE`, off by default);
  it adds no security behavior of its own.

## 3.5. Server (`app/server/main.py`, Phases 4–5, 7 scope)

Phase 4 implemented the REST endpoints. Phase 5 (below) adds the WebSocket
telemetry broadcast loop on top of them. Phase 7 mounts the vulnerable-mode
router (`routes_vulnerable.router`) alongside the secure one.

- **Lifecycle**: FastAPI's `lifespan` async context manager (not the
  deprecated `@app.on_event`) creates a single `OllamaClient`, calls
  `ensure_model_available()` (fail-fast: aborts startup if the model is
  missing), a single `AuditLog`, and a single `SecureSDKCore` — all stored on
  `app.state`. On shutdown, `ollama_client.aclose()` is awaited. `hal` is
  imported directly as the existing module-level singleton (same pattern as
  every previous phase), not re-wired through `app.state`.
- **Startup warm-up (post-Phase 6 addendum)**: right after
  `ensure_model_available()`, `lifespan` fires
  `ollama_client.warm_up(OLLAMA_KEEP_ALIVE)` as a background
  `asyncio.create_task` (reference kept to avoid premature GC, never
  awaited) — a trivial `"ping"` completion that absorbs Ollama's ~8-12s
  cold-start model load *before* the first real user chat request arrives,
  instead of that request risking a `RESOURCE_LIMIT` timeout. It is
  best-effort: exceptions are swallowed and logged, never raised — the real
  fail-fast startup guard remains `ensure_model_available()`. `keep_alive`
  (an Ollama duration string, default `"5m"` via `OLLAMA_KEEP_ALIVE` in
  `app/config.py`) deliberately keeps the model resident only for a bounded
  window rather than `"-1"` (forever) — this is a prototype demo, not a
  24/7 service, so permanently pinning RAM on the Pi was rejected.
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
  - `GET /api/debug/status` is also unauthenticated (reveals only the
    `SDK_DEBUG_MODE` boolean, never trace content); `GET /api/debug/traces`
    uses the same `_verify_sdk_token` dependency as `/api/scenario/set` and
    `404`s whenever debug mode is off (see §3.4-bis).
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
- Endpoints implemented in Phase 4:
  - `GET /api/state` → state snapshot (shape extended in Phase 5, see below).
  - `POST /api/reset` → resets HAL, returns the resulting snapshot.
  - `POST /api/scenario/set {vehicle_speed_kmh?, outside_temp_c?}` → token
    required.
  - `POST /api/secure/chat {prompt}` → delegates to `SecureSDKCore`.

### Phase 5: WebSocket telemetry

- **`app/server/ws_manager.py`** (`ConnectionManager`, module-level singleton
  `manager`): tracks active `WebSocket` connections and broadcasts messages
  to all of them. Deliberately has **no** knowledge of HAL, metrics, or any
  business logic — it only stores connections and pushes pre-built dicts.
  This keeps it dependency-free so both `routes_common.py` (which owns the
  `/ws/telemetry` endpoint) and `main.py` (which owns the broadcast loop)
  can import it without a circular import.
  - `connect(websocket)`: accepts and registers.
  - `disconnect(websocket)`: removes if present (idempotent).
  - `broadcast(message)`: iterates a **copy** of the connection list (the
    live list is mutated by `disconnect()`, which would otherwise corrupt an
    in-progress iteration); a send failure (e.g. an abrupt/ungraceful client
    disconnect) is caught and treated as a disconnect rather than
    propagating and killing the broadcast loop for all other clients.
- **`build_state_snapshot(metrics: dict) -> dict`** (`routes_common.py`,
  public — renamed from the Phase 4 private `_state_snapshot()`): now also
  includes a `"metrics"` key, so `GET /api/state`, `POST /api/reset`,
  `POST /api/scenario/set`, and the WS broadcast loop all share one single
  source of truth for the snapshot shape — REST and WS must never diverge.
  Final shape: `{vehicle, environment, telemetry, metrics}`.
- **`GET /ws/telemetry`** (`routes_common.py`): accepts the connection via
  `manager.connect()`, then blocks on `receive_text()` in a loop purely to
  detect disconnection (`WebSocketDisconnect`) — this is a push-only
  channel, the server never expects client messages.
- **Telemetry loop** (`app/server/main.py`, `_telemetry_loop`): a background
  `asyncio.Task` created in `lifespan` startup, cancelled (and awaited,
  suppressing `CancelledError`) in `lifespan` shutdown. Every
  `TELEMETRY_INTERVAL_S` (1.0 s) it broadcasts a fresh snapshot — but
  **skips building/broadcasting entirely if `manager.active_connections` is
  empty**, to avoid needless `psutil` telemetry reads on the Pi when no
  dashboard is open.
- **Metrics**: `app.state.metrics = {"secure": {"allowed": 0, "blocked": 0},
  "vulnerable": {"allowed": 0, "blocked": 0}}`, initialized once in
  `lifespan` startup as plain in-memory counters (not derived by scanning the
  audit log — cheaper, and the audit log's purpose is tamper-evident
  forensics, not a live dashboard feed). `routes_secure.py` increments
  `metrics["secure"]["allowed"]` or `["blocked"]` once per `/api/secure/chat`
  call, based on `result.verdict`. `routes_vulnerable.py` increments the
  `vulnerable` counters the same way (Phase 7).
- **Race-condition analysis (considered, discarded)**: whether
  `build_state_snapshot()` needs its own HAL lock/deep-copy accessor to avoid
  reading mid-mutation state concurrently with `apply_action()`. Concluded
  unnecessary: neither function contains an internal `await` point, so
  Python's single-threaded cooperative asyncio scheduling guarantees each
  runs to completion without interleaving.
- **Validated behavior**: WS client receives snapshots at ~1 s cadence with
  the `{vehicle, environment, telemetry, metrics}` shape; an abrupt
  (non-graceful) client disconnect is caught by `broadcast()`'s try/except
  and removed from `active_connections` without crashing the server or
  affecting other connections; `/api/secure/chat` calls are reflected in
  `metrics.secure` in the next broadcast tick (i.e. eventually consistent
  within ~1 s, not synchronously pushed on every action — acceptable for a
  dashboard use case).

### Phase 6: Minimal frontend (`frontend/`)

- **Static serving**: `app/server/main.py` mounts `frontend/` as
  `StaticFiles(html=True)` at `"/"`, registered **after** both API routers,
  so the explicit REST/WS routes always take precedence over the
  catch-all static mount. Serving the dashboard from the same FastAPI
  process/origin as the API means **zero CORS configuration** is needed.
- **Tailwind CSS, compiled locally, no Node/npm**: the Raspberry Pi has
  neither `node` nor `npm` installed. Rather than installing Node (needs
  `sudo`, more disk) or relying on the Tailwind Play CDN (would need
  internet access at demo time — unacceptable for an edge/offline-first
  prototype), the standalone Tailwind v4 CLI binary
  (`tailwindcss-linux-arm64`, from Tailwind's official GitHub releases) was
  downloaded into a git-ignored `tools/` directory. `frontend/css/input.css`
  (`@import "tailwindcss";` plus explicit `@source` directives pointing at
  `index.html`/`js/*.js`, since there is no `node_modules` context for
  automatic content detection to anchor on) is compiled once into the
  committed, minified `frontend/css/tailwind.css` via
  `tools/tailwindcss -i frontend/css/input.css -o frontend/css/tailwind.css --minify`.
  This build step is manual/on-demand (re-run whenever a new utility class
  is added to the markup), not wired into the server startup.
- **`X-SDK-Token` handling**: never hardcoded in the shipped JS. The
  dashboard has a password-type input where the operator pastes the token
  once per browser tab; `dashboard.js` stores it in `sessionStorage` only
  (cleared when the tab closes, never `localStorage`, never a cookie) and
  attaches it as the `X-SDK-Token` header on both `/api/secure/chat` and
  `/api/scenario/set` calls.
- **`frontend/js/ws_client.js`**: a minimal `connectTelemetry(onMessage,
  onStatusChange)` helper — opens the WS, forwards parsed JSON messages, and
  flips a connected/disconnected status callback. Deliberately has **no**
  auto-reconnect/backoff loop: a dropped connection just surfaces as
  "Desconectado" in the header. Robust reconnection is explicitly reserved
  for Phase 10 hardening, per the implementation plan's own phase split.
- **`frontend/js/dashboard.js`**: renders the `{vehicle, environment,
  telemetry, metrics}` snapshot (shared by the initial `GET /api/state` call
  on page load — so the dashboard isn't blank for the ~1 s until the first
  WS broadcast — and every subsequent WS message, through the same
  `renderState()` function); drives the Reset button (`POST /api/reset`),
  the Scenario Control Panel (`POST /api/scenario/set`, operator-only,
  token-gated), and the chat panel (`POST /api/secure/chat`, token-gated,
  with a "Verificando respuesta…" indicator while awaiting the response,
  consistent with the no-streaming design decision). Chat history is a
  plain in-memory array, purely cosmetic client-side state — never resent to
  the server as context (the LLM pipeline is stateless per request) — and
  only ever renders the SDK's own `verdict`/`message`/`error_code` fields,
  never an LLM `reasoning` field (which `ActionResult` does not even
  expose).
- **Vehicle actuator panel is read-only** in this phase: climate, windows,
  lights, and door locks are only ever changed by the LLM via chat
  (`apply_action()`); the operator's Scenario Control Panel only ever
  touches `EnvironmentState` (`vehicle_speed_kmh`, `outside_temp_c`), never
  actuators — mirroring the strict separation already enforced server-side.
- **Validated behavior**: chat actions (e.g. "enciende las luces
  interiores") update the corresponding actuator card and the
  `metrics.secure` counters within one WS broadcast tick; scenario changes
  update the speedometer/outside-temp cards immediately (from the endpoint's
  own response, not waiting for the next WS tick); a missing/invalid token
  surfaces a clear inline message for both the chat and scenario forms
  (`401`/`UNAUTHENTICATED` are never silently swallowed); Reset restores all
  cards to their default values.

### Phase 7: Vulnerable mode + toggle

- **`app/server/routes_vulnerable.py`** (new): implements `POST
  /api/vulnerable/chat` as described in §3.2 above. Mounted in `main.py` via
  `app.include_router(routes_vulnerable.router)`, alongside
  `routes_common`/`routes_secure`.
- **Frontend toggle** (`frontend/index.html` + `dashboard.js`): a checkbox
  (`#vulnerable-mode-toggle`) in the chat panel header switches
  `handleChatSubmit()` between `/api/secure/chat` (token attached) and
  `/api/vulnerable/chat` (token header omitted entirely, not sent empty, to
  simulate a caller with no credentials at all). The panel title and a red
  warning banner (`#vulnerable-mode-warning`) update via a `change` listener
  so the active mode is always visually unambiguous. Chat history entries
  are tagged with their mode and rendered with a `[VULNERABLE]` prefix.
- **Metrics panel**: a second `metrics-vulnerable-allowed/blocked` block
  mirrors the existing secure one, both fed from the same `GET /api/state`
  snapshot (`metrics.vulnerable`).
- **Debug-trace refresh guard**: the Admin/Debug tab's auto-refresh after a
  chat submission (§3.4-bis) fires for submissions from either pipeline —
  the vulnerable endpoint gained its own debug-trace instrumentation (see
  the addendum in `docs/phases/phase-7.md`), tagged `pipeline="vulnerable"`
  so both pipelines' traces coexist in `debug_trace.jsonl` and are
  distinguished by a `[SEGURO]`/`[VULNERABLE]` badge in the tab.
- **Validated on-device** (with `SDK_DEBUG_MODE=true`, so every attempt is
  recorded for audit): `POST /api/vulnerable/chat` succeeds with no
  `X-SDK-Token` at all; a benign prompt with no DSL catalog guidance often
  yields a hallucinated action name rejected by the HAL as `unknown_action`;
  the explicit speed-lockout bypass (see §3.2) reproduced the expected
  contrast — `BLOCKED`/`POLICY_VIOLATION` on `/api/secure/chat` vs.
  `ALLOWED` with the HAL's window state actually mutated to 100% at 180
  km/h on `/api/vulnerable/chat`; `metrics.secure`/`metrics.vulnerable` and
  `logs/audit.log` entries (tagged `mode="secure"`/`"vulnerable"`) were
  confirmed consistent with each test's outcome.

### Phase 8: Audit visibility panel

- **`AuditLog.read_last()`** (`app/core/audit_log.py`) and two new
  always-available, token-gated endpoints — `GET /api/audit/entries` and
  `GET /api/audit/verify` (`app/server/routes_common.py`) — as described in
  §3.4-ter above.
- **Frontend**: `#audit-open-btn` header button + `#audit-modal` overlay
  (`frontend/index.html`); `renderAuditEntry()`, `fetchAuditEntries()`,
  `fetchVerifyChain()`, `initAuditModal()` (`frontend/js/dashboard.js`)
  render entries and wire the open/close/refresh/verify controls.
- **Validated on-device**: `GET /api/audit/entries` returns `401` with no
  token and the expected entry list (with correctly chained
  `entry_hash`/`prev_hash`) with a valid token; `GET /api/audit/verify`
  returned `{"valid": true}` against the live `logs/audit.log`. In the
  browser, the "Auditoría" button opens the modal, entries from both
  `secure` and `vulnerable` pipelines render with the correct mode badge
  and verdict color, "Verificar cadena" shows "Cadena OK", and the close
  button/backdrop dismiss the modal correctly.

