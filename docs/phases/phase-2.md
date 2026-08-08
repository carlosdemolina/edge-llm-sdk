# Phase 2 — Isolated Ollama client

**Date:** 2026-08-08
**Status:** ✅ Completed (DoD validated)

## What was done

Implemented `app/llm/ollama_client.py` and `app/config.py`:

- **`app/config.py`**: loads `OLLAMA_HOST`/`OLLAMA_MODEL` from `.env` via `python-dotenv`.
- **`OllamaClient`**: thin async transport layer around Ollama's `/api/generate`
  and `/api/tags` — no JSON parsing/validation here (that belongs to
  `sdk_core.py`, Phase 3).
  - `ensure_model_available()`: fail-fast startup check against `/api/tags`.
  - `generate(prompt, config, timeout)`: serialized via `asyncio.Semaphore(1)`
    (shared regardless of secure/vulnerable caller — the Pi can only run one
    inference at a time). Split timeout: `connect=5.0s` (fail fast if Ollama
    is down), `read=30.0s` (accommodates the model's cold-start warm-up).
  - `aclose()`: explicit shutdown of the underlying `httpx.AsyncClient`.
- **Not a module-level singleton** (unlike `hal.py`): the client's lifecycle
  will be tied explicitly to the FastAPI app's startup/shutdown events in
  Phase 4; this phase's CLI script creates/closes its own instance.
- Manual CLI demo (`python -m app.llm.ollama_client`): runs the same fixed
  JSON-schema prompt 5 times with `temperature=0, top_k=1, top_p=0.1,
  format=json`, parses each response, reports success rate and latency
  breakdown (first call isolated from the rest).

## DoD validation

| Criterion | Result |
|---|---|
| 5 consecutive runs return parseable JSON | ✅ 5/5 |
| Average latency documented | ✅ see below |

## Measured latency (Raspberry Pi 5, `llama3.2:latest`, Q4_K_M)

| Call | Latency |
|---|---|
| 1st (cold start) | **11,251 ms** |
| 2nd–5th (avg) | **3,092 ms** (min 2,956 ms, max 3,318 ms) |

The first call is ~3.6x slower than the steady-state average — consistent
with Ollama loading model weights into memory after being idle. This is
expected hardware/runtime behavior, not a client defect, and is relevant for
sizing `deadline_ms` in later phases.

## Design decisions confirmed this phase

- `ollama_client.py` is a pure transport layer; JSON parsing/schema validation
  stays exclusively in `sdk_core.py` (Phase 3).
- `asyncio.Semaphore(1)` lives in the client (not in `sdk_core.py`), so
  serialization is enforced regardless of which pipeline calls it.
- Split `httpx.Timeout(connect=5.0, read=30.0, write=5.0, pool=5.0)` instead of
  a single uniform value, to fail fast on a down/unreachable Ollama service
  while still tolerating cold-start latency on real inference calls.
