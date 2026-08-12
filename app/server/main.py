"""FastAPI application entrypoint (see docs/ARCHITECTURE.md §3.5).

Wires together the REST routers (`routes_common`, `routes_secure`,
`routes_vulnerable`), the WebSocket telemetry broadcast loop, and the
static frontend mount into a single app, for a side-by-side secure/
vulnerable comparison against the same HAL/audit log.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import (
    AUDIT_LOG_HMAC_SECRET,
    AUDIT_LOG_PATH,
    DEBUG_TRACE_LOG_PATH,
    OLLAMA_HOST,
    OLLAMA_KEEP_ALIVE,
    OLLAMA_MODEL,
    SDK_DEBUG_MODE,
    SDK_TOKEN,
)
from app.core.audit_log import AuditLog
from app.core.debug_log import DebugTraceLog
from app.core.sdk_core import SecureSDKCore
from app.hal.hal import hal
from app.llm.ollama_client import OllamaClient
from app.server import routes_common, routes_secure, routes_vulnerable
from app.server.ws_manager import manager

POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

TELEMETRY_INTERVAL_S = 1.0


async def _telemetry_loop(app: FastAPI) -> None:
    """Broadcast the state snapshot to every connected WS client, once per
    `TELEMETRY_INTERVAL_S`. Skips building the snapshot entirely when no
    client is connected, to avoid needless psutil reads on the Pi.
    """
    while True:
        await asyncio.sleep(TELEMETRY_INTERVAL_S)
        if not manager.active_connections:
            continue
        await manager.broadcast(routes_common.build_state_snapshot(app.state.metrics))


@asynccontextmanager
async def lifespan(app: FastAPI):
    ollama_client = OllamaClient(host=OLLAMA_HOST, model=OLLAMA_MODEL)
    # Fail-fast: abort startup rather than fail silently on the user's first chat.
    await ollama_client.ensure_model_available()
    # Best-effort warm-up, fired in the background (NOT awaited) so it never
    # delays the server accepting connections: absorbs the ~8-12s cold-start
    # load time before the first real chat request, instead of that request
    # risking a RESOURCE_LIMIT timeout. Reference kept (not just fire-and-
    # forget) so asyncio doesn't garbage-collect the task mid-execution;
    # it is a one-shot task, so it needs no explicit cancellation at shutdown.
    warmup_task = asyncio.create_task(ollama_client.warm_up(OLLAMA_KEEP_ALIVE))

    audit_log = AuditLog(path=AUDIT_LOG_PATH, hmac_secret=AUDIT_LOG_HMAC_SECRET)
    dsl_catalog = json.loads((POLICIES_DIR / "dsl_actions.json").read_text())
    policy = json.loads((POLICIES_DIR / "vehicle_default.json").read_text())

    # Developer-only debug tracing (see docs/ARCHITECTURE.md): off by default.
    # When enabled, `DebugTraceLog` writes plain-text prompts/LLM output to a
    # git-ignored file — never a production security control, unlike AuditLog.
    debug_log = DebugTraceLog(path=DEBUG_TRACE_LOG_PATH) if SDK_DEBUG_MODE else None

    app.state.ollama_client = ollama_client
    app.state.audit_log = audit_log
    app.state.debug_mode = SDK_DEBUG_MODE
    app.state.debug_log = debug_log
    # Shared with the vulnerable pipeline (routes_vulnerable.py) so its system
    # prompt can document the same DSL catalog as the secure pipeline — the
    # catalog is API documentation, not a security control (see
    # app/core/prompt_catalog.py).
    app.state.dsl_catalog = dsl_catalog
    app.state.secure_core = SecureSDKCore(
        hal=hal,
        ollama_client=ollama_client,
        audit_log=audit_log,
        sdk_token=SDK_TOKEN,
        dsl_catalog=dsl_catalog,
        policy=policy,
        debug_mode=SDK_DEBUG_MODE,
        debug_log=debug_log,
    )
    app.state.metrics = {
        "secure": {"allowed": 0, "blocked": 0},
        "vulnerable": {"allowed": 0, "blocked": 0},
    }

    telemetry_task = asyncio.create_task(_telemetry_loop(app))

    yield

    telemetry_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await telemetry_task

    await ollama_client.aclose()


app = FastAPI(title="Edge LLM SDK — Vehicle IVC Prototype", lifespan=lifespan)

app.include_router(routes_common.router)
app.include_router(routes_secure.router)
app.include_router(routes_vulnerable.router)

# Registered last: a catch-all mount, so the explicit API/WS routes
# above always take precedence over static file serving. Same-origin serving
# means the dashboard needs no CORS configuration at all.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
