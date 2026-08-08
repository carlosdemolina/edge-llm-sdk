"""FastAPI application entrypoint (see docs/DESIGN_SPEC.md §3.5).

Phase 5 scope adds the WebSocket telemetry broadcast loop on top of Phase 4's
REST endpoints. No vulnerable-mode router mounted yet (Phase 7).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.config import (
    AUDIT_LOG_HMAC_SECRET,
    AUDIT_LOG_PATH,
    OLLAMA_HOST,
    OLLAMA_MODEL,
    SDK_TOKEN,
)
from app.core.audit_log import AuditLog
from app.core.sdk_core import SecureSDKCore
from app.hal.hal import hal
from app.llm.ollama_client import OllamaClient
from app.server import routes_common, routes_secure
from app.server.ws_manager import manager

POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"

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

    audit_log = AuditLog(path=AUDIT_LOG_PATH, hmac_secret=AUDIT_LOG_HMAC_SECRET)
    dsl_catalog = json.loads((POLICIES_DIR / "dsl_actions.json").read_text())
    policy = json.loads((POLICIES_DIR / "vehicle_default.json").read_text())

    app.state.ollama_client = ollama_client
    app.state.audit_log = audit_log
    app.state.secure_core = SecureSDKCore(
        hal=hal,
        ollama_client=ollama_client,
        audit_log=audit_log,
        sdk_token=SDK_TOKEN,
        dsl_catalog=dsl_catalog,
        policy=policy,
    )
    # Vulnerable-mode counters are pre-declared even though nothing increments
    # them until Phase 7, matching the final §3.5 metrics payload shape.
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
