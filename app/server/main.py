"""FastAPI application entrypoint (see docs/DESIGN_SPEC.md §3.5).

Phase 4 scope: REST endpoints only. No WebSocket/telemetry background task
yet (Phase 5), and no vulnerable-mode router mounted yet (Phase 7).
"""

from __future__ import annotations

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

POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"


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

    yield

    await ollama_client.aclose()


app = FastAPI(title="Edge LLM SDK — Vehicle IVC Prototype", lifespan=lifespan)

app.include_router(routes_common.router)
app.include_router(routes_secure.router)
