"""Common REST routes: state snapshot, reset, and operator scenario control
(see docs/DESIGN_SPEC.md §3.5).

`GET /api/state` and `POST /api/reset` are intentionally unauthenticated, per
the design spec's auth scoping (only `/api/secure/*` and `/api/scenario/*`
require `X-SDK-Token`). `POST /api/scenario/set` is the one route in this
file that requires the token, since it is the human-operator control that
must never be reachable by the same channel the LLM/chat uses.
"""

from __future__ import annotations

import hmac
from dataclasses import asdict

from fastapi import APIRouter, Depends, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.config import SDK_TOKEN
from app.hal.hal import hal
from app.server.ws_manager import manager

router = APIRouter()


def build_state_snapshot(metrics: dict) -> dict:
    """Single source of truth for the vehicle/environment/telemetry/metrics
    view, shared by GET /api/state, POST /api/reset, and the WS telemetry
    broadcast loop (main.py) — REST and WS must never show two different
    shapes of the same state.
    """
    return {
        "vehicle": asdict(hal.vehicle),
        "environment": asdict(hal.get_environment()),
        "telemetry": asdict(hal.get_telemetry()),
        "metrics": metrics,
    }


def _verify_sdk_token(x_sdk_token: str | None = Header(default=None)) -> None:
    """Shared auth guard for routes that do NOT go through SecureSDKCore
    (which already does its own constant-time check + audit logging).
    """
    if not hmac.compare_digest(x_sdk_token or "", SDK_TOKEN):
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED")


@router.get("/api/state")
async def get_state(request: Request) -> dict:
    return build_state_snapshot(request.app.state.metrics)


@router.post("/api/reset")
async def reset_state(request: Request) -> dict:
    await hal.reset()
    return build_state_snapshot(request.app.state.metrics)


@router.websocket("/ws/telemetry")
async def ws_telemetry(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            # The server never expects a message from the client; this only
            # blocks until the client disconnects (or sends something, which
            # is ignored — this is a push-only channel).
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


class ScenarioSetRequest(BaseModel):
    vehicle_speed_kmh: int | None = None
    outside_temp_c: int | None = None


@router.post("/api/scenario/set", dependencies=[Depends(_verify_sdk_token)])
async def set_scenario(body: ScenarioSetRequest, request: Request) -> dict:
    await hal.set_environment(
        vehicle_speed_kmh=body.vehicle_speed_kmh,
        outside_temp_c=body.outside_temp_c,
    )
    return build_state_snapshot(request.app.state.metrics)


@router.get("/api/debug/status")
async def get_debug_status(request: Request) -> dict:
    """Unauthenticated on purpose: this only reveals whether the server-side
    `SDK_DEBUG_MODE` switch is on, so the frontend knows whether to show the
    Admin/Debug tab at all \u2014 no trace content is returned here.
    """
    return {"debug_mode": request.app.state.debug_mode}


@router.get("/api/debug/traces", dependencies=[Depends(_verify_sdk_token)])
async def get_debug_traces(request: Request, limit: int = 20) -> dict:
    """Developer-only endpoint: returns the last `limit` debug traces.

    404s when `SDK_DEBUG_MODE` is off, since `DebugTraceLog` isn't even
    instantiated in that case \u2014 this route only ever exposes anything on a
    server explicitly started with debug mode enabled.
    """
    debug_log = request.app.state.debug_log
    if debug_log is None:
        raise HTTPException(status_code=404, detail="Debug mode is disabled on this server")
    traces = await debug_log.read_last(limit)
    return {"traces": traces}

