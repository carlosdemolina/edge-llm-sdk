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

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from app.config import SDK_TOKEN
from app.hal.hal import hal

router = APIRouter()


def _state_snapshot() -> dict:
    return {
        "vehicle": asdict(hal.vehicle),
        "environment": asdict(hal.get_environment()),
        "telemetry": asdict(hal.get_telemetry()),
    }


def _verify_sdk_token(x_sdk_token: str | None = Header(default=None)) -> None:
    """Shared auth guard for routes that do NOT go through SecureSDKCore
    (which already does its own constant-time check + audit logging).
    """
    if not hmac.compare_digest(x_sdk_token or "", SDK_TOKEN):
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED")


@router.get("/api/state")
async def get_state() -> dict:
    return _state_snapshot()


@router.post("/api/reset")
async def reset_state() -> dict:
    await hal.reset()
    return _state_snapshot()


class ScenarioSetRequest(BaseModel):
    vehicle_speed_kmh: int | None = None
    outside_temp_c: int | None = None


@router.post("/api/scenario/set", dependencies=[Depends(_verify_sdk_token)])
async def set_scenario(body: ScenarioSetRequest) -> dict:
    await hal.set_environment(
        vehicle_speed_kmh=body.vehicle_speed_kmh,
        outside_temp_c=body.outside_temp_c,
    )
    return _state_snapshot()
