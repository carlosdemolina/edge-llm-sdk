"""Secure chat route (see docs/ARCHITECTURE.md §3.5, §3.1).

No separate FastAPI-level auth guard is added here: authentication (step 0
of the secure pipeline) already happens inside `SecureSDKCore.handle_request()`,
which also audits failed attempts under their own `trace_id`. Adding a
route-level guard ahead of it would either duplicate that check or, if it
short-circuits the request on failure, silently drop `UNAUTHENTICATED`
attempts from the audit trail — so the header is simply passed through.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Header, Request
from pydantic import BaseModel

router = APIRouter()


class ChatRequest(BaseModel):
    prompt: str


@router.post("/api/secure/chat")
async def secure_chat(
    body: ChatRequest,
    request: Request,
    x_sdk_token: str | None = Header(default=None),
) -> dict:
    core = request.app.state.secure_core
    result = await core.handle_request(body.prompt, x_sdk_token or "")

    bucket = "allowed" if result.verdict == "ALLOWED" else "blocked"
    request.app.state.metrics["secure"][bucket] += 1

    return asdict(result)
