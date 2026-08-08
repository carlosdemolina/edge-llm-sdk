"""Data contracts for the Secure SDK core (see docs/DESIGN_SPEC.md §2.3-2.5).

- `ErrorCode`: operational subset of the standard error codes.
- `LLMAction`: strict Pydantic schema the LLM's JSON output must conform to.
- `Ctx`: simplified per-request context envelope (prototype scope).
- `ActionResult`: the SDK's deterministic verdict returned to the caller —
  never derived from the LLM's own `reasoning` text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict

SECURITY_VIOLATION_PREFIX = "@SECURITY_VIOLATION@"


class ErrorCode(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    INVALID_INPUT = "INVALID_INPUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class LLMAction(BaseModel):
    """Strict schema for the LLM's JSON output (extra fields rejected)."""

    model_config = ConfigDict(extra="forbid")

    action: str
    params: dict[str, Any]
    reasoning: str | None = None


@dataclass
class Ctx:
    session_id: str
    policy_id: str
    trace_id: str
    deadline_ms: int
    canary_token: str


@dataclass
class ActionResult:
    verdict: str                     # "ALLOWED" | "BLOCKED"
    error_code: ErrorCode | None
    action: str | None
    message: str                     # SDK-deterministic message, never the LLM's `reasoning`
    trace_id: str | None
