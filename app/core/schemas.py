"""Data contracts for the Secure SDK core (see docs/ARCHITECTURE.md §2.3-2.5).

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
class PipelineStageTrace:
    """One step of the secure pipeline (see docs/ARCHITECTURE.md §3.1),
    captured only when `SDK_DEBUG_MODE` is on — a developer-tooling
    observation, never used for authorization decisions.
    """

    name: str
    status: str                     # "passed" | "blocked" | "skipped"
    detail: str | None = None
    duration_ms: float | None = None


@dataclass
class DebugTrace:
    """Full developer-debug trace of a single `handle_request()` call.

    Deliberately NOT part of the audit log's tamper-evident chain (see
    `app/core/audit_log.py`): this is a developer tool for model/design
    iteration and future test-bench tooling, not a production security
    control, so it carries the prompt and LLM output in plain text and is
    only ever produced when `SDK_DEBUG_MODE` is explicitly enabled.
    """

    timestamp: str
    stages: list[PipelineStageTrace]
    final_prompt: str | None = None
    raw_llm_output: str | None = None
    parsed_llm_action: dict[str, Any] | None = None
    ollama_metrics: dict[str, Any] | None = None
    sdk_total_duration_ms: float | None = None
    cpu_percent_start: float | None = None
    cpu_percent_end: float | None = None
    ram_percent_start: float | None = None
    ram_percent_end: float | None = None
    cpu_temp_c_start: float | None = None
    cpu_temp_c_end: float | None = None
    pipeline: str = "secure"          # "secure" | "vulnerable" — lets the
                                      # Admin/Debug tab and debug_trace.jsonl
                                      # distinguish/compare both pipelines


@dataclass
class ActionResult:
    verdict: str                     # "ALLOWED" | "BLOCKED"
    error_code: ErrorCode | None
    action: str | None
    message: str                     # SDK-deterministic message, never the LLM's `reasoning`
    trace_id: str | None
    debug: DebugTrace | None = None  # only populated when SDK_DEBUG_MODE is on
    params: dict[str, Any] | None = None  # only populated on ALLOWED — lets the
                                           # frontend render a friendly HUD phrase
                                           # ("opening window") without trusting
                                           # the LLM's own `reasoning` text
