"""Developer-only debug trace log (see docs/ARCHITECTURE.md, debug-mode section).

Deliberately separate from `app/core/audit_log.py`: `AuditLog` is a
production security control (tamper-evident HMAC chain, prompt only ever
stored as a SHA-256 hash). `DebugTraceLog` is a developer tool for model and
policy iteration (and future test-bench tooling) — it stores prompts and raw
LLM output in plain text, has no integrity chain, and is only ever created
and written to when `SDK_DEBUG_MODE` is explicitly enabled on the server.
`logs/*` is already git-ignored, so this file is never committed.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import psutil

from app.core.schemas import DebugTrace, PipelineStageTrace


class DebugTraceLog:
    def __init__(self, path: Path):
        self._path = path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def append(self, trace_id: str, trace: DebugTrace) -> None:
        entry = {"trace_id": trace_id, **asdict(trace)}
        async with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    async def read_last(self, limit: int) -> list[dict]:
        """Return up to `limit` most recent entries, newest first."""
        async with self._lock:
            if not self._path.exists():
                return []
            with self._path.open("r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

        selected = lines[-limit:] if limit > 0 else lines
        entries = [json.loads(line) for line in selected]
        entries.reverse()
        return entries

    async def clear(self) -> None:
        """Erase the entire debug trace history.

        Safe to expose destructively: unlike `AuditLog`, this file is a
        developer tool with no integrity chain and no production role, so
        truncating it has no security implications — it only discards
        plaintext prompts/LLM output kept for local iteration.
        """
        async with self._lock:
            if self._path.exists():
                self._path.write_text("", encoding="utf-8")


class DebugTraceRecorder:
    """Per-request accumulator for one `DebugTrace` (see `app/core/schemas.py`).

    Shared by both pipelines — `SecureSDKCore` (`app/core/sdk_core.py`) and
    the vulnerable route (`app/server/routes_vulnerable.py`) — so their
    traces stay structurally identical and can never silently drift apart
    the way two independently maintained copies could.

    Always constructed (never `None`), even when debug mode is off: every
    method below is then a no-op, so call sites never need `is not None`
    guards around `mark_stage()`/`set_*()` calls. The only exception is the
    (rare, per-request) cost of reading a CPU temperature sensor — callers
    still guard that themselves via the public `enabled` flag before doing
    it, exactly as before this class existed.
    """

    def __init__(self, enabled: bool, pipeline: str, cpu_temp_c: float | None = None):
        self.enabled = enabled
        self._pipeline = pipeline
        self._stages: list[PipelineStageTrace] = []
        self._final_prompt: str | None = None
        self._raw_llm_output: str | None = None
        self._parsed_llm_action: dict | None = None
        self._ollama_metrics: dict | None = None
        if not enabled:
            return
        self._t0 = time.perf_counter()
        self._last_t = self._t0
        self._cpu_start = psutil.cpu_percent(interval=None)
        self._ram_start = psutil.virtual_memory().percent
        self._cpu_temp_start = cpu_temp_c

    def mark_stage(self, name: str, status: str, detail: str | None = None) -> None:
        """Append one `PipelineStageTrace` entry, timed since the previous
        mark (or since construction, for the first one). `status` is
        "passed", "blocked", or (vulnerable pipeline only) "skipped" for a
        security stage the secure pipeline runs that this one deliberately
        does not, kept so both pipelines' stage lists line up 1:1.
        """
        if not self.enabled:
            return
        now = time.perf_counter()
        self._stages.append(
            PipelineStageTrace(
                name=name,
                status=status,
                detail=detail,
                duration_ms=(now - self._last_t) * 1000,
            )
        )
        self._last_t = now

    def set_final_prompt(self, prompt: str) -> None:
        if self.enabled:
            self._final_prompt = prompt

    def set_llm_output(self, text: str | None, metrics: dict | None) -> None:
        if self.enabled:
            self._raw_llm_output = text
            self._ollama_metrics = metrics

    def set_parsed_action(self, parsed: dict) -> None:
        if self.enabled:
            self._parsed_llm_action = parsed

    async def finalize(
        self,
        trace_id: str,
        debug_log: DebugTraceLog | None,
        cpu_temp_c: float | None = None,
    ) -> DebugTrace | None:
        """Build the final `DebugTrace` (with the closing CPU/RAM/temp
        snapshot) and persist it to `debug_log`, if debug mode is on.

        Note: `psutil.cpu_percent(interval=None)` measures "since the last
        call anywhere in this process" — other work (e.g. a background
        telemetry loop) may also sample it, so this is an approximation of
        this request's own CPU usage, not a perfectly isolated reading.
        """
        if not self.enabled:
            return None
        trace = DebugTrace(
            timestamp=datetime.now(timezone.utc).isoformat(),
            stages=self._stages,
            final_prompt=self._final_prompt,
            raw_llm_output=self._raw_llm_output,
            parsed_llm_action=self._parsed_llm_action,
            ollama_metrics=self._ollama_metrics,
            sdk_total_duration_ms=(time.perf_counter() - self._t0) * 1000,
            cpu_percent_start=self._cpu_start,
            cpu_percent_end=psutil.cpu_percent(interval=None),
            ram_percent_start=self._ram_start,
            ram_percent_end=psutil.virtual_memory().percent,
            cpu_temp_c_start=self._cpu_temp_start,
            cpu_temp_c_end=cpu_temp_c,
            pipeline=self._pipeline,
        )
        if debug_log is not None:
            await debug_log.append(trace_id, trace)
        return trace
