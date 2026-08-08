"""Developer-only debug trace log (see docs/DESIGN_SPEC.md, debug-mode section).

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
from dataclasses import asdict
from pathlib import Path

from app.core.schemas import DebugTrace


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
