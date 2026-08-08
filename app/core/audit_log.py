"""Hash-chained, tamper-evident audit log (see docs/DESIGN_SPEC.md §3.4).

Each entry is one JSON line (JSONL) in an append-only file. Every entry
embeds an HMAC-SHA256 computed over its own fields plus the previous entry's
hash, forming a chain that can be verified end-to-end with `verify_chain()`.
The chain starts from a genesis hash of 64 zeros; on restart, it continues
from the last line already present in the file — it is never reset while the
file exists.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64


def _canonical_json(entry: dict) -> bytes:
    """Deterministic serialization used for both writing and re-verifying entries."""
    return json.dumps(
        entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class AuditLog:
    def __init__(self, path: Path, hmac_secret: bytes):
        self._path = path
        self._secret = hmac_secret
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev_hash = self._read_last_state()

    def _read_last_state(self) -> tuple[int, str]:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return 0, GENESIS_HASH

        last_line: str | None = None
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line

        if last_line is None:
            return 0, GENESIS_HASH

        last_entry = json.loads(last_line)
        return last_entry["seq"], last_entry["entry_hash"]

    def _compute_hash(self, entry_without_hash: dict) -> str:
        return hmac.new(
            self._secret, _canonical_json(entry_without_hash), hashlib.sha256
        ).hexdigest()

    async def append(
        self,
        *,
        trace_id: str,
        mode: str,
        prompt: str,
        verdict: str,
        error_code: str | None,
        action: str | None,
    ) -> dict:
        async with self._lock:
            entry_without_hash = {
                "seq": self._seq + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "trace_id": trace_id,
                "mode": mode,
                "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "verdict": verdict,
                "error_code": error_code,
                "action": action,
                "prev_hash": self._prev_hash,
            }
            entry_hash = self._compute_hash(entry_without_hash)
            entry = {**entry_without_hash, "entry_hash": entry_hash}

            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

            self._seq = entry["seq"]
            self._prev_hash = entry_hash
            return entry

    def verify_chain(self) -> bool:
        """Recompute every entry's HMAC and check hash-chain continuity from genesis."""
        if not self._path.exists():
            return True  # no entries yet is trivially a valid (empty) chain

        expected_prev_hash = GENESIS_HASH
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)

                if entry.get("prev_hash") != expected_prev_hash:
                    return False

                stored_hash = entry.get("entry_hash")
                entry_without_hash = {k: v for k, v in entry.items() if k != "entry_hash"}
                if self._compute_hash(entry_without_hash) != stored_hash:
                    return False

                expected_prev_hash = stored_hash

        return True

    async def read_last(self, limit: int) -> list[dict]:
        """Return up to `limit` most recent entries, newest first.

        Read-only, developer-tool-style accessor for the dashboard's
        Auditoría panel (Phase 8) — does not affect `verify_chain()` or the
        append-only write path in any way.
        """
        async with self._lock:
            if not self._path.exists():
                return []
            with self._path.open("r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

        selected = lines[-limit:] if limit > 0 else lines
        entries = [json.loads(line) for line in selected]
        entries.reverse()
        return entries
