"""Global configuration constants, loaded from the local .env file.

Secrets and infrastructure endpoints live in `.env` (never committed to git).
Operational policy constants (rate limit cooldown, deadline, sanitizer rules,
contextual rules) live in the versioned `app/policies/vehicle_default.json`
instead — see `app/core/sdk_core.py`.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR: Path = Path(__file__).resolve().parent.parent

OLLAMA_HOST: str = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.environ.get("OLLAMA_MODEL", "llama3.2:latest")

SDK_TOKEN: str = os.environ["SDK_TOKEN"]
AUDIT_LOG_HMAC_SECRET: bytes = bytes.fromhex(os.environ["AUDIT_LOG_HMAC_SECRET"])
AUDIT_LOG_PATH: Path = BASE_DIR / "logs" / "audit.log"

