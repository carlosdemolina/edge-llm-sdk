"""Prompt-quality calibration runner (see Implementacion_Capitulo6.md).

Runs the calibration catalog (`redteam/calibration_prompts.json`) straight
through `SecureSDKCore.handle_request()`, WITHOUT going through the HTTP
server — same pattern as the manual `_demo()` in `app/core/sdk_core.py`.

This is deliberately scoped to prompt/semantic quality only, always against
the secure pipeline. The security attack catalog (`redteam/attack_prompts.json`)
is exclusively run by `redteam/run_redteam.py` (HTTP, secure+vulnerable dual
pipeline, plus credential_bypass) — that harness is strictly more complete
for security testing than an in-process, secure-only run could be, so this
module no longer supports pointing it at an arbitrary catalog file.

Why not just hit the running server with curl? Two reasons:
  1. We want `SDK_DEBUG_MODE` always on for this run, regardless of how the
     live dashboard server happens to be configured.
  2. We want an isolated `AuditLog` (`logs/calibration_audit.log`) so test
     runs never pollute the production tamper-evident chain that the
     dashboard's Audit modal displays (`AuditLog` has no delete method by
     design — see docs/DESIGN_SPEC.md).

Debug traces DO go to the real `DEBUG_TRACE_LOG_PATH` (`logs/debug_trace.jsonl`)
on purpose, so a run's full per-request pipeline detail (final prompt, raw
LLM output, parsed action, Ollama metrics) is inspectable both here (console
report + JSON report file) and in the live dashboard's Admin/Debug panel.

The model tested is whatever `OLLAMA_MODEL` resolves to (see app/config.py)
at the time this process starts — set it in the environment before running
to calibrate a specific model (`redteam/run_suite.py` does this automatically
when comparing multiple models). The report JSON and its filename both
record which model produced it.

Usage:
    python -m redteam.calibrate_prompt
    python -m redteam.calibrate_prompt --category boolean_inversion
    OLLAMA_MODEL=llama3.2:1b python -m redteam.calibrate_prompt
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import (
    AUDIT_LOG_HMAC_SECRET,
    BASE_DIR,
    DEBUG_TRACE_LOG_PATH,
    OLLAMA_HOST,
    OLLAMA_MODEL,
    SDK_TOKEN,
)
from app.core.audit_log import AuditLog
from app.core.debug_log import DebugTraceLog
from app.core.sdk_core import SecureSDKCore
from app.hal.hal import hal
from app.llm.ollama_client import OllamaClient
from redteam.scoring import NormalizedResult, model_slug, score_entry

CALIBRATION_AUDIT_LOG_PATH = BASE_DIR / "logs" / "calibration_audit.log"
CALIBRATION_CATALOG_PATH = BASE_DIR / "redteam" / "calibration_prompts.json"
REPORTS_DIR = BASE_DIR / "redteam" / "reports"
POLICIES_DIR = BASE_DIR / "app" / "policies"


async def _build_core() -> SecureSDKCore:
    dsl_catalog = json.loads((POLICIES_DIR / "dsl_actions.json").read_text())
    policy = json.loads((POLICIES_DIR / "vehicle_default.json").read_text())

    ollama_client = OllamaClient(host=OLLAMA_HOST, model=OLLAMA_MODEL)
    await ollama_client.ensure_model_available()

    audit_log = AuditLog(path=CALIBRATION_AUDIT_LOG_PATH, hmac_secret=AUDIT_LOG_HMAC_SECRET)
    debug_log = DebugTraceLog(path=DEBUG_TRACE_LOG_PATH)

    await hal.reset()

    return SecureSDKCore(
        hal=hal,
        ollama_client=ollama_client,
        audit_log=audit_log,
        sdk_token=SDK_TOKEN,
        dsl_catalog=dsl_catalog,
        policy=policy,
        debug_mode=True,
        debug_log=debug_log,
    ), policy["rate_limit_cooldown_s"]


async def run(catalog_path: Path, only_category: str | None) -> None:
    catalog = json.loads(catalog_path.read_text())
    categories = catalog.get("categories", {})
    if only_category:
        if only_category not in categories:
            raise SystemExit(f"Unknown category '{only_category}'. Available: {list(categories)}")
        categories = {only_category: categories[only_category]}

    core, cooldown_s = await _build_core()

    run_started = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "catalog_file": str(catalog_path),
        "model": OLLAMA_MODEL,
        "started_at": run_started,
        "categories": {},
    }
    totals = {"PASS": 0, "FAIL": 0, "REVIEW": 0}

    for category, entries in categories.items():
        print(f"\n=== {category} ===")
        report["categories"][category] = []

        for entry in entries:
            prompt = entry["prompt"]
            requires_speed = entry.get("requires_speed_kmh")
            if requires_speed is not None:
                await hal.set_environment(vehicle_speed_kmh=requires_speed)

            # Calibration measures prompt/semantic quality, not the rate
            # limiter (already covered by Fase 3's manual burst test) — reset
            # the cooldown clock before every entry so a slow-but-legitimate
            # previous inference can never cause a spurious RESOURCE_LIMIT
            # on the next catalog entry.
            core._last_request_ts = None
            result = await core.handle_request(prompt, SDK_TOKEN)

            if requires_speed is not None:
                await hal.set_environment(vehicle_speed_kmh=0)

            debug = result.debug
            stages = [asdict(s) for s in debug.stages] if debug else []
            parsed_action = debug.parsed_llm_action if debug else None

            normalized = NormalizedResult(
                verdict=result.verdict,
                error_code=result.error_code.value if result.error_code else None,
                action=result.action,
                params=(parsed_action or {}).get("params"),
                stages=stages,
            )
            status, detail = score_entry(entry, normalized)
            totals[status] += 1

            print(f"[{status}] {prompt!r}\n       {detail}  (trace {result.trace_id[:8]})")

            report["categories"][category].append(
                {
                    "prompt": prompt,
                    "status": status,
                    "detail": detail,
                    "verdict": result.verdict,
                    "error_code": result.error_code.value if result.error_code else None,
                    "action": result.action,
                    "params": (parsed_action or {}).get("params"),
                    "trace_id": result.trace_id,
                }
            )

            # No inter-request sleep needed: the cooldown clock is reset
            # per-entry above, and Ollama calls are already serialized by
            # OllamaClient's internal semaphore.

    report["totals"] = totals
    report["finished_at"] = datetime.now(timezone.utc).isoformat()

    print("\n=== Summary ===")
    for category, entries in report["categories"].items():
        counts = {"PASS": 0, "FAIL": 0, "REVIEW": 0}
        for e in entries:
            counts[e["status"]] += 1
        print(f"{category:32s} PASS={counts['PASS']:<3} FAIL={counts['FAIL']:<3} REVIEW={counts['REVIEW']:<3}")
    print(f"{'TOTAL':32s} PASS={totals['PASS']:<3} FAIL={totals['FAIL']:<3} REVIEW={totals['REVIEW']:<3}")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    report_path = REPORTS_DIR / f"calibration_{model_slug(OLLAMA_MODEL)}_{timestamp}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nFull report written to {report_path.relative_to(BASE_DIR)}")
    print(f"Per-request debug traces (final prompt, raw LLM output, params, metrics) in {DEBUG_TRACE_LOG_PATH.relative_to(BASE_DIR)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--category", default=None, help="Run only this category")
    args = parser.parse_args()

    asyncio.run(run(CALIBRATION_CATALOG_PATH, args.category))


if __name__ == "__main__":
    main()
