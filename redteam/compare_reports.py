"""Builds a side-by-side comparison across the models tested by one
`redteam/run_suite.py` run.

Reads each model's archived `calibration.json`, `redteam.json` and
`debug_trace.jsonl` (all written by `run_suite.py` into
`redteam/reports/<run_id>/<model-slug>/`) and writes:
  - `redteam/reports/<run_id>/comparison.json` (machine-readable)
  - `redteam/reports/<run_id>/comparison.md`   (human-readable table)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _avg_latency_ms(debug_trace_path: Path) -> tuple[float | None, int]:
    """Average `sdk_total_duration_ms` across every traced request (both
    the calibration and red-team runs for this model share one log file,
    which is exactly the end-to-end population we want to compare).
    """
    if not debug_trace_path.exists():
        return None, 0

    durations: list[float] = []
    for line in debug_trace_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        duration = entry.get("sdk_total_duration_ms")
        if isinstance(duration, (int, float)):
            durations.append(duration)

    if not durations:
        return None, 0
    return sum(durations) / len(durations), len(durations)


def _model_summary(model_dir: Path) -> dict[str, Any]:
    calibration = json.loads((model_dir / "calibration.json").read_text(encoding="utf-8"))
    redteam = json.loads((model_dir / "redteam.json").read_text(encoding="utf-8"))
    avg_latency_ms, request_count = _avg_latency_ms(model_dir / "debug_trace.jsonl")

    return {
        "calibration_totals": calibration.get("totals", {}),
        "redteam_totals": redteam.get("totals", {}),
        "avg_latency_ms": avg_latency_ms,
        "traced_request_count": request_count,
    }


def _format_totals(totals: dict[str, int]) -> str:
    return f"PASS={totals.get('PASS', 0)} FAIL={totals.get('FAIL', 0)} REVIEW={totals.get('REVIEW', 0)}"


def write_comparison(run_dir: Path, model_dirs: dict[str, Path]) -> None:
    summaries = {model: _model_summary(model_dir) for model, model_dir in model_dirs.items()}

    comparison = {"run_id": run_dir.name, "models": summaries}
    (run_dir / "comparison.json").write_text(
        json.dumps(comparison, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    lines = [
        f"# Model comparison — run {run_dir.name}",
        "",
        "| Model | Calibration | Red-team (secure) | Red-team (vulnerable) | Avg latency (ms) | Traced requests |",
        "|---|---|---|---|---|---|",
    ]
    for model, summary in summaries.items():
        redteam_totals = summary["redteam_totals"]
        secure_totals = redteam_totals.get("secure", {})
        vulnerable_totals = redteam_totals.get("vulnerable", {})
        latency = summary["avg_latency_ms"]
        latency_str = f"{latency:.0f}" if latency is not None else "n/a"
        lines.append(
            f"| {model} | {_format_totals(summary['calibration_totals'])} "
            f"| {_format_totals(secure_totals)} | {_format_totals(vulnerable_totals)} "
            f"| {latency_str} | {summary['traced_request_count']} |"
        )

    (run_dir / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n" + "\n".join(lines))
