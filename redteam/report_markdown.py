"""Markdown rendering for `redteam/run_redteam.py`'s per-category reports.

Split out of `run_redteam.py` (which stays focused on driving the live HTTP
attack/scoring loop) for the same reason `redteam/compare_reports.py` is its
own module: report *rendering* is a separate responsibility from producing
the data it renders, and keeping it here makes `run_redteam.py` easier to
follow end to end.

The only public entry point is `write_category_markdown()`, called once per
category from `run_redteam.py`'s `run()` after the whole HTTP run finishes
(`report_categories[category]` is already fully populated JSON-shaped data
by then — this module has no HTTP/scoring knowledge of its own).
"""

from __future__ import annotations

import json
from pathlib import Path


def _fence_for(text: str) -> str:
    """Pick a backtick fence long enough that it can't be prematurely closed
    by backtick runs already present inside `text` (LLM output/prompts can
    legitimately contain ``` themselves).
    """
    longest_run = 0
    current = 0
    for ch in text:
        if ch == "`":
            current += 1
            longest_run = max(longest_run, current)
        else:
            current = 0
    return "`" * max(3, longest_run + 1)


def _code_block(text: str, lang: str = "") -> list[str]:
    fence = _fence_for(text)
    return [f"{fence}{lang}", text, fence]


def _render_trace_block(trace: dict) -> list[str]:
    """Renders the same per-request pipeline detail as the live dashboard's
    "Admin / Debug — pipeline trace" panel (see frontend/js/dashboard.js
    `renderDebugTraceEntry()`), as a collapsible Markdown `<details>` block —
    stage-by-stage timing/status, the full prompt sent to the LLM, its raw
    output, the parsed action and Ollama's own timing metrics, plus the
    CPU/RAM/temperature delta observed for that single request.
    """
    lines: list[str] = []
    total_ms = trace.get("sdk_total_duration_ms")
    total_label = f"{total_ms:.0f} ms" if isinstance(total_ms, (int, float)) else "—"
    lines.append(f"<details>\n<summary>pipeline trace — trace_id {trace.get('trace_id', '—')} ({total_label} total)</summary>\n")

    stages = trace.get("stages") or []
    if stages:
        lines.append("**Stages:**\n")
        for stage in stages:
            duration = stage.get("duration_ms")
            duration_part = f" ({duration:.1f} ms)" if isinstance(duration, (int, float)) else ""
            detail_part = f" — {stage['detail']}" if stage.get("detail") else ""
            lines.append(f"- `{stage.get('name')}`: **{stage.get('status')}**{duration_part}{detail_part}")
        lines.append("")

    if trace.get("final_prompt"):
        lines.append("**final_prompt:**\n")
        lines.extend(_code_block(trace["final_prompt"]))
        lines.append("")

    if trace.get("raw_llm_output"):
        lines.append("**raw_llm_output:**\n")
        lines.extend(_code_block(trace["raw_llm_output"]))
        lines.append("")

    if trace.get("parsed_llm_action") is not None:
        lines.append("**parsed_llm_action:**\n")
        lines.extend(_code_block(json.dumps(trace["parsed_llm_action"], indent=2, ensure_ascii=False), "json"))
        lines.append("")

    if trace.get("ollama_metrics") is not None:
        lines.append("**ollama_metrics:**\n")
        lines.extend(_code_block(json.dumps(trace["ollama_metrics"], indent=2, ensure_ascii=False), "json"))
        lines.append("")

    cpu0, cpu1 = trace.get("cpu_percent_start"), trace.get("cpu_percent_end")
    ram0, ram1 = trace.get("ram_percent_start"), trace.get("ram_percent_end")
    temp0, temp1 = trace.get("cpu_temp_c_start"), trace.get("cpu_temp_c_end")
    if any(v is not None for v in (cpu0, cpu1, ram0, ram1, temp0, temp1)):
        lines.append(f"CPU: {cpu0}% → {cpu1}% · RAM: {ram0}% → {ram1}% · Temp: {temp0}°C → {temp1}°C\n")

    lines.append("</details>")
    return lines


def _render_mode_result(label: str, info: dict) -> list[str]:
    status = info.get("status", "?")
    detail = info.get("detail", "")
    lines = [f"- **{label}** `{status}` — {detail}"]
    # Full trace detail is only surfaced for FAIL/REVIEW cases -- a clean
    # PASS doesn't need the stage-by-stage breakdown to be understood, and
    # dumping it for every single PASS would bury the cases that actually
    # need attention under a wall of repetitive, expected-good detail.
    trace = info.get("trace")
    if status != "PASS" and trace:
        lines.append("")
        lines.extend(_render_trace_block(trace))
    return lines


def _render_case(index: int, entry: dict) -> list[str]:
    title = entry.get("description") or entry.get("prompt") or f"case {index}"
    lines = [f"## {index}. {title}\n"]

    meta = {
        k: v
        for k, v in entry.items()
        if k not in ("description", "prompt", "secure", "vulnerable")
    }
    if meta:
        meta_line = " · ".join(f"{k}={v}" for k, v in meta.items())
        lines.append(f"*{meta_line}*\n")

    for label, key in (("SECURE", "secure"), ("VULNERABLE", "vulnerable")):
        if key in entry:
            lines.extend(_render_mode_result(label, entry[key]))
    lines.append("")
    return lines


def write_category_markdown(run_dir: Path, category: str, entries: list[dict]) -> None:
    lines = [f"# {category}\n"]
    for i, entry in enumerate(entries, start=1):
        lines.extend(_render_case(i, entry))
    (run_dir / f"{category}.md").write_text("\n".join(lines), encoding="utf-8")
