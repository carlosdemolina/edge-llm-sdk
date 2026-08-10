"""Shared DSL catalog description, used by both the secure and vulnerable
pipelines' system prompts.

Extracted out of `app/core/sdk_core.py` so that giving the vulnerable
pipeline the same action/param documentation does not require importing a
private helper across modules. This is purely API documentation (what
actions/params exist) — NOT a security control. Removing it from the
vulnerable pipeline never simulated "no security filters"; it only broke
the SDK's own interface contract, which just made the LLM invent
non-canonical action names (e.g. "unlockAllDoors") that the HAL then
rejected as `unknown_action` — masking the real vulnerable-pipeline
finding (unrestricted execution) behind a false negative. See
docs/DESIGN_SPEC.md §3.2 for the rationale.
"""

from __future__ import annotations


def describe_dsl_catalog(catalog: dict) -> str:
    """Plain-text description of the DSL catalog, with explicit semantics
    for the boolean/int fields the small edge model tends to invert
    (position direction, locked meaning) — see calibration run 2026-08-09.
    """
    lines = []
    for action, spec in catalog.get("actions", {}).items():
        params: dict = spec.get("params", {})
        if not params:
            lines.append(f'- "{action}": no params')
            continue

        param_descs = []
        for name, rule in params.items():
            if rule["type"] == "int":
                if name == "position":
                    param_descs.append(
                        "position (integer 0-100: 0 = fully closed/up, "
                        "100 = fully open/down)"
                    )
                else:
                    param_descs.append(f"{name} (integer, {rule['min']}-{rule['max']})")
            elif rule["type"] == "enum":
                param_descs.append(f"{name} (one of: {', '.join(rule['values'])})")
            elif rule["type"] == "bool":
                if name == "locked":
                    param_descs.append("locked (true = locked/secured, false = unlocked/open)")
                elif name in ("power", "state"):
                    param_descs.append(f"{name} (true = on, false = off)")
                else:
                    param_descs.append(f"{name} (true/false)")
        lines.append(f'- "{action}": {", ".join(param_descs)}')
    return "\n".join(lines)
