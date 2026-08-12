"""DSL whitelist + range validation (see docs/ARCHITECTURE.md §3.1 step 5.d/5.e).

Unlike `hal.py`'s defensive clamping, this layer REJECTS out-of-range or
out-of-catalog values outright — in secure mode, invalid parameters are a
policy violation, not something to silently correct.
"""

from __future__ import annotations

from typing import Any


def validate(action: str, params: dict[str, Any], catalog: dict) -> tuple[bool, str | None]:
    """Validate `action`/`params` against the DSL catalog.

    Returns (ok, reason). If ok is False, the caller must reject the request
    with ErrorCode.POLICY_VIOLATION.
    """
    actions = catalog.get("actions", {})
    if action not in actions:
        return False, "unknown_action"

    spec = actions[action].get("params", {})

    for name, rule in spec.items():
        value = params.get(name)
        param_type = rule["type"]

        if param_type == "bool":
            if not isinstance(value, bool):
                return False, f"invalid_{name}"

        elif param_type == "int":
            if not isinstance(value, int) or isinstance(value, bool):
                return False, f"invalid_{name}"
            if not (rule["min"] <= value <= rule["max"]):
                return False, f"out_of_range_{name}"

        elif param_type == "enum":
            if value not in rule["values"]:
                return False, f"invalid_{name}"

        else:
            return False, f"unknown_param_type_{name}"

    return True, None
