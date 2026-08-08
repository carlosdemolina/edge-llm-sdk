# Phase 1 — Isolated HAL

**Date:** 2026-08-08
**Status:** ✅ Completed (DoD validated)

## What was done

Implemented `app/hal/hal.py`:

- **`VehicleState`** (actuators, mutable only via `apply_action()`): `ClimateState`,
  `WindowsState`, `LightsState`, `DoorsState` — plain `@dataclass`, not Pydantic
  (validation/whitelisting belongs to `sdk_core.py`, not the HAL).
- **`EnvironmentState`** (operator-only simulated scenario: `vehicle_speed_kmh`,
  `outside_temp_c`), mutable only via `set_environment()`.
- **`SystemTelemetry`** (real, read-only Raspberry Pi data via `psutil`), read via
  `get_telemetry()`.
- **`apply_action(action, params) -> ActionOutcome`**: dispatches the 5 DSL verbs
  (`set_climate`, `set_window`, `set_lights`, `set_door_lock`, `get_status`).
  Strict `isinstance` checks on booleans/ints (no permissive casts), numeric
  clamping instead of exceptions, unknown actions resolve to a safe no-op
  (`ok=False`), guarded by `asyncio.Lock`.
- **`set_environment(vehicle_speed_kmh=None, outside_temp_c=None)`**: partial
  update, clamped, same lock.
- **`get_telemetry()`**: no lock (read-only). CPU temperature read via
  `psutil.sensors_temperatures()["cpu_thermal"]` with a `vcgencmd measure_temp`
  fallback (regex-parsed), returns `None` if both fail.
- Module-level singleton `hal = HAL()`.
- Manual CLI demo (`if __name__ == "__main__"`), run via `python -m app.hal.hal`.

## DoD validation

| Criterion | Result |
|---|---|
| Real telemetry reads without exceptions on the Pi | ✅ `cpu_percent`, `ram_percent`, `cpu_temp_c` all populated |
| Out-of-range actions are clamped, not raised | ✅ `set_window position=150` → clamped to `100` |
| Unknown actions are a safe no-op | ✅ `set_speed` → `ok=False`, no exception, no state change |
| `set_environment()` independent from actuators | ✅ verified in demo |

## Design decisions confirmed this phase

- HAL state modeled with plain dataclasses (no Pydantic) — security/contract
  validation is exclusively the SDK core's responsibility (Phase 3).
- Booleans validated strictly (`isinstance(x, bool)`), no truthy casting.
- `ActionOutcome(ok, action, error)` as the internal return type of `apply_action()`.
- `psutil.cpu_percent()` primed once in `HAL.__init__` so the first real reading
  is meaningful.
