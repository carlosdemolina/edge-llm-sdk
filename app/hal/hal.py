"""Hardware Abstraction Layer (HAL) for the simulated vehicle ECU/IVC prototype.

Three distinct state blocks with different trust boundaries (see
docs/ARCHITECTURE.md §2.1):

- VehicleState: actuators, mutable ONLY via `apply_action()` (DSL-whitelisted
  intents, invoked by the secure/vulnerable pipelines after the LLM response).
- EnvironmentState: simulated scenario data (speed, outside temperature),
  mutable ONLY via `set_environment()` (operator-triggered, never by the LLM).
- SystemTelemetry: real, read-only hardware telemetry from the Raspberry Pi
  (psutil), exposed via `get_telemetry()`.

This module intentionally contains NO security/DSL-whitelist validation logic
(that responsibility belongs to `app/core/sdk_core.py`). It only guarantees
that no numeric value ever escapes its valid range (clamping) and that no
malformed input can raise an exception, so that even the "vulnerable" pipeline
(which skips all upstream validation) cannot crash the process.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

import psutil


def clamp(value: int | float, lo: int | float, hi: int | float) -> int | float:
    """Clamp `value` to the inclusive range [lo, hi]."""
    return max(lo, min(hi, value))


# --------------------------------------------------------------------------
# VehicleState (actuators — mutable only via apply_action())
# --------------------------------------------------------------------------

@dataclass
class ClimateState:
    power: bool = False
    target_temp_c: int = 22        # valid range [16, 28]
    fan_speed: int = 0             # valid range [0, 5]


@dataclass
class WindowsState:
    front_left: int = 0            # % open, valid range [0, 100]
    front_right: int = 0
    rear_left: int = 0
    rear_right: int = 0


@dataclass
class LightsState:
    headlights: bool = False
    interior: bool = False
    hazard: bool = False


@dataclass
class DoorsState:
    driver_locked: bool = True
    passenger_locked: bool = True
    rear_left_locked: bool = True
    rear_right_locked: bool = True


@dataclass
class VehicleState:
    climate: ClimateState = field(default_factory=ClimateState)
    windows: WindowsState = field(default_factory=WindowsState)
    lights: LightsState = field(default_factory=LightsState)
    doors: DoorsState = field(default_factory=DoorsState)


# --------------------------------------------------------------------------
# EnvironmentState (simulated scenario — mutable only via set_environment())
# --------------------------------------------------------------------------

@dataclass
class EnvironmentState:
    vehicle_speed_kmh: int = 0     # valid range [0, 220]
    outside_temp_c: int = 20       # valid range [-20, 50]
    fuel_percent: int = 100        # valid range [0, 100]
    battery_percent: int = 100     # valid range [0, 100]


# --------------------------------------------------------------------------
# SystemTelemetry (real, read-only, Raspberry Pi hardware via psutil)
# --------------------------------------------------------------------------

@dataclass
class SystemTelemetry:
    cpu_percent: float
    ram_percent: float
    cpu_temp_c: float | None
    fan_level: int | None          # current cooling_device state (0 = idle/off)
    fan_level_max: int | None      # max_state of the same cooling_device
    timestamp: str                 # ISO 8601, UTC


# Raspberry Pi 5 official Active Cooler thermal cooling device (step_wise
# governor, states 0-4). Read-only, best-effort: absent on any other board
# or OS, so every read is wrapped defensively and falls back to None.
_FAN_COOLING_DEVICE = Path("/sys/class/thermal/cooling_device0")


# --------------------------------------------------------------------------
# Result of apply_action()
# --------------------------------------------------------------------------

@dataclass
class ActionOutcome:
    ok: bool
    action: str
    error: str | None = None


class HAL:
    """Singleton-style Hardware Abstraction Layer.

    A single instance (`hal`, at the bottom of this module) is meant to be
    imported and shared across the whole application/process.
    """

    _VALID_WINDOWS = ("front_left", "front_right", "rear_left", "rear_right")
    _VALID_LIGHTS = ("headlights", "interior", "hazard")
    _VALID_DOORS = ("driver", "passenger", "rear_left", "rear_right")

    def __init__(self) -> None:
        self.vehicle = VehicleState()
        self.environment = EnvironmentState()
        self._lock = asyncio.Lock()
        # Prime psutil's internal reference: the first call to cpu_percent()
        # after import always returns 0.0 because it has no prior sample to
        # compare against. Discarding one call here means the first *real*
        # reading from get_telemetry() is already meaningful.
        psutil.cpu_percent(interval=None)

    # ---------------------------------------------------------------- #
    # Reset (used by POST /api/reset — test reproducibility)
    # ---------------------------------------------------------------- #

    async def reset(self) -> None:
        """Reset both VehicleState and EnvironmentState to their defaults.

        Both blocks are reset (not just actuators) so that red-team runs
        start from a fully known baseline — e.g. a previously set
        `vehicle_speed_kmh=180` scenario must not leak into the next test.
        Telemetry is real hardware data and has no "default" to reset.
        """
        async with self._lock:
            self.vehicle = VehicleState()
            self.environment = EnvironmentState()

    # ---------------------------------------------------------------- #
    # Actuators (DSL-driven)
    # ---------------------------------------------------------------- #

    async def apply_action(self, action: str, params: dict) -> ActionOutcome:
        async with self._lock:
            try:
                if action == "set_climate":
                    return self._apply_set_climate(params)
                if action == "set_window":
                    return self._apply_set_window(params)
                if action == "set_lights":
                    return self._apply_set_lights(params)
                if action == "set_door_lock":
                    return self._apply_set_door_lock(params)
                if action == "get_status":
                    return ActionOutcome(ok=True, action=action)
                # Unknown/disallowed action (e.g. a removed verb like
                # "set_speed"): safe no-op, never raises.
                return ActionOutcome(ok=False, action=action, error="unknown_action")
            except Exception as exc:  # defensive: never let apply_action crash
                return ActionOutcome(ok=False, action=action, error=f"internal_error: {exc}")

    def _apply_set_climate(self, params: dict) -> ActionOutcome:
        power = params.get("power")
        target_temp_c = params.get("target_temp_c")
        fan_speed = params.get("fan_speed")

        if not isinstance(power, bool):
            return ActionOutcome(ok=False, action="set_climate", error="invalid_power")
        if not isinstance(target_temp_c, int) or isinstance(target_temp_c, bool):
            return ActionOutcome(ok=False, action="set_climate", error="invalid_target_temp_c")
        if not isinstance(fan_speed, int) or isinstance(fan_speed, bool):
            return ActionOutcome(ok=False, action="set_climate", error="invalid_fan_speed")

        self.vehicle.climate.power = power
        self.vehicle.climate.target_temp_c = clamp(target_temp_c, 16, 28)
        self.vehicle.climate.fan_speed = clamp(fan_speed, 0, 5)
        return ActionOutcome(ok=True, action="set_climate")

    def _apply_set_window(self, params: dict) -> ActionOutcome:
        window = params.get("window")
        position = params.get("position")

        if not isinstance(position, int) or isinstance(position, bool):
            return ActionOutcome(ok=False, action="set_window", error="invalid_position")
        position = clamp(position, 0, 100)

        if window == "all":
            for name in self._VALID_WINDOWS:
                setattr(self.vehicle.windows, name, position)
            return ActionOutcome(ok=True, action="set_window")

        if window not in self._VALID_WINDOWS:
            return ActionOutcome(ok=False, action="set_window", error="invalid_window")

        setattr(self.vehicle.windows, window, position)
        return ActionOutcome(ok=True, action="set_window")

    def _apply_set_lights(self, params: dict) -> ActionOutcome:
        light = params.get("light")
        state = params.get("state")

        if light not in self._VALID_LIGHTS:
            return ActionOutcome(ok=False, action="set_lights", error="invalid_light")
        if not isinstance(state, bool):
            return ActionOutcome(ok=False, action="set_lights", error="invalid_state")

        setattr(self.vehicle.lights, light, state)
        return ActionOutcome(ok=True, action="set_lights")

    def _apply_set_door_lock(self, params: dict) -> ActionOutcome:
        door = params.get("door")
        locked = params.get("locked")

        if not isinstance(locked, bool):
            return ActionOutcome(ok=False, action="set_door_lock", error="invalid_locked")

        if door == "all":
            for name in self._VALID_DOORS:
                setattr(self.vehicle.doors, f"{name}_locked", locked)
            return ActionOutcome(ok=True, action="set_door_lock")

        if door not in self._VALID_DOORS:
            return ActionOutcome(ok=False, action="set_door_lock", error="invalid_door")

        setattr(self.vehicle.doors, f"{door}_locked", locked)
        return ActionOutcome(ok=True, action="set_door_lock")

    # ---------------------------------------------------------------- #
    # Environment (operator-driven, never by the LLM)
    # ---------------------------------------------------------------- #

    async def set_environment(
        self,
        vehicle_speed_kmh: int | None = None,
        outside_temp_c: int | None = None,
        fuel_percent: int | None = None,
        battery_percent: int | None = None,
    ) -> EnvironmentState:
        async with self._lock:
            if vehicle_speed_kmh is not None:
                self.environment.vehicle_speed_kmh = int(clamp(vehicle_speed_kmh, 0, 220))
            if outside_temp_c is not None:
                self.environment.outside_temp_c = int(clamp(outside_temp_c, -20, 50))
            if fuel_percent is not None:
                self.environment.fuel_percent = int(clamp(fuel_percent, 0, 100))
            if battery_percent is not None:
                self.environment.battery_percent = int(clamp(battery_percent, 0, 100))
            return self.environment

    def get_environment(self) -> EnvironmentState:
        """Return a *copy* of the current EnvironmentState.

        A copy (not the live reference) is returned deliberately: callers
        (e.g. the secure pipeline's contextual policy check, §3.1 step 5.g)
        must not be able to mutate `self.environment` by holding onto the
        returned object — the only sanctioned write path is
        `set_environment()`. No lock is needed for the read itself, same
        rationale as `get_telemetry()` (cheap, read-only).
        """
        return replace(self.environment)

    # ---------------------------------------------------------------- #
    # Telemetry (real hardware, read-only, no lock needed)
    # ---------------------------------------------------------------- #

    def get_telemetry(self) -> SystemTelemetry:
        fan_level, fan_level_max = self._read_fan_level()
        return SystemTelemetry(
            cpu_percent=psutil.cpu_percent(interval=None),
            ram_percent=psutil.virtual_memory().percent,
            cpu_temp_c=self._read_cpu_temp(),
            fan_level=fan_level,
            fan_level_max=fan_level_max,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _read_fan_level() -> tuple[int | None, int | None]:
        try:
            level = int((_FAN_COOLING_DEVICE / "cur_state").read_text().strip())
            level_max = int((_FAN_COOLING_DEVICE / "max_state").read_text().strip())
            return level, level_max
        except (OSError, ValueError):
            return None, None

    def _read_cpu_temp(self) -> float | None:
        try:
            temps = psutil.sensors_temperatures()
            if temps and "cpu_thermal" in temps and temps["cpu_thermal"]:
                return temps["cpu_thermal"][0].current
        except (AttributeError, KeyError, IndexError):
            pass

        try:
            result = subprocess.run(
                ["vcgencmd", "measure_temp"],
                capture_output=True,
                text=True,
                timeout=1,
            )
            match = re.search(r"temp=([\d.]+)", result.stdout)
            if match:
                return float(match.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return None


# Module-level singleton, shared across the whole process.
hal = HAL()


# --------------------------------------------------------------------------
# Manual CLI test (Fase 1 DoD) — run with: python -m app.hal.hal
# --------------------------------------------------------------------------

async def _demo() -> None:
    print("=== 1. Acción válida: set_climate ===")
    outcome = await hal.apply_action(
        "set_climate", {"power": True, "target_temp_c": 22, "fan_speed": 3}
    )
    print(outcome)
    print(hal.vehicle.climate)

    print("\n=== 2. Acción fuera de rango: set_window (position=150) ===")
    outcome = await hal.apply_action(
        "set_window", {"window": "front_left", "position": 150}
    )
    print(outcome)
    print(hal.vehicle.windows, "(se espera front_left clampado a 100)")

    print("\n=== 3. Acción desconocida: set_speed ===")
    outcome = await hal.apply_action("set_speed", {"kmh": 200})
    print(outcome, "(se espera ok=False, sin excepción)")
    print(hal.environment, "(no debe haber cambiado)")

    print("\n=== 4. set_environment (operador humano) ===")
    env = await hal.set_environment(vehicle_speed_kmh=140, outside_temp_c=35)
    print(env)

    print("\n=== 5. Telemetría real de la Raspberry Pi ===")
    telemetry = hal.get_telemetry()
    print(telemetry)


if __name__ == "__main__":
    asyncio.run(_demo())
