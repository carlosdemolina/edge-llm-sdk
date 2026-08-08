# Design Specification (English reference)

> The authoritative source of design decisions for this project is a private,
> Spanish-language document (`Implementacion_Capitulo6.md`) that is **not**
> included in this repository (see `.gitignore`). This file mirrors, section by
> section and in English, **only the parts that are already implemented in
> code**, so that in-repo comments can reference a document that actually
> exists here. Section numbers are kept aligned with the private source
> document for traceability.
>
> Sections not yet listed below are pending and will be added as their
> corresponding implementation phase is completed (see `docs/phases/`).

---

## 2.1. Vehicle state (`app/hal/hal.py`)

In-memory state, held as a single *singleton* instance guarded by an
`asyncio.Lock`. Three data origins with distinct trust boundaries are
distinguished: **actuators** (mutable only by the LLM via the DSL),
**simulated environment** (mutable only by the human operator, never by the
LLM), and **real telemetry** (read-only, Raspberry Pi hardware):

```text
VehicleState (actuators — mutable ONLY via the whitelisted DSL):
  climate:
    power: bool
    target_temp_c: int          # valid range [16, 28]
    fan_speed: int               # valid range [0, 5]
  windows:
    front_left:  int             # % open, range [0, 100]
    front_right: int
    rear_left:   int
    rear_right:  int
  lights:
    headlights: bool
    interior:   bool
    hazard:     bool
  doors:
    driver_locked:      bool
    passenger_locked:   bool
    rear_left_locked:   bool
    rear_right_locked:  bool

EnvironmentState (simulated scenario — mutable ONLY by the operator via
`POST /api/scenario/set`, NEVER by the LLM):
  vehicle_speed_kmh: int         # range [0, 220]. Ground truth "the car is
                                   # driving at X km/h", used to build Red
                                   # Teaming scenarios and for the secure
                                   # pipeline's contextual policy validation.
  outside_temp_c: int             # range [-20, 50]. Simulated outside
                                   # temperature, shown on the dashboard.

SystemTelemetry (real, read-only, Raspberry Pi hardware):
  cpu_percent: float              # psutil.cpu_percent(interval=None)
  ram_percent: float               # psutil.virtual_memory().percent
  cpu_temp_c: float | None         # psutil.sensors_temperatures() -> 'cpu_thermal',
                                   # falls back to `vcgencmd measure_temp` if absent
  timestamp: str (ISO 8601, UTC)
```

**Validation rules in `hal.py` (independent of the SDK, minimal defense even in
"vulnerable" mode):**
- Every numeric value out of range is **clamped** (never raises an exception),
  so that the vulnerable mode cannot crash the process — the vulnerability
  being demonstrated is a **security policy bypass**, not interpreter
  stability.
- Every state write (actuators or environment) goes through dedicated methods
  (`apply_action()` / `set_environment()`) protected by the same lock; reading
  telemetry (`get_telemetry()`) requires no lock (read-only, low cost).
- **Trust boundary:** `EnvironmentState` is test data deliberately set by the
  human operator (never by the chat user nor the LLM), so it does not
  constitute a new attack surface exposed to the model — its only purpose is
  to build reproducible Red Teaming scenarios.

## 2.2 – 6.x

*(pending — will be added as each phase is implemented)*
