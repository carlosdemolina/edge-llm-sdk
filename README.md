# edge-sdk

Prototipo de asistente LLM embarcado (vehicular) con una arquitectura Zero
Trust: dos rutas HTTP en paralelo, una *segura* (con sanitización, DSL
whitelist, políticas contextuales, canary tokens, etc.) y otra *vulnerable*
(sin apenas controles), pensadas para poder comparar y cuantificar el efecto
de cada control de seguridad. Ver [docs/DESIGN_SPEC.md](docs/DESIGN_SPEC.md)
para el diseño detallado del pipeline.

Este documento cubre únicamente el **uso**: cómo arrancar el servidor a mano
y cómo ejecutar la suite de tests/calibración/red-team automatizada.

## Requisitos

- Python 3.13 y un entorno virtual con `pip install -r requirements.txt`.
- [Ollama](https://ollama.com) corriendo localmente, con los modelos que se
  vayan a usar ya descargados, por ejemplo:
  ```bash
  ollama pull llama3.2:1b
  ollama pull llama3.2:latest
  ```
- Un archivo `.env` en la raíz del proyecto con, como mínimo:
  ```
  AUDIT_LOG_HMAC_SECRET=<hex de 32 bytes>
  SDK_TOKEN=<token para las rutas protegidas>
  OLLAMA_HOST=http://localhost:11434
  OLLAMA_MODEL=llama3.2:latest
  ```
  (`OLLAMA_MODEL` es el valor por defecto; la suite de tests lo sobrescribe
  por proceso para poder comparar varios modelos sin tocar `.env`.)

## Arrancar el servidor manualmente

```bash
source venv/bin/activate
uvicorn app.server.main:app --reload
```

Por defecto expone `http://127.0.0.1:8000` (dashboard estático incluido).
Para activar el panel de depuración (trazas completas de cada request en
`logs/debug_trace.jsonl` y en `GET /api/debug/traces`):

```bash
SDK_DEBUG_MODE=true uvicorn app.server.main:app --reload
```

## Limpiar outputs generados

`scripts/clean.sh` borra de forma **destructiva** (sin copia de seguridad)
todo lo que generan los tests y ejecuciones manuales:

- `logs/*.log`, `logs/*.jsonl` (conserva `.gitkeep` y cualquier
  `debug_trace_baseline_*.jsonl`, que son snapshots manuales de referencia).
- Todo el contenido de `redteam/reports/`.
- Cachés `__pycache__/` y `.pytest_cache/` en todo el repo.

```bash
./scripts/clean.sh          # pide confirmación
./scripts/clean.sh -y       # sin confirmación
```

## Ejecutar la suite completa (tests + calibración + red-team, multi-modelo)

`scripts/run_suite.sh` (envoltorio de `python -m redteam.run_suite`) automatiza
todo el proceso de comparación entre modelos:

```bash
./scripts/run_suite.sh                                    # modelos por defecto
./scripts/run_suite.sh --models llama3.2:1b               # solo un modelo
./scripts/run_suite.sh --models llama3.2:1b llama3.2:latest
./scripts/run_suite.sh --skip-pytest                       # solo calibración + red-team
./scripts/run_suite.sh --kill-stale-server                 # mata un uvicorn propio olvidado en :8000, si lo hay
```

`--kill-stale-server` solo detiene un proceso si su línea de comandos
corresponde a `uvicorn app.server.main:app` (p. ej. un `uvicorn --reload`
manual que olvidaste parar, o un run anterior de la suite que no cerró
limpio). Si el puerto 8000 lo ocupa cualquier otro proceso, la suite aborta
sin tocarlo.

Para cada modelo indicado (por defecto `llama3.2:1b` y `llama3.2:latest`,
en ese orden), la suite:

1. Ejecuta `redteam/calibrate_prompt.py` en proceso (sin servidor HTTP),
   contra `redteam/calibration_prompts.json` — calidad/semántica del
   prompt, siempre sobre el pipeline seguro.
2. Levanta un servidor `uvicorn` real con `SDK_DEBUG_MODE=true` y
   `OLLAMA_MODEL` fijado a ese modelo, y espera a que `GET /api/state`
   responda.
3. Ejecuta `redteam/run_redteam.py` contra ese servidor — catálogo de
   ataques (`redteam/attack_prompts.json`) sobre ambos pipelines
   (seguro/vulnerable) vía HTTP.
4. Para el servidor y archiva los resultados de ese modelo (incluyendo
   `logs/debug_trace.jsonl` y `logs/calibration_audit.log`) antes de pasar
   al siguiente modelo, dejando esos dos logs vacíos para el siguiente.

Antes del bucle por modelo se ejecuta una única vez `tests/` (los tests
unitarios no dependen del modelo, así que no tiene sentido repetirlos).

### Estructura de resultados

Los resultados de `pytest` solo se muestran por consola (no generan un
archivo de reporte aparte); el resto queda bajo `redteam/reports/<run_id>/`:

```
redteam/reports/<run_id>/
├── comparison.json          # comparación agregada, todos los modelos
├── comparison.md            # misma comparación en tabla Markdown
├── llama3.2-1b/
│   ├── calibration.json
│   ├── redteam.json
│   ├── debug_trace.jsonl
│   └── calibration_audit.log
└── llama3.2-latest/
    ├── calibration.json
    ├── redteam.json
    ├── debug_trace.jsonl
    └── calibration_audit.log
```

`<run_id>` es una marca de tiempo UTC (`YYYYMMDDTHHMMSSZ`).

### Interpretar `comparison.md`

Una fila por modelo con:

- **Calibration**: `PASS/FAIL/REVIEW` del catálogo de calibración
  (pipeline seguro únicamente).
- **Red-team (secure)** / **Red-team (vulnerable)**: `PASS/FAIL/REVIEW` del
  catálogo de ataques, para cada uno de los dos pipelines.
- **Avg latency (ms)**: media de `sdk_total_duration_ms` sobre todas las
  peticiones trazadas de ese modelo (calibración + red-team combinadas).
- **Traced requests**: número de peticiones que aportaron esa media
  (peticiones bloqueadas antes de llamar al LLM también cuentan, ya que
  igualmente generan una traza).

`PASS`/`FAIL`/`REVIEW` es el mismo criterio en calibración y red-team (ver
`redteam/scoring.py`): `FAIL` indica que se alcanzó un resultado
explícitamente prohibido o no coincide con el veredicto/acción esperada;
`REVIEW` indica que la entrada del catálogo no tiene una expectativa
automática y requiere inspección manual del reporte JSON.
