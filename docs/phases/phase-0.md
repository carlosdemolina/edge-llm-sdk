# Phase 0 — Environment Setup

**Date:** 2026-08-07
**Status:** ✅ Completed (DoD validated)

## What was done

1. **Folder structure** created per §1 of the implementation spec, with empty stub files
   (`__init__.py`, `.py`, `.html`, `.js`, `.css`) and JSON policy/DSL/redteam files initialized to `{}`:
   - `app/` (`config.py`, `hal/`, `llm/`, `core/`, `policies/`, `server/`)
   - `frontend/` (`index.html`, `css/`, `js/`)
   - `redteam/`, `logs/` (with `.gitkeep`), `tests/`

2. **Dependencies installed** in the existing `venv` and pinned in `requirements.txt`:
   - New: `fastapi 0.141.1`, `uvicorn 0.52.1` (+ `uvloop`, `httptools`, `watchfiles`), `httpx 0.28.1`, `websockets 17.0.1`, `python-dotenv 1.2.2`.
   - Already present: `psutil 7.2.2`, `pydantic 2.13.4`, `requests 2.34.2`.

3. **Ollama verified**: systemd service active, model available as `llama3.2:latest`
   (Llama 3.2, 3.2B parameters, Q4_K_M quantization).

4. **`.env` created** with randomly generated secrets (`secrets.token_hex(32)`):
   `AUDIT_LOG_HMAC_SECRET`, `SDK_TOKEN`, `OLLAMA_HOST`, `OLLAMA_MODEL`, `RATE_LIMIT_COOLDOWN_S`.
   Excluded from git.

5. **`.gitignore` created**: excludes `venv/`, `.env`, `logs/` contents (except `.gitkeep`),
   `__pycache__/`, test caches, and the theoretical design documents (`SDK_API.md`,
   `Implementacion_Capitulo6.md`), which are kept local and not versioned.

## DoD validation

| Criterion | Result |
|---|---|
| `pip install -r requirements.txt` with no errors | ✅ |
| `python -c "import fastapi, httpx, psutil, pydantic"` | ✅ |
| `ollama list` includes the model | ✅ (`llama3.2:latest`) |

## Notes / decisions

- Model tag corrected in the spec document (3 references) from `llama3.2:3b` to `llama3.2:latest`.
- Design/theory documents are intentionally excluded from this implementation repository.
