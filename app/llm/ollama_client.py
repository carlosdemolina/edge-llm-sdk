"""Async client for the local Ollama HTTP API (see docs/DESIGN_SPEC.md §3.3).

This module is a pure transport layer: it sends requests to Ollama and
returns the raw response text. It intentionally does NOT parse or validate
JSON output, whitelist actions, or apply any security policy — that is the
exclusive responsibility of `app/core/sdk_core.py` (Phase 3).

Design notes:
- `OllamaClient` is NOT instantiated as a module-level singleton (unlike
  `app/hal/hal.py`). Its `httpx.AsyncClient` holds a persistent HTTP
  connection whose lifecycle should be tied explicitly to the application
  that uses it: the FastAPI server will create one in its startup event and
  close it in its shutdown event (Phase 4); this Phase 2's manual CLI script
  creates and closes its own instance.
- `asyncio.Semaphore(1)` lives here (not in sdk_core.py) so that Ollama calls
  are serialized regardless of which pipeline (secure or vulnerable) issues
  them — the Raspberry Pi only has resources to run one inference at a time.
- Timeouts are split by phase: a short `connect` timeout (Ollama down/unreachable
  should fail fast) and a much longer `read` timeout (the model can take
  8-12s to warm up from an idle state on the Pi 5 before generating).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

# Ollama can take 8-12s to load model weights into memory after being idle
# on the Raspberry Pi 5. `connect` stays short: if the service is down or
# unreachable, we want to fail fast rather than wait alongside a genuine
# cold-start inference.
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=5.0, pool=5.0)


@dataclass
class InferenceConfig:
    temperature: float = 0.0
    top_k: int = 1
    top_p: float = 0.1
    format_json: bool = True


@dataclass
class OllamaResult:
    ok: bool
    text: str | None                # raw response text — NOT parsed here
    latency_ms: float | None
    error: str | None = None        # "timeout" | "connection_error" | "http_status_error" | None


class OllamaClient:
    """Thin async wrapper around Ollama's `/api/generate` and `/api/tags`."""

    def __init__(self, host: str, model: str, default_timeout: httpx.Timeout = DEFAULT_TIMEOUT):
        self._client = httpx.AsyncClient(base_url=host)
        self._semaphore = asyncio.Semaphore(1)
        self.model = model
        self._default_timeout = default_timeout

    async def ensure_model_available(self) -> None:
        """Fail-fast check: verify `self.model` is present in `ollama list`.

        Meant to be called once at application startup (Phase 4's FastAPI
        startup event). Raises RuntimeError with a clear message if the
        model is missing, instead of letting the first user chat fail
        silently.
        """
        try:
            response = await self._client.get("/api/tags", timeout=self._default_timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Could not reach Ollama at startup ({self._client.base_url}): {exc}"
            ) from exc

        models = [m.get("name") for m in response.json().get("models", [])]
        if self.model not in models:
            raise RuntimeError(
                f"Model '{self.model}' is not available in Ollama (found: {models}). "
                f"Run 'ollama pull {self.model}' before starting the server."
            )

    async def generate(
        self,
        prompt: str,
        config: InferenceConfig,
        timeout: httpx.Timeout | None = None,
        keep_alive: str | None = None,
    ) -> OllamaResult:
        """Send a single prompt to Ollama's /api/generate endpoint.

        Serialized via `asyncio.Semaphore(1)`: only one inference runs at a
        time regardless of caller, since the Pi can only load one model in
        memory (impediment §4.5 of the design spec).

        `keep_alive` (Ollama duration string, e.g. `"5m"`) is passed through
        unchanged when set — used by `warm_up()` to keep the model resident
        in memory for a while after startup, without affecting the default
        Ollama behavior (~5 min) for ordinary chat calls that omit it.
        """
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": config.temperature,
                "top_k": config.top_k,
                "top_p": config.top_p,
            },
        }
        if config.format_json:
            payload["format"] = "json"
        if keep_alive is not None:
            payload["keep_alive"] = keep_alive

        request_timeout = timeout or self._default_timeout

        async with self._semaphore:
            start = time.perf_counter()
            try:
                response = await self._client.post(
                    "/api/generate", json=payload, timeout=request_timeout
                )
                latency_ms = (time.perf_counter() - start) * 1000
                response.raise_for_status()
            except httpx.TimeoutException:
                latency_ms = (time.perf_counter() - start) * 1000
                return OllamaResult(ok=False, text=None, latency_ms=latency_ms, error="timeout")
            except httpx.HTTPStatusError as exc:
                return OllamaResult(
                    ok=False, text=None, latency_ms=latency_ms, error=f"http_status_error: {exc}"
                )
            except httpx.HTTPError as exc:
                latency_ms = (time.perf_counter() - start) * 1000
                return OllamaResult(
                    ok=False, text=None, latency_ms=latency_ms, error=f"connection_error: {exc}"
                )

        text = response.json().get("response")
        return OllamaResult(ok=True, text=text, latency_ms=latency_ms, error=None)

    async def warm_up(self, keep_alive: str) -> None:
        """Best-effort cold-start absorption: send a trivial prompt at
        startup so the model is already loaded in memory by the time the
        first real user request arrives, instead of that request eating the
        ~8-12s load time and risking a `RESOURCE_LIMIT` timeout.

        Meant to be launched as a fire-and-forget `asyncio.create_task()` from
        the FastAPI `lifespan()`, in parallel with the server accepting
        connections — never awaited inline, since it would otherwise delay
        startup by the same cold-start latency it is meant to hide.

        Deliberately swallows all errors: this is an optimization, not a
        correctness requirement (`ensure_model_available()` is the real
        fail-fast startup check). If Ollama is slow or briefly unreachable,
        the warm-up simply doesn't help this time; the next real request
        will still pay its own cold-start cost.
        """
        try:
            result = await self.generate(
                "ping",
                InferenceConfig(temperature=0.0, top_k=1, top_p=0.1, format_json=False),
                timeout=DEFAULT_TIMEOUT,
                keep_alive=keep_alive,
            )
            if result.ok:
                print(f"[ollama_client] Warm-up OK ({result.latency_ms:.0f} ms) — model resident in memory.")
            else:
                print(f"[ollama_client] Warm-up failed ({result.error}) — first real request may be slow.")
        except Exception as exc:  # noqa: BLE001 - best-effort, must never crash startup
            print(f"[ollama_client] Warm-up raised an unexpected error ({exc}) — ignored.")

    async def aclose(self) -> None:
        await self._client.aclose()


# --------------------------------------------------------------------------
# Manual CLI test (Fase 2 DoD) — run with: python -m app.llm.ollama_client
# --------------------------------------------------------------------------

_TEST_PROMPT = (
    "Return ONLY a JSON object with exactly these two fields: "
    '"greeting" (a short string) and "number" (an integer between 1 and 10). '
    "Do not include any text outside the JSON object."
)


async def _demo() -> None:
    import json

    from app.config import OLLAMA_HOST, OLLAMA_MODEL

    client = OllamaClient(host=OLLAMA_HOST, model=OLLAMA_MODEL)
    config = InferenceConfig(temperature=0.0, top_k=1, top_p=0.1, format_json=True)

    try:
        print(f"=== Comprobación de arranque: modelo '{OLLAMA_MODEL}' disponible ===")
        await client.ensure_model_available()
        print("OK: modelo disponible.\n")

        successes = 0
        latencies: list[float] = []

        for i in range(1, 6):
            result = await client.generate(_TEST_PROMPT, config)
            latencies.append(result.latency_ms or 0.0)

            if not result.ok:
                print(f"[{i}/5] ERROR ({result.error}) — latencia: {result.latency_ms:.1f} ms")
                continue

            try:
                parsed = json.loads(result.text)
                successes += 1
                print(
                    f"[{i}/5] OK — latencia: {result.latency_ms:.1f} ms — "
                    f"JSON parseado: {parsed}"
                )
            except (json.JSONDecodeError, TypeError):
                print(
                    f"[{i}/5] JSON NO parseable — latencia: {result.latency_ms:.1f} ms — "
                    f"texto crudo: {result.text!r}"
                )

        print("\n=== Resumen ===")
        print(f"Éxito de parseo JSON: {successes}/5")
        print(f"Latencia — primera llamada (posible cold start): {latencies[0]:.1f} ms")
        if len(latencies) > 1:
            rest = latencies[1:]
            print(
                f"Latencia — media (llamadas 2-5): {sum(rest) / len(rest):.1f} ms "
                f"(mín: {min(rest):.1f} ms, máx: {max(rest):.1f} ms)"
            )
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(_demo())
