"""HTTP-based Red Team runner (see Implementacion_Capitulo6.md §3.7).

Unlike `calibrate_prompt.py` (in-process, secure pipeline only, via
`SecureSDKCore.handle_request()`), this module drives BOTH
`/api/secure/chat` and `/api/vulnerable/chat` over real HTTP against an
already-running server, so it can produce the side-by-side secure-vs-
vulnerable security comparison that is the whole point of Phase 9's Red
Teaming requirement — a comparison `calibrate_prompt.py` cannot make, since
it never touches the vulnerable pipeline at all.

This requires the target server to be started with `SDK_DEBUG_MODE=true`
(see app/config.py). Full per-request pipeline detail (stage list,
`final_prompt` — which contains the per-request canary token — and
`raw_llm_output`) is NEVER attached to a chat response body itself:
`ActionResult.debug` is always `None` over HTTP regardless of server-side
debug mode, because both `routes_secure.py` and `routes_vulnerable.py`
return `asdict(result)` directly (see docs/DESIGN_SPEC.md §3.5). The only
way to recover that detail is `GET /api/debug/traces?limit=1`, polled
immediately after every chat call — which itself 404s if the server wasn't
started with debug mode on, and returns entries newest-first (see
`DebugTraceLog.read_last()`), so a `limit=1` poll right after each request
reliably correlates to that same request as long as no other client is
concurrently hitting the same server.

Usage:
    # terminal 1 — start the server with debug mode on:
    SDK_DEBUG_MODE=true uvicorn app.server.main:app

    # terminal 2:
    python -m redteam.run_redteam
    python -m redteam.run_redteam --category state_dependent_danger
    python -m redteam.run_redteam --category credential_bypass
    python -m redteam.run_redteam --base-url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.config import BASE_DIR, SDK_TOKEN
from redteam.scoring import NormalizedResult, score_entry

REPORTS_DIR = BASE_DIR / "redteam" / "reports"
POLICIES_DIR = BASE_DIR / "app" / "policies"

# Matches the canary token embedded by app/core/sdk_core.py's prompt
# encapsulation stage (see Ctx.canary_token) inside the secure pipeline's
# final_prompt — e.g. "Secret canary token: 3f9a1b2c...".
CANARY_RE = re.compile(r"Secret canary token: ([0-9a-f]{32})")

# Sentinel distinguishing "use the real SDK token" (the default for every
# ordinary category entry) from an explicit `token=None` ("send no
# X-SDK-Token header at all") — both are meaningfully different inputs for
# the credential_bypass category.
_USE_REAL_TOKEN = object()


def extract_canary_token(final_prompt: str | None) -> str | None:
    if not final_prompt:
        return None
    match = CANARY_RE.search(final_prompt)
    return match.group(1) if match else None


class RedTeamClient:
    """Thin HTTP wrapper around the live server's REST API.

    Kept deliberately free of scoring/business logic (mirrors the
    transport/setup vs. scoring split `calibrate_prompt.py` keeps between
    `_build_core()` and `run()`) — `run()` below is the single place that
    decides what a response means.
    """

    def __init__(self, base_url: str, sdk_token: str):
        self._token = sdk_token
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=5.0, pool=5.0),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def reset(self) -> None:
        r = await self._client.post("/api/reset")
        r.raise_for_status()

    async def set_scenario(self, **kwargs: Any) -> None:
        r = await self._client.post(
            "/api/scenario/set",
            json={k: v for k, v in kwargs.items() if v is not None},
            headers={"X-SDK-Token": self._token},
        )
        r.raise_for_status()

    def _auth_header(self, token: Any) -> dict[str, str]:
        if token is _USE_REAL_TOKEN:
            token = self._token
        return {"X-SDK-Token": token} if token is not None else {}

    async def raw_chat(self, path: str, prompt: str, token: Any) -> tuple[int, dict | None]:
        """Low-level POST that never raises on a non-200 status — used
        directly by the credential_bypass category, which deliberately
        probes malformed/oversized auth headers and needs to observe
        exactly how the transport layer (not just the SDK) reacts (e.g. an
        oversized header causing a raw 4xx from the ASGI server itself,
        instead of a clean app-level 401-equivalent BLOCKED/UNAUTHENTICATED
        body) — a real finding in its own right, not a bug in this runner.
        """
        headers = self._auth_header(token)
        r = await self._client.post(path, json={"prompt": prompt}, headers=headers)
        try:
            body = r.json()
        except ValueError:
            body = None
        return r.status_code, body

    async def secure_chat(self, prompt: str, token: Any = _USE_REAL_TOKEN) -> dict:
        status, body = await self.raw_chat("/api/secure/chat", prompt, token)
        if status != 200 or body is None:
            raise RuntimeError(f"unexpected HTTP {status} from /api/secure/chat: {body!r}")
        return body

    async def vulnerable_chat(self, prompt: str, token: Any = _USE_REAL_TOKEN) -> dict:
        status, body = await self.raw_chat("/api/vulnerable/chat", prompt, token)
        if status != 200 or body is None:
            raise RuntimeError(f"unexpected HTTP {status} from /api/vulnerable/chat: {body!r}")
        return body

    async def last_debug_trace(self) -> dict | None:
        r = await self._client.get(
            "/api/debug/traces",
            params={"limit": 1},
            headers={"X-SDK-Token": self._token},
        )
        if r.status_code == 404:
            # Server-side SDK_DEBUG_MODE is off — the run can still proceed
            # (verdict/action/params are still scored normally), just
            # without stage-level detail or canary-leak content inspection.
            return None
        r.raise_for_status()
        traces = r.json().get("traces", [])
        return traces[0] if traces else None


def _normalize(response: dict, trace: dict | None) -> NormalizedResult:
    stages = trace.get("stages", []) if trace else []
    final_prompt = trace.get("final_prompt") if trace else None
    return NormalizedResult(
        verdict=response["verdict"],
        error_code=response.get("error_code"),
        action=response.get("action"),
        params=response.get("params"),
        stages=stages,
        canary_token=extract_canary_token(final_prompt),
        raw_llm_output=trace.get("raw_llm_output") if trace else None,
    )


def _resolve_token_mode(entry: dict) -> str | None:
    mode = entry["token_mode"]
    if mode == "missing":
        return None
    if mode == "empty":
        return ""
    if mode == "wrong":
        return entry["token_value"]
    if mode == "whitespace_padded_correct":
        return f"  {SDK_TOKEN}  "
    if mode == "oversized":
        return "x" * 10_000
    raise ValueError(f"Unknown token_mode: {mode!r}")


def _empty_totals() -> dict[str, dict[str, int]]:
    return {"secure": {"PASS": 0, "FAIL": 0, "REVIEW": 0}, "vulnerable": {"PASS": 0, "FAIL": 0, "REVIEW": 0}}


async def _run_category(
    client: RedTeamClient,
    category: str,
    entries: list[dict],
    cooldown_s: float,
    totals: dict[str, dict[str, int]],
    report_categories: dict[str, Any],
) -> None:
    print(f"\n=== {category} ===")
    report_categories[category] = []

    for entry in entries:
        prompt = entry["prompt"]
        requires_speed = entry.get("requires_speed_kmh")
        if requires_speed is not None:
            await client.set_scenario(vehicle_speed_kmh=requires_speed)

        # Unlike calibrate_prompt.py, we have no in-process handle to reset
        # `core._last_request_ts` between entries — over HTTP the only way
        # to avoid a spurious RESOURCE_LIMIT is to actually wait out the
        # real cooldown before every secure-pipeline call. The vulnerable
        # pipeline has no rate limiter at all, so no sleep is needed there.
        await asyncio.sleep(cooldown_s)
        secure_response = await client.secure_chat(prompt)
        secure_trace = await client.last_debug_trace()
        secure_status, secure_detail = score_entry(
            entry, _normalize(secure_response, secure_trace), mode="secure"
        )
        totals["secure"][secure_status] += 1

        vulnerable_response = await client.vulnerable_chat(prompt)
        vulnerable_trace = await client.last_debug_trace()
        vulnerable_status, vulnerable_detail = score_entry(
            entry, _normalize(vulnerable_response, vulnerable_trace), mode="vulnerable"
        )
        totals["vulnerable"][vulnerable_status] += 1

        if requires_speed is not None:
            await client.reset()

        preview = prompt if len(prompt) <= 80 else f"{prompt[:77]}..."
        print(f"[secure     {secure_status:6s}] {preview!r}\n                  {secure_detail}")
        print(f"[vulnerable {vulnerable_status:6s}] {preview!r}\n                  {vulnerable_detail}")

        report_categories[category].append(
            {
                "prompt": prompt,
                "secure": {
                    "status": secure_status,
                    "detail": secure_detail,
                    "verdict": secure_response.get("verdict"),
                    "error_code": secure_response.get("error_code"),
                    "action": secure_response.get("action"),
                    "params": secure_response.get("params"),
                    "trace_id": secure_response.get("trace_id"),
                },
                "vulnerable": {
                    "status": vulnerable_status,
                    "detail": vulnerable_detail,
                    "verdict": vulnerable_response.get("verdict"),
                    "error_code": vulnerable_response.get("error_code"),
                    "action": vulnerable_response.get("action"),
                    "params": vulnerable_response.get("params"),
                    "trace_id": vulnerable_response.get("trace_id"),
                },
            }
        )


async def _run_credential_bypass(
    client: RedTeamClient,
    entries: list[dict],
    cooldown_s: float,
    totals: dict[str, dict[str, int]],
    report_categories: dict[str, Any],
) -> None:
    """Special-cased: varies the X-SDK-Token header itself rather than the
    prompt, so it has hardcoded expectations instead of the
    expected_verdict/expected_action `score_entry()` contract — secure must
    ALWAYS reject with BLOCKED/UNAUTHENTICATED regardless of token_mode
    (auth happens before any other pipeline stage), and vulnerable — which
    reads X-SDK-Token but never checks it (see routes_vulnerable.py) — must
    ALWAYS behave exactly as if no auth existed (ALLOWED, for this benign
    prompt).
    """
    print("\n=== credential_bypass ===")
    report_categories["credential_bypass"] = []

    for entry in entries:
        token = _resolve_token_mode(entry)
        prompt = entry["prompt"]

        await asyncio.sleep(cooldown_s)
        secure_status_code, secure_response = await client.raw_chat("/api/secure/chat", prompt, token)
        vulnerable_status_code, vulnerable_response = await client.raw_chat(
            "/api/vulnerable/chat", prompt, token
        )

        if secure_status_code != 200 or secure_response is None:
            secure_status, secure_detail = "FAIL", f"unexpected raw HTTP {secure_status_code} (expected a clean 200 body with verdict=BLOCKED)"
        elif secure_response.get("verdict") == "BLOCKED" and secure_response.get("error_code") == "UNAUTHENTICATED":
            secure_status, secure_detail = "PASS", "correctly rejected with BLOCKED/UNAUTHENTICATED"
        else:
            secure_status, secure_detail = "FAIL", f"expected BLOCKED/UNAUTHENTICATED, got verdict={secure_response.get('verdict')} error_code={secure_response.get('error_code')}"
        totals["secure"][secure_status] += 1

        if vulnerable_status_code != 200 or vulnerable_response is None:
            vulnerable_status, vulnerable_detail = "FAIL", f"unexpected raw HTTP {vulnerable_status_code} (expected a clean 200 ALLOWED body)"
        elif vulnerable_response.get("verdict") == "ALLOWED":
            vulnerable_status, vulnerable_detail = "PASS", "ALLOWED as expected (token is read but never checked)"
        else:
            vulnerable_status, vulnerable_detail = "FAIL", f"expected ALLOWED, got verdict={vulnerable_response.get('verdict')} error_code={vulnerable_response.get('error_code')}"
        totals["vulnerable"][vulnerable_status] += 1

        print(f"[secure     {secure_status:6s}] {entry['description']}\n                  {secure_detail}")
        print(f"[vulnerable {vulnerable_status:6s}] {entry['description']}\n                  {vulnerable_detail}")

        report_categories["credential_bypass"].append(
            {
                "description": entry["description"],
                "token_mode": entry["token_mode"],
                "secure": {"status": secure_status, "detail": secure_detail},
                "vulnerable": {"status": vulnerable_status, "detail": vulnerable_detail},
            }
        )


def _print_summary(totals_by_category: dict[str, dict[str, dict[str, int]]], grand_totals: dict[str, dict[str, int]]) -> None:
    print("\n=== Summary ===")
    for category, totals in totals_by_category.items():
        s, v = totals["secure"], totals["vulnerable"]
        print(
            f"{category:24s} secure PASS={s['PASS']:<3} FAIL={s['FAIL']:<3} REVIEW={s['REVIEW']:<3} | "
            f"vulnerable PASS={v['PASS']:<3} FAIL={v['FAIL']:<3} REVIEW={v['REVIEW']:<3}"
        )
    s, v = grand_totals["secure"], grand_totals["vulnerable"]
    print(
        f"{'TOTAL':24s} secure PASS={s['PASS']:<3} FAIL={s['FAIL']:<3} REVIEW={s['REVIEW']:<3} | "
        f"vulnerable PASS={v['PASS']:<3} FAIL={v['FAIL']:<3} REVIEW={v['REVIEW']:<3}"
    )


async def run(catalog_path: Path, base_url: str, only_category: str | None) -> None:
    catalog = json.loads(catalog_path.read_text())
    categories: dict[str, list[dict]] = catalog.get("categories", {})
    credential_bypass_entries: list[dict] = catalog.get("credential_bypass", [])

    run_credential_bypass = True
    if only_category is not None:
        if only_category == "credential_bypass":
            categories = {}
        elif only_category in categories:
            categories = {only_category: categories[only_category]}
            run_credential_bypass = False
        else:
            available = list(categories) + ["credential_bypass"]
            raise SystemExit(f"Unknown category '{only_category}'. Available: {available}")

    policy = json.loads((POLICIES_DIR / "vehicle_default.json").read_text())
    # Small safety margin over the policy's own cooldown, same rationale as
    # calibrate_prompt.py's per-entry `_last_request_ts` reset: never let a
    # legitimate rate-limit window cause a spurious RESOURCE_LIMIT result.
    cooldown_s = policy["rate_limit_cooldown_s"] + 0.5

    client = RedTeamClient(base_url, SDK_TOKEN)
    await client.reset()

    run_started = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "catalog_file": str(catalog_path),
        "base_url": base_url,
        "started_at": run_started,
        "categories": {},
    }
    totals_by_category: dict[str, dict[str, dict[str, int]]] = {}
    grand_totals = _empty_totals()

    try:
        for category, entries in categories.items():
            category_totals = _empty_totals()
            await _run_category(client, category, entries, cooldown_s, category_totals, report["categories"])
            totals_by_category[category] = category_totals
            for mode in ("secure", "vulnerable"):
                for status in ("PASS", "FAIL", "REVIEW"):
                    grand_totals[mode][status] += category_totals[mode][status]

        if run_credential_bypass and credential_bypass_entries:
            category_totals = _empty_totals()
            await _run_credential_bypass(client, credential_bypass_entries, cooldown_s, category_totals, report["categories"])
            totals_by_category["credential_bypass"] = category_totals
            for mode in ("secure", "vulnerable"):
                for status in ("PASS", "FAIL", "REVIEW"):
                    grand_totals[mode][status] += category_totals[mode][status]
    finally:
        await client.aclose()

    report["totals"] = grand_totals
    report["finished_at"] = datetime.now(timezone.utc).isoformat()

    _print_summary(totals_by_category, grand_totals)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"redteam_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nFull report written to {report_path.relative_to(BASE_DIR)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--file",
        default=str(BASE_DIR / "redteam" / "attack_prompts.json"),
        help="Path to the attack prompt catalog JSON (default: redteam/attack_prompts.json)",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Base URL of a running server, started with SDK_DEBUG_MODE=true (default: http://127.0.0.1:8000)",
    )
    parser.add_argument("--category", default=None, help="Run only this category (or 'credential_bypass')")
    args = parser.parse_args()

    asyncio.run(run(Path(args.file), args.base_url, args.category))


if __name__ == "__main__":
    main()
