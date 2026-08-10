"""End-to-end test-suite orchestrator: runs the unit tests plus the full
calibration + red-team catalogs against every model under comparison, and
produces a side-by-side comparison report.

For each model in `--models` (default: llama3.2:1b, llama3.2:latest) this:
  1. Runs `redteam/calibrate_prompt.py` in-process (no live server needed),
     with `OLLAMA_MODEL` set to that model.
  2. Starts a real `uvicorn` server (`SDK_DEBUG_MODE=true`, `OLLAMA_MODEL`
     set to that model) and waits for `GET /api/state` to answer.
  3. Runs `redteam/run_redteam.py` against that server (HTTP, secure +
     vulnerable pipelines), tagging the report with `--model-label`.
  4. Stops the server and archives that model's reports plus
     `logs/debug_trace.jsonl` / `logs/calibration_audit.log` into
     `redteam/reports/<run_id>/<model-slug>/`, then truncates those two log
     files so the next model starts from a clean slate.

`tests/` (model-independent unit tests) runs once, before the per-model loop.

Afterwards, `redteam/compare_reports.py` builds
`redteam/reports/<run_id>/comparison.json` and `comparison.md`.

Usage:
    python -m redteam.run_suite
    python -m redteam.run_suite --models llama3.2:1b llama3.2:latest
    python -m redteam.run_suite --skip-pytest
    ./scripts/run_suite.sh
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import psutil

from app.config import BASE_DIR, OLLAMA_HOST
from redteam.compare_reports import write_comparison
from redteam.scoring import model_slug

REPORTS_DIR = BASE_DIR / "redteam" / "reports"
LOGS_DIR = BASE_DIR / "logs"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000
SERVER_BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
SERVER_READY_TIMEOUT_S = 90.0
SERVER_READY_POLL_INTERVAL_S = 1.0
SERVER_STOP_TIMEOUT_S = 15.0

DEFAULT_MODELS = ["llama3.2:1b", "llama3.2:latest"]


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=True, cwd=BASE_DIR, **kwargs)


# What this project's own dev/suite server always looks like on the command
# line (`python -m uvicorn app.server.main:app ...`) — used to tell "our own
# leftover server" apart from an unrelated process that happens to be
# listening on the same port, which must never be killed automatically.
_OWN_SERVER_CMDLINE_MARKER = "app.server.main:app"


def _find_listening_pid(host: str, port: int) -> int | None:
    """Return the PID bound to `host:port` in LISTEN state, or None.

    `host` is not used to filter (a process bound to 0.0.0.0 also occupies
    127.0.0.1) — only the port matters for the actual conflict.
    """
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port:
            return conn.pid
    return None


def _is_own_stale_server(pid: int) -> bool:
    """True if `pid` looks like a leftover `uvicorn app.server.main:app`
    process from a previous manual run or a suite run that didn't shut down
    cleanly — never true for an unrelated process, even one also named
    `uvicorn` (e.g. serving a different app on the same machine).
    """
    try:
        proc = psutil.Process(pid)
        return _OWN_SERVER_CMDLINE_MARKER in " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def _check_port_free(host: str, port: int, kill_stale_server: bool = False) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        if sock.connect_ex((host, port)) != 0:
            return  # free

    pid = _find_listening_pid(host, port)
    if pid is not None and _is_own_stale_server(pid):
        if kill_stale_server:
            print(f"Port {port} is held by a stale uvicorn server (PID {pid}) — stopping it ...")
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=SERVER_STOP_TIMEOUT_S)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            return
        raise SystemExit(
            f"Port {port} is already in use on {host} by what looks like a leftover "
            f"`uvicorn app.server.main:app` process (PID {pid}), probably from a "
            f"manual `uvicorn ...` run or a previous suite run that didn't shut down "
            f"cleanly.\nEither stop it yourself (`kill {pid}`) or re-run with "
            f"--kill-stale-server to have the suite stop it automatically."
        )

    detail = f" (PID {pid}, not a uvicorn instance of this project)" if pid else ""
    raise SystemExit(
        f"Port {port} is already in use on {host}{detail} — stop whatever is "
        f"listening there before running the suite. Refusing to kill it "
        f"automatically since it doesn't look like this project's own server."
    )


def _check_ollama_models(models: list[str]) -> None:
    try:
        with urllib.request.urlopen(f"{OLLAMA_HOST}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError) as exc:
        raise SystemExit(f"Cannot reach Ollama at {OLLAMA_HOST}: {exc}")

    available = {m.get("name") for m in data.get("models", [])}
    missing = [m for m in models if m not in available]
    if missing:
        pulls = "\n".join(f"  ollama pull {m}" for m in missing)
        raise SystemExit(f"Missing Ollama model(s). Run:\n{pulls}")


def _wait_server_ready(base_url: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/api/state", timeout=3) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
        time.sleep(SERVER_READY_POLL_INTERVAL_S)
    raise SystemExit(f"Server did not become ready within {timeout_s:.0f}s ({last_error})")


def _run_pytest() -> None:
    print("\n" + "=" * 70)
    print("UNIT TESTS (tests/, model-independent, runs once)")
    print("=" * 70)
    _run([sys.executable, "-m", "pytest", "tests/", "-v"])


def _run_calibration(env: dict[str, str]) -> Path:
    before = {p.name for p in REPORTS_DIR.glob("calibration_*.json")}
    _run([sys.executable, "-m", "redteam.calibrate_prompt"], env=env)
    after = {p.name for p in REPORTS_DIR.glob("calibration_*.json")}
    new = after - before
    if len(new) != 1:
        raise RuntimeError(f"Expected exactly one new calibration report, found: {sorted(new)}")
    return REPORTS_DIR / new.pop()


def _start_server(env: dict[str, str]) -> subprocess.Popen:
    print(f"\nStarting uvicorn (OLLAMA_MODEL={env.get('OLLAMA_MODEL')}) ...")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "app.server.main:app",
            "--host", SERVER_HOST, "--port", str(SERVER_PORT),
        ],
        cwd=BASE_DIR,
        env=env,
    )
    try:
        _wait_server_ready(SERVER_BASE_URL, SERVER_READY_TIMEOUT_S)
    except SystemExit:
        _stop_server(proc)
        raise
    print("Server ready.")
    return proc


def _stop_server(proc: subprocess.Popen) -> None:
    print("Stopping server ...")
    proc.terminate()
    try:
        proc.wait(timeout=SERVER_STOP_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _run_redteam(model: str, env: dict[str, str]) -> Path:
    before = {p.name for p in REPORTS_DIR.iterdir() if p.is_dir() and p.name.startswith("redteam_")}
    _run(
        [
            sys.executable, "-m", "redteam.run_redteam",
            "--base-url", SERVER_BASE_URL,
            "--model-label", model,
        ],
        env=env,
    )
    after = {p.name for p in REPORTS_DIR.iterdir() if p.is_dir() and p.name.startswith("redteam_")}
    new = after - before
    if len(new) != 1:
        raise RuntimeError(f"Expected exactly one new redteam report dir, found: {sorted(new)}")
    return REPORTS_DIR / new.pop()


def _archive_model_run(run_dir: Path, model: str, calibration_report: Path, redteam_report: Path) -> Path:
    model_dir = run_dir / model_slug(model)
    model_dir.mkdir(parents=True, exist_ok=True)

    shutil.move(str(calibration_report), model_dir / "calibration.json")

    # redteam_report is now a directory (report.json + one .md per category,
    # see run_redteam.py) rather than a single file -- move its contents
    # straight into model_dir, renaming report.json for consistency with
    # calibration.json, then drop the now-empty source directory.
    for item in redteam_report.iterdir():
        dest_name = "redteam.json" if item.name == "report.json" else item.name
        shutil.move(str(item), model_dir / dest_name)
    redteam_report.rmdir()

    for filename in ("debug_trace.jsonl", "calibration_audit.log"):
        src = LOGS_DIR / filename
        if src.exists():
            shutil.copy2(src, model_dir / filename)
            src.write_text("")  # truncate so the next model starts clean

    return model_dir


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--models", nargs="+", default=DEFAULT_MODELS,
        help=f"Models to compare, in order (default: {DEFAULT_MODELS})",
    )
    parser.add_argument("--skip-pytest", action="store_true", help="Skip the tests/ unit test run")
    parser.add_argument(
        "--kill-stale-server", action="store_true",
        help=(
            "If port 8000 is held by a leftover `uvicorn app.server.main:app` "
            "process (e.g. from a manual run or a previous suite run that "
            "didn't shut down cleanly), stop it automatically instead of "
            "aborting. Never kills a process that isn't this project's own "
            "server."
        ),
    )
    args = parser.parse_args()

    _check_ollama_models(args.models)
    _check_port_free(SERVER_HOST, SERVER_PORT, kill_stale_server=args.kill_stale_server)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = REPORTS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_pytest:
        _run_pytest()

    model_dirs: dict[str, Path] = {}
    for model in args.models:
        print("\n" + "=" * 70)
        print(f"MODEL: {model}")
        print("=" * 70)

        env = os.environ.copy()
        env["OLLAMA_MODEL"] = model

        calibration_report = _run_calibration(env)

        server_env = env.copy()
        server_env["SDK_DEBUG_MODE"] = "true"
        server = _start_server(server_env)
        try:
            redteam_report = _run_redteam(model, env)
        finally:
            _stop_server(server)

        model_dirs[model] = _archive_model_run(run_dir, model, calibration_report, redteam_report)

    write_comparison(run_dir, model_dirs)

    print(f"\nSuite complete. Results in: {run_dir.relative_to(BASE_DIR)}")


if __name__ == "__main__":
    main()
