#!/usr/bin/env bash
# run_suite.sh — thin wrapper around `python -m redteam.run_suite`.
#
# Runs the full test suite (unit tests + calibration + red-team, for every
# model being compared) and writes a timestamped report/comparison under
# redteam/reports/. See `redteam/run_suite.py` for details and CLI options
# (this wrapper forwards all arguments to it, e.g. `./scripts/run_suite.sh
# --models llama3.2:1b`).
#
# Prerequisites: Ollama running locally with the models pulled, and a
# populated .env (see README.md).

set -euo pipefail

# Repo root (this script lives in scripts/, one level below it) — venv/ and
# the redteam package both live at the repo root, not here.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ -d venv ]]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi

exec python -m redteam.run_suite "$@"
