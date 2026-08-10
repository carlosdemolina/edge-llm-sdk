#!/usr/bin/env bash
# clean.sh — destructive cleanup of all generated outputs: logs, red-team /
# calibration reports, and Python bytecode caches. Safe to run any time in
# development; run it before a fresh `scripts/run_suite.sh` pass so results from a
# comparison run aren't mixed in with leftovers from previous experiments.
#
# This is intentionally destructive and non-archiving (see project design
# notes): it does NOT keep copies of anything it deletes, with one
# exception — logs/debug_trace_baseline_*.jsonl files (manually captured
# reference baselines) are never touched.
#
# Usage:
#   ./scripts/clean.sh          # asks for confirmation
#   ./scripts/clean.sh -y       # no confirmation (used by CI / automation)

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        -y|--yes)
            ASSUME_YES=1
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Usage: $0 [-y|--yes]" >&2
            exit 1
            ;;
    esac
done

if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "This will permanently delete logs/, redteam/reports/, and Python caches. Continue? [y/N] " reply
    case "$reply" in
        [yY]|[yY][eE][sS]) ;;
        *) echo "Aborted."; exit 1 ;;
    esac
fi

echo "==> Cleaning logs/ (keeping .gitkeep and debug_trace_baseline_*.jsonl) ..."
find logs -maxdepth 1 -type f \
    ! -name ".gitkeep" \
    ! -name "debug_trace_baseline_*.jsonl" \
    -print -delete

echo "==> Cleaning redteam/reports/ ..."
mkdir -p redteam/reports
find redteam/reports -mindepth 1 -maxdepth 1 -print -exec rm -rf {} +

echo "==> Cleaning __pycache__ and .pytest_cache ..."
find . \( -path ./venv -o -path ./.git \) -prune -o \
    -type d \( -name "__pycache__" -o -name ".pytest_cache" \) \
    -print -exec rm -rf {} +

echo "==> Done."
