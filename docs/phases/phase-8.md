# Phase 8 — Audit visibility panel

**Date:** 2026-08-08
**Status:** ✅ Completed (DoD validated)

## What was done

Added a read-only, always-available way for the dashboard to show every
recorded attempt (blocked or allowed, either pipeline) with its verdict and
chained hash, without touching `AuditLog`'s append-only write path. Full
design rationale is in `docs/DESIGN_SPEC.md` §3.4-ter.

- **`app/core/audit_log.py`**: new `read_last(limit: int) -> list[dict]`
  async method — reads all lines under the existing `asyncio.Lock`, slices
  the last `limit`, `json.loads()`s each, and returns them newest-first.
  Mirrors `DebugTraceLog.read_last()`'s exact pattern. Purely additive: does
  not affect `append()` or `verify_chain()`.
- **`app/server/routes_common.py`**: two new endpoints, both gated only by
  `Depends(_verify_sdk_token)` (no `SDK_DEBUG_MODE` check, unlike
  `/api/debug/traces` — the audit log is a production feature, not a
  developer tool, so it stays available regardless of debug mode):
  - `GET /api/audit/entries?limit=20` → `{"entries": [...]}` via
    `AuditLog.read_last()`.
  - `GET /api/audit/verify` → `{"valid": bool}` via the existing
    `AuditLog.verify_chain()`.
- **`frontend/index.html`**: a prominent `#audit-open-btn` ("Auditoría")
  button in the header, next to Reset — deliberately not folded into the
  Admin/Debug tab, since this is a production accountability feature meant
  to be discoverable rather than a hidden developer tool. A new
  `#audit-modal` overlay (backdrop + centered card) holds the controls
  (`#audit-refresh-btn`, `#audit-verify-btn`, `#audit-verify-status`) and
  the entry list (`#audit-entries-list`).
- **`frontend/js/dashboard.js`**: `renderAuditEntry()` renders each entry as
  a compact 3-line card (`#seq` + timestamp + `[secure]`/`[vulnerable]`
  badge; color-coded verdict + action + error_code + truncated `trace_id`;
  truncated `entry_hash`/`prev_hash`). `fetchAuditEntries()` and
  `fetchVerifyChain()` call the two new endpoints with the stored
  `X-SDK-Token`. `initAuditModal()` wires the open button (populates on
  open), close button, backdrop-click-to-close, and the refresh/verify
  buttons.
- **`frontend/css/tailwind.css`**: rebuilt to include the new modal/backdrop
  utility classes (`fixed inset-0 z-50`, `bg-black/60`, `max-h-[85vh]`,
  etc.) — required after every markup change since this project uses a
  locally-compiled, git-committed stylesheet (no runtime CDN, no Node/npm
  on the Pi).
- **`docs/DESIGN_SPEC.md`**: also fixed a stale bullet under "Phase 7" left
  over from the debug-tracing addendum (the auto-refresh guard text still
  said it only fired for secure-mode submissions, which stopped being true
  once that addendum shipped).

## DoD validation

Tested end-to-end against a real `uvicorn app.server.main:app` instance on
the Raspberry Pi (port 8003, using the pre-existing `logs/audit.log` built
up over prior phases' testing):

| Criterion | Result |
|---|---|
| `GET /api/audit/entries` with no `X-SDK-Token` | `401 Unauthorized` |
| `GET /api/audit/entries?limit=3` with a valid token | Returns the 3 most recent entries, newest first, each with `seq`, `timestamp`, `mode`, `verdict`, `action`, `error_code`, `trace_id`, `prev_hash`, `entry_hash` |
| `GET /api/audit/verify` | `{"valid": true}` against the live, multi-entry, mixed secure/vulnerable chain |
| "Auditoría" header button | Opens `#audit-modal` as an overlay; background dimmed, header/main inaccessible while open (correct modal behavior — confirmed a click that lands on the backdrop closes the modal instead of reaching a button underneath) |
| Entry list rendering | Both `[secure]` and `[vulnerable]` badges render with correct colors; `ALLOWED`/`BLOCKED` verdicts color-coded; hash/prev-hash truncated and visibly chained across consecutive entries |
| "Verificar cadena" button | Shows "Cadena OK" (green) after calling `/api/audit/verify` |
| "Cerrar" button | Hides the modal, restoring interaction with the rest of the dashboard |
| `get_errors` across all changed files (`audit_log.py`, `routes_common.py`, `index.html`, `dashboard.js`) | Clean |

## Design decision confirmed during planning

Placement was deliberately the opposite of the Admin/Debug tab: the user
chose a prominent header button + modal overlay (not a separate page, not
folded into the intentionally-obscure Admin/Debug section), since the audit
panel is meant to demonstrate the system's own accountability, not to be a
developer-only tool.

## Addendum: clearable debug history

Per user request, added a "Borrar histórico" button next to the Admin/Debug
tab's existing "Refrescar histórico" — deliberately **only** for
`DebugTraceLog`, never for `AuditLog`:

- **`app/core/debug_log.py`**: new `clear()` async method truncates
  `logs/debug_trace.jsonl` under the existing lock. Safe to expose
  destructively since this log has no integrity chain and no production
  role (unlike `AuditLog`, which has no equivalent method by design).
- **`app/server/routes_common.py`**: `DELETE /api/debug/traces`
  (token-gated, same `404`-when-debug-mode-off behavior as `GET
  /api/debug/traces`).
- **`frontend/index.html`**: `#debug-clear-btn` button next to
  `#debug-refresh-btn`.
- **`frontend/js/dashboard.js`**: `clearDebugTraces()` gates the call
  behind a native `confirm()` dialog (irreversible action) before calling
  `DELETE /api/debug/traces` and refreshing the list.
- **Validated on-device**: `DELETE` with no token → `401`; with a valid
  token, entry count dropped from 5 → 0 while `GET /api/audit/verify`
  still returned `{"valid": true}` (audit chain untouched). In the browser,
  clicking "Borrar histórico" shows the confirm dialog; accepting clears
  the list, dismissing leaves it untouched.

