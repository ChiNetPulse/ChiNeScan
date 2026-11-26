# Phase 3 ARTEX and Execution Hardening Report

## Result

**PHASE 3 IMPLEMENTED — RELEASE BLOCKED** pending the controlled release
commit, branch push, pull request review, and CI checks. The implementation and
local validation are complete for the approved scope; this report does not claim
that a remote PR or merge exists.

## Baseline and preservation

- Release branch: `release/phase-3`
- Starting commit: `3debcd2c93fdb8d83b62d875e9d7c42fc8c30c59`
- Phase 2 parent in history: `742481c999e31917e94cc1e37d8c64e7a54e47f8`
- Remote: `https://github.com/ChiNetPulse/ChiNeScan.git`
- Preserved untracked paths: `artifacts/` and `scripts/make_cover.py`
- No database migration was required.

The existing Rust Phase 3 reporter report (`docs/reports/phase-3-report.md`)
was not overwritten; this report covers only the ARTEX and execution-reliability
closure work in the current release branch.

## ARTEX network security

`chinescan/integrations/artex/network.py` centralizes URL policy, DNS
resolution, address validation, and pinned HTTP/HTTPS transports. Every DNS
answer is validated. Loopback is allowed only for explicit local destinations;
non-loopback traffic requires HTTPS on port 443 and a globally routable address.
Private, link-local, unspecified, multicast, reserved, IPv4-mapped-private,
malformed, mixed-answer, credential-bearing, unexpected-port, and unexpected-
scheme destinations are rejected before a socket is opened.

The transport connects directly to the validated sockaddr and retains the
original hostname for HTTP Host and TLS SNI/certificate verification. It never
performs a second hostname resolution during `connect()`. Redirects remain
rejected by the client. Tests cover public IPv4/IPv6, all prohibited address
families, mixed DNS answers, DNS rebinding/second-resolution attempts, local
loopback, URL validation, bounded responses, and redirects.

## ARTEX authentication and visibility

The upstream contract remains health-only and exposes no supported service
authentication protocol. The client therefore sends no invented credentials and
fails closed for disabled or invalid configuration. The authenticated status
route now reports only safe state, configuration readiness, the explicit
`unsupported_health_only` authentication marker, and the health capability. The
existing frontend system-status panel renders those fields without exposing
secrets or upstream response bodies.

ARTEX remains disabled by default and does not represent scanning, findings,
exports, or task execution as available.

## Durable execution reconciliation

`ExecutionGovernanceService` now provides a bounded, tenant-scoped reconciliation
workflow for uncertain external actions. Only organization managers can list or
resolve jobs; the route hides inaccessible jobs as not found, requires CSRF for
writes, requires a bounded evidence reference, and records allow/deny audit
events. The API returns safe metadata only; immutable execution context and raw
upstream response data remain protected.

The implementation does not claim exactly-once execution. Uncertain actions are
not automatically replayed. A confirmed failure preserves the uncertain action
attempt and records the operator's classification and evidence reference so the
original ambiguity remains auditable.

## Verification

Fresh commands against the final working tree:

- `py -3.12 -m pytest -q --disable-warnings --tb=short`: **930 passed, 0
  failed, 5 deselected** (389 warnings).
- ARTEX and durable-job focused tests: **36 passed**.
- `npm test`: **81 passed** in 20 files.
- `npm run typecheck`: passed.
- `npm run build`: passed, including strict CSP check.
- Targeted Ruff: passed.
- Targeted Ruff format check: passed.
- Targeted strict mypy for ARTEX/execution files: passed with 0 issues.
- `py -3.12 -m alembic heads`: one head,
  `0015_durable_job_leases_actions`.
- `git diff --check`: passed.
- Rust `cargo fmt --all -- --check`, `cargo test --workspace`, and
  `cargo clippy --workspace --all-targets -- -D warnings`: passed.

`gitleaks` is not installed in the environment, so secret scanning is blocked
and is not claimed as passed. No Phase 3 Dockerfile or container image was
changed; a container scan was not run. Remote GitHub Actions/PR checks were not
run locally.

## Changed paths

- `chinescan/integrations/artex/network.py` (new pinned destination policy)
- `chinescan/integrations/artex/client.py`
- `chinescan/web/app.py`
- `chinescan/core/execution_governance.py`
- `chinescan/web/execution_api.py`
- `frontend/src/ui/SystemStatus.tsx`
- `frontend/src/ui/SystemStatus.test.tsx`
- `tests/unit/test_artex_integration.py`
- `tests/unit/test_phase2d_durable_jobs.py`
- `docs/ARTEX-PHASE3.md`
- this report

No migration, credential, database, distributed-worker, or Phase 1 governance
changes were introduced.

## Remaining release conditions

Before calling Phase 3 complete, review the unstaged diff, stage only the paths
above (leaving `artifacts/` and `scripts/make_cover.py` untouched), commit on
`release/phase-3`, push that branch, open the pull request against `main`, and
wait for required CI/security checks. The absence of local `gitleaks` and
container scanning tools must be resolved in CI or explicitly accepted by the
release reviewer.
