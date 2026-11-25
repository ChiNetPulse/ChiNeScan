# ChineScan Phase 2G Final Acceptance Report

**Date:** 2026-11-25
**Repository:** `C:\GitHub\Chinescan`
**Branch / HEAD:** `main` / `c09d3f150003421136790c42ffa96d570606da79`
**Decision:** **ACCEPTED WITH DOCUMENTED LIMITATIONS**

## A. Executive summary

The integrated Phase 2B–2F implementation passed the current focused security acceptance selection and the latest phase-local full-suite evidence. No cross-organization read/write path, assignment-based privilege escalation, approval replay path, stale-worker mutation path, or frontend tenant-cache leak was found in this review.

Current acceptance evidence:

- Cross-phase backend selection: **45 passed, 0 failed**.
- Latest phase-local full Python evidence: **896 passed, 0 failed, 5 deselected**, artifact `artifacts/phase2e-final-20261125-r2.xml`. Phase 2F changed frontend files only; no backend or migration changes were made in Phase 2F.
- Frontend: **81 passed** across 20 files; TypeScript, production build, and strict CSP passed.
- Alembic: one head, `0015_durable_job_leases_actions`; disposable upgrade/downgrade/upgrade, foreign-key, and downgrade-guard checks passed.

The decision is not unconditional because the project remains a SQLite single-instance system, POSIX process-group termination was inspected rather than executed on this Windows host, several settings are documented ceilings rather than dynamically wired parser limits, and no manual reconciliation endpoint exists for `reconciliation_required` jobs.

## B. Repository baseline and preservation

Before this review:

- Branch: `main`.
- HEAD: `c09d3f150003421136790c42ffa96d570606da79`.
- Staged paths: none.
- Working tree: 97 status entries (60 modified tracked paths, 37 untracked paths, 0 staged).
- ARTEX integration, Phase 2B–2F reports, generated artifacts, migrations, and unrelated work were preserved.

No files were staged, committed, reset, rebased, stashed, cleaned, or discarded. No production database, credential, or customer data was accessed.

## C. Phase 2B–2F integration matrix

| Phase | Integrated capability reviewed | Evidence | Result | Remaining limitation |
|---|---|---|---|---|
| 2B | Fail-closed tenant repository, SQL caller paths, roles/assignments, reports/evidence | `phase-2b-final-acceptance-2026-11-25.md`, `phase-2b-final-sql-audit-2026-11-25.md`; current authorization/tenant tests | Verified | Service-level authorization over SQLite; no database-native row security |
| 2C | Persistent identity, sessions, lockouts, TOTP/recovery, invitations, migration | `phase-2c-final-security-acceptance-review-2026-11-25.md`; `phase2c-final-20261125-r2.xml` (885 passing) | Verified with limitations | Fault-injected migration retry, some HTTP TOTP happy paths, invitation audit-row assertions, and explicit DB absolute-TTL/revoked-status tests remain follow-up coverage |
| 2D | Durable jobs, leases, fencing, action attempts, cancellation, recovery | `phase-2d-durable-job-orchestration-report.md`; `phase2d-final-20261125-r3.xml` (890 passing); current durable tests | Verified | No exactly-once external execution claim; uncertain outcomes require reconciliation |
| 2E | Admission quotas, fairness, deadlines, subprocess supervision, durable accounting | `phase-2e-resource-governance-report.md`; `phase2e-final-20261125-r2.xml` (896 passing); current governance tests | Verified with limitations | Several configuration fields are ceilings not dynamically wired into all parsers/providers; POSIX process-group branch not run here |
| 2F | Unified organization/engagement workspace, governed workflows, jobs, account security, context switching | `phase-2f-unified-frontend-report.md`; current frontend suite (81 passing) | Verified with limitations | Direct chain form, reports/audit tabs, and mobile viewport have type/build or indirect coverage rather than dedicated browser tests; no reconciliation UI because backend endpoint does not exist |

## D. Tenant-isolation matrix

| Boundary | Evidence | Result |
|---|---|---|
| Missing/invalid organization context | `SQLiteRepository._owned_record`; tenant security tests | Fails closed with `StorageError` or non-disclosure response |
| Cross-organization records, findings, evidence, reports, jobs | Phase 2B final SQL register (380 live sites: 311 tenant-sensitive, 24 global, 45 privileged, 0 unresolved/unsafe); current tenant and authorization tests | No confirmed cross-organization access |
| Role/assignment intersection | `test_authorization_matrix_complete.py`; current focused selection | Viewer/Auditor assignments do not elevate write/review/manage authority; Member assignments are operation-specific; Owner/Admin branches remain explicit |
| Revoked membership/assignment | Current matrix tests and identity/session tests | Protected access is denied |
| Pagination/count/bulk/repository writes | Phase 2B tenant repository tests and SQL audit | Shared ownership predicates and fail-closed writes preserved |
| Streaming/context propagation | Phase 2B final audit; SSE/JSONL regressions | Principal is re-established inside generators |
| Diagnostics/admin SQL | Local-operator identity checks and Phase 2E quota diagnostics test | Ordinary organization members cannot access local-operator diagnostics |

## E. Identity and session matrix

Verified through Phase 2C report and current focused run: Argon2id-backed password flow, legacy operator migration, TOTP replay prevention, one-use recovery codes, persistent lockouts, session rotation, logout/account-status revocation, CSRF, invitations, membership lifecycle, and restart survival.

The Phase 2C review explicitly left bounded follow-up coverage for fault-injected interrupted migration, some HTTP TOTP success paths, invitation audit-row assertions, explicit DB-mode absolute expiry/revoked status, and concurrent rotation contention. These are not observed vulnerabilities in the current implementation, but remain operational test gaps.

## F. Durable execution matrix

Verified: atomic claims, lease generations, heartbeat and expiry fencing, stale-worker recovery, immutable execution context, policy and approval revalidation, durable action attempts, cancellation before and during action, `outcome_uncertain`/`reconciliation_required` persistence, backup/restore preservation, and no automatic replay of uncertain external actions.

The implementation does not claim exactly-once external execution. A manual reconciliation endpoint is not implemented; operators must use the existing governed maintenance/recovery process.

## G. Resource-governance matrix

Enforced and tested: per-organization/global queue and active limits, workload concurrency, fair scheduling, queue-wait expiry, execution deadlines, maximum findings, durable accounting, cancellation, supervised subprocess timeout/output/cancellation, and Windows process-tree cleanup.

Documented as limitations: `archive_max_*`, parser output, network timeout/response, and safe-retry settings are validated as ceilings or settings while underlying parsers/providers use stricter hardcoded bounds or their own timeout controls. POSIX `start_new_session`/`killpg` behavior was inspected but not executed on this Windows host. Arbitrary Python thread CPU/memory isolation is not claimed.

## H. Frontend acceptance matrix

The current frontend suite verifies the unified job monitor, all eight durable states, no automatic retry for reconciliation-required jobs, quota visibility, organization/engagement switching, stale-state clearing, static-only malware triage, account security flows, session-expiry handling, and local-operator diagnostics visibility.

Fresh result: `npm test -- --run` → **20 files, 81 tests passed**. `npm run typecheck` passed. `npm run build` passed, including strict CSP verification. The build retains the existing Vite advisory for a 535.41 kB scene chunk.

## I. Backup and migration

`py -3.12 scripts/_phase2d_alembic_verify.py` passed all checks: upgrade to `0015_durable_job_leases_actions`, zero foreign-key violations, downgrade to `0014_multi_user_identity_sessions`, re-upgrade, and downgrade guard when durable action history exists. The test used disposable databases and did not touch the application database.

## J. Test evidence

### Current commands

- `py -3.12 -m pytest -q tests/unit/test_authorization_matrix_complete.py tests/unit/test_tenant_repository_security.py tests/unit/test_phase2c_identity_sessions.py tests/unit/test_phase2d_durable_jobs.py tests/unit/test_phase2e_acceptance_closure.py tests/unit/test_phase2e_resource_governance.py --junitxml artifacts/phase2g-focused-20261125-r1.xml` → **45 passed, 0 failed**; JUnit totals `tests=45 failures=0 errors=0 skipped=0`.
- `npm test -- --run` → **81 passed**.
- `npm run typecheck` → passed.
- `npm run build` → build and strict CSP passed.
- `py -3.12 scripts/_phase2d_alembic_verify.py` → all Alembic, FK, roundtrip, and downgrade-guard checks passed.
- `py -3.12 -m alembic heads` → `0015_durable_job_leases_actions (head)`.
- `git diff --check` → passed; Git emitted only existing CRLF normalization notices.

### Static analysis

- Targeted mypy on Phase 2E modules previously passed with 0 errors. A broader current command including `web/app.py` reports one known unrelated ARTEX error at `chinescan/integrations/artex/client.py:40` (`HTTPSConnection` receives `str | None`).
- Current Ruff selection reports legacy/style findings (152 in the broad selected set), primarily E501 and existing test/import debt. No global suppression or unrelated ARTEX refactor was performed. Phase reports attribute introduced findings separately.

### Tests not rerun

The complete 896-test Python suite was not rerun in Phase 2G because Phase 2F changed frontend files only and the latest backend full-suite artifact remains applicable. The current backend security-critical selection was rerun fresh. This is a bounded verification choice, not a claim that a new 896-test run occurred during Phase 2G.

## K. Deployment readiness

Supported model: authenticated loopback web dashboard, SQLite single-instance deployment, governed local workers, private managed evidence storage, and explicit local-operator maintenance. Before deployment, operators must validate credential storage, private evidence ACLs, encrypted/off-host backup handling, restore drills, loopback/reverse-proxy assumptions, and the documented resource-ceiling limitations. Public signup, distributed workers, Redis, PostgreSQL, Kubernetes, and multi-instance deployment are outside this phase.

## L. Known limitations and residual risks

1. No exactly-once external execution guarantee; uncertain outcomes require reconciliation.
2. No manual reconciliation endpoint or frontend action exists yet.
3. Several resource settings are not dynamically wired into every parser/provider; hardcoded stricter limits currently govern those paths.
4. POSIX process-group termination and multi-host behavior were not executed in this Windows environment.
5. Some Phase 2C HTTP and migration fault-injection cases remain follow-up tests.
6. Repository-wide Ruff is not clean because of inherited legacy/style and ARTEX-related findings.

None of these findings is a confirmed cross-organization access vulnerability or privilege escalation in the reviewed paths. They do prevent an unconditional “all operational requirements verified” claim.

## M. Final acceptance decision

**ACCEPTED WITH DOCUMENTED LIMITATIONS**

The critical Phase 2 security and reliability boundaries are verified by current focused tests and phase-local full-suite artifacts. The limitations above are explicit, bounded, and inherited/documented rather than concealed. Phase 3 work may proceed only with the understanding that reconciliation operations, dynamic resource-setting wiring, POSIX verification, and the remaining identity coverage are follow-up work.
