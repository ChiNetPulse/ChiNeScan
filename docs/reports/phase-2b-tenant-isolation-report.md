# Phase 2B Tenant Isolation Report

**Status: INCOMPLETE — do not proceed to Phase 2C**
**Date:** 2026-11-25
**Repository:** `C:\GitHub\Chinescan`
**Branch / HEAD:** `main` / `c09d3f150003421136790c42ffa96d570606da79` (unchanged)

## Root cause

`SQLiteRepository._owned_record()` returned `None` when `_organization_context` was unset. Callers appended that predicate only when non-`None`, so the missing-context case removed the tenant condition and allowed reads across organizations. `_ensure_record_ownership()` also returned silently when context was absent, allowing newly written records without ownership metadata. The repository default therefore treated absence of authorization as global access.

## Recovery and final authorization model implemented so far

The partial `system_context()`/`_system_context`/`_owner_filter()` bypass proposal was removed. There is no general `system_context`, skip-tenant flag, or absent-context fallback in the current repository implementation.

- **Organization context:** `organization_context()` rejects empty identifiers and verifies an active organization in SQLite before setting the context.
- **Member context:** `member_context()` verifies active user, active organization, and active membership. It records the principal and read/write mode. Repository ownership predicates constrain member access to the organization and, for engagement-owned data, to the principal's active engagement assignments and assignment role when writing.
- **Local CLI context:** legacy local CLI entry points now use `_local_cli_repository()`, which requires the active local operator credential and stable identity, provisions/resolves that operator's personal organization, and scopes the repository to that organization. This preserves the legacy CLI as personal local data access; it is not cross-organization access. Governed CLI commands bind an explicit member context after their existing identity/membership checks.
- **Maintenance:** no generic maintenance principal or bypass was added. Explicit maintenance-only repository APIs remain deferred; internal maintenance that accesses tenant records must currently use an explicit organization authorization scope.
- **Workers:** local worker managers were scoped to the operator's personal organization. This does **not** yet satisfy the required job-derived, immutable worker principal for all governed worker paths; this remains an incomplete boundary.
- **Tests:** the shared `repository` test fixture now explicitly establishes a synthetic operator/personal-org principal. New tenant tests create separate organizations explicitly. Production repository defaults remain fail-closed.

`_owned_record()` raises `StorageError` without an organization. `_ensure_record_ownership()` also raises when absent, and ownership records are assigned on writes. The new regression test reproduces the original unscoped read/list/count/page/write condition and asserts denial. Repository filters are applied to get, get-many, list/page, count/group counts, updates/deletes, and domain queue/acknowledgement queries that use repository accessors. Direct execution-governance SQL is explicitly organization-keyed; it is not protected by `_owned_record()` and needs continued independent review.

## API routes and reports

Middleware now permits authenticated organization members on `/api/scans`, `/api/cases`, `/api/findings`, and `/api/reports` without requiring the server's local operator identity. It validates the selected organization against active membership, sets member context, denies mutating methods to roles outside owner/admin/member, and leaves other legacy API families behind the local-operator gate. Inaccessible repository resources return the existing not-found response where the handler uses repository lookup.

Report generation and download handlers use the scoped repository-backed reporting data path. The JSONL streaming response now re-establishes the member context while yielding each finding batch, because the request middleware context has already exited by the time a streaming body is consumed. Existing redaction and report storage behavior were not intentionally changed.

**Not complete:** route-level engagement assignment semantics, complete reviewer/assessor/observer role matrix, and read/write permission distinctions have not been covered comprehensively by regression tests. Report provenance, evidence access, engagement scope history, and audit behavior require a full successful integration run before these routes can be accepted.

## Compatibility decisions and remaining compatibility work

Standalone code assessment, logs, reports, scan history, case/project/GitHub workflows use the explicit local operator's personal organization. Governed CLI commands use a validated organization membership. Setup/bootstrap retains the existing operator identity and organization data. No migration was added.

The first complete Python run shows many existing fixtures and service tests directly construct a repository and operate on tenant data without a principal. Those calls are now denied, as intended, but the authorized caller/fixture repairs are incomplete. Do not resolve these failures by making repository defaults permissive or by wrapping every service in an all-tenant context.

## Files changed by this Phase 2B attempt

- `chinescan/core/storage/sqlite.py`
- `chinescan/core/organizations.py`
- `chinescan/web/app.py` (contains pre-existing ARTEX integration edits; those were preserved, and only tenant middleware/CSRF/streaming hunks were added for this task)
- `chinescan/cli/commands.py`
- `chinescan/cli/chain_commands.py`
- `chinescan/core/github_import.py`
- `chinescan/core/malware_project_scan.py`
- `chinescan/web/chain_trace_jobs.py`
- `chinescan/web/code_jobs.py`
- `chinescan/web/log_jobs.py`
- `chinescan/web/malware_jobs.py`
- `tests/conftest.py`
- `tests/unit/test_cases.py`
- `tests/unit/test_organizations.py`
- `tests/unit/test_web_api.py`
- `tests/unit/test_tenant_repository_security.py` (new)

Pre-existing dirty configuration and ARTEX integration files remain untouched: `chinescan/core/config/io.py`, `chinescan/core/config/settings.py`, `configs/chinescan.example.toml`, `chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, `scripts/make_cover.py`, and `tests/unit/test_artex_integration.py`. The architecture audit and implementation plan were already untracked at recovery start. No stage, commit, reset, clean, stash, or rebase was performed. No database migration was created.

## Tests and verification

- Focused tenant repository tests plus report/malware API selections: **6 passed**.
- External-report and malware route regressions: **2 passed**.
- Authenticated JSONL streaming route: **1 passed**.
- Full Python suite: **118 failed, 730 passed, 5 deselected**, 353 warnings, 1163.19 seconds. This does not meet the completion condition. Failures span unscoped legacy test/service setup as well as other compatibility paths and need category-by-category repair.
- `py -3.12 -m compileall -q chinescan`: passed.
- Frontend tests: **77 passed** across 19 files.
- Frontend TypeScript check: passed.
- Frontend production build and CSP check: passed (Vite emitted an existing large-chunk advisory).
- `py -3.12 -m mypy chinescan/core/storage/sqlite.py chinescan/core/organizations.py chinescan/web/app.py chinescan/cli/commands.py`: failed on one unrelated/pre-existing ARTEX typing issue in `chinescan/integrations/artex/client.py:40` (`str | None` passed to `HTTPSConnection`). Tenant files produced no remaining mypy errors.
- Ruff: failed with 57 reported violations in the checked implementation/test files; includes import ordering, unused imports, and line length. Must be cleaned and rerun.
- Alembic: one head, `0013_governed_chain_trace`.
- `git diff --check`: passed; Git reported line-ending conversion warnings only.

The confirmed Phase 1 baseline was 844 passed, 0 failed, 5 deselected. This run has 114 fewer passes and 118 failures relative to that baseline (the current test tree also includes pre-existing ARTEX tests). Phase 2B is not complete until compatibility failures are repaired and the complete Python suite, lint, and scoped security regression tests pass.

## Remaining limitations

1. Repair and classify all Python compatibility failures at their authorized caller or explicit test-fixture boundary, preserving default denial.
2. Implement and test job-derived worker authorization for governed workers; local operator worker scopes are not a substitute.
3. Add route tests for non-operator organization members, membership revocation, cross-organization not-found behavior, assignments, role-specific writes, and report download controls.
4. Audit all direct SQL and every resource category (records, scans, cases, findings, evidence, reports, queue items, assets, jobs/results, and engagement data) beyond repository accessor call paths.
5. Resolve Ruff violations and verify whether the single ARTEX mypy finding is pre-existing by comparison to the untouched baseline; ARTEX remains out of scope.
6. Run the required Phase 1 acceptance commands and repeat the complete Python suite after repairs.

**Review decision:** Keep Phase 2B marked incomplete. Do not proceed to Phase 2C.

## Reproduced failure analysis

A second complete run reproduced exactly **118 failed, 730 passed, 5 deselected**. The per-test traceback inventory and grouped corrections are in `docs/reports/phase-2b-failure-analysis.md`.

The 118 break down by observed failure signal: 103 callers/tests reach tenant repository methods without an established organization principal; 9 CLI tests cannot establish the local operator from their credential/identity setup; 5 worker/application startup cases attempt local operator worker scope before a valid operator scope exists; and 1 asynchronous worker test times out after the worker fails to complete. These are observed execution failures, not authorization bypasses. The corresponding caller principal setup, worker lifecycle behavior, and tests remain to be repaired. The failure analysis records each test name and available stack frame.

This confirms the compatibility work is incomplete. Repository denial remains intentional; remediation must establish the correct principal at each authorized entry point, and distinguish application regressions from test setup needing explicit principals. No test was removed or weakened.

## Implementation backlog and incremental status

The backlog below maps the four failure groups in `phase-2b-failure-analysis.md` to corrective work. Status is intentionally conservative: focused test results are not a substitute for the required complete suite.

| Priority | Failure group | Count from reproduced run | Shared cause and caller boundary | Required implementation / regression | Status |
|---|---|---:|---|---|---|
| 1 | Missing repository principal | 103 | Legacy unit/service callers and worker paths accessed owned data without an explicit principal. | Keep repository access fail-closed; establish personal-organization CLI identity or validated member/job principal at the real entry point; use explicit principals in integration fixtures; cover missing-context and ownership behavior. | In progress; several CLI, service, recovery, and API tests repaired. Focused combined rerun pending. |
| 2 | Worker startup without local operator | 5 | Local worker managers assumed a bootstrapped operator even when the app was serving setup/diagnostics. | Keep setup/diagnostics available without fabricating authority; start local-only workers only when operator context is available; test readiness and worker lifecycle. | Targeted diagnostics regression passed; combined rerun pending. |
| 3 | CLI credential/principal setup | 9 | CLI tests/callers relied on absent or mismatched local operator credential identity. | Resolve the explicit local credential to its personal organization at the CLI boundary; avoid repeated bootstrap writes; exercise existing standalone commands with matching identity. | Caller/fixture updates made; combined rerun pending. |
| 4 | Worker thread/context propagation | 1 | A thread-based worker failed to finish because request context was not available in the worker thread. | Establish scoped authority in the worker thread from its explicit local or persisted job identity; retain cleanup; regression-test thread execution. | Earlier worker tests passed; governed worker now reconstructs requester membership from revalidated persisted job; focused provenance and worker tests passed (10 including tenant suite). Combined rerun pending. |

### Implementation checklist

- [x] Preserve fail-closed behavior for absent/invalid organization context and tenant-owned repository operations.
- [x] Keep local CLI access personal-organization scoped and credential-derived; do not infer operator authority from a missing request.
- [x] Allow setup/diagnostics when local worker authorization is unavailable without creating a local principal.
- [x] Reconstruct governed worker repository access from the persisted job's organization and requester after job claim and policy revalidation; ensure nested same-organization adapter contexts retain only the validated principal.
- [x] Complete post-change verification of the previously failing compatibility groups; the full suite now passes after 18 residual failures were fixed.
- [ ] Complete a direct-SQL audit for every application-facing access path, especially all maintenance/setup operations and cross-service reads.
- [x] Add route permission/assignment tests for owner, admin, assigned member lead/assessor/reviewer, auditor, viewer, observer, unassigned, and revoked membership behavior across scans, findings, cases, and reports.
- [x] Verify report download and JSONL streaming for assigned users, and deny unassigned/cross-organization report and resource access.
- [x] Run the complete Python suite, frontend checks, Ruff, targeted mypy, Alembic head, and `git diff --check`; lint/type findings are recorded below.
- [x] Record exact repository status and changed-file inventory below.

## Final remediation and verification (2026-11-25)

### Resolved compatibility groups

The reproduced failure groups were traced to callers that had not established the intended principal. The repository default was not relaxed.

- CLI workflows now resolve and bind the authenticated local operator to the operator's personal organization. CLI bootstrap is idempotent, avoids routine ownership rewrites, and refuses to silently adopt existing unowned data.
- Test fixtures that exercise authorized local workflows create a synthetic operator and explicitly bind the personal-organization principal. Repository security tests continue to use separate organizations and verify denied behavior.
- Local application workers re-establish operator scope inside their worker thread. Governed workers instead reconstruct a writable member scope from the persisted job's organization and requester after claim and policy revalidation; they do not inherit the web thread's ContextVars or local operator authority.
- Repository assessment project reads occur only after the service validates the requested engagement lead and are scoped to that organization. The project lookup is kept within that validated scope.
- Diagnostics, migration, chain, dashboard, and repository-assessment callers/tests were corrected at their entry boundaries. Legacy records without ownership metadata remain in SQLite but are unavailable through normal tenant-aware repository methods.
- Failed-CSRF and repeated-login alerts now persist only the server-generated security signal. Those paths no longer refresh the dashboard by reading tenant records, and failed login handling no longer enters local-operator context.

The original 118-failure run was followed by a full run with 18 remaining failures. Those 18 were individually enumerated in the JUnit output: 12 repository-assessment callers, two chain paths, one dashboard fixture, one migration compatibility assertion, one route-security fixture, and one storage migration assertion. They were corrected by explicit principal establishment, job-thread scope reconstruction, or preserving-but-denying unowned legacy payloads. The final full run has zero failures.

### Final authorization boundaries

`SQLiteRepository._owned_record()` raises `StorageError` if organization context is absent. It always emits an ownership predicate for the active organization. A member principal additionally requires active membership and either an organization role that grants broad read access (owner/admin/auditor/viewer) or an active assignment to the record's engagement. Writes require a writable member context and, for non-admin members, an active lead/assessor/reviewer assignment. Observer and unassigned members cannot mutate or access engagement-owned records. Cross-organization lookup returns no row; updates/deletes cannot affect a row hidden by the same predicate.

Create/save paths call `_ensure_record_ownership()` and reject absent scope. Existing owner metadata is checked before replacement; bulk saves validate each item in the same transaction. List, page, count, grouped count, queue, acknowledgement, and delete paths use the repository ownership condition. Pagination totals are computed from the same scoped base query as the returned page. No `system_context`, bypass flag, or absent-context global fallback exists.

The HTTP middleware requires a live session and resolves the selected organization through active membership. `/api/scans`, `/api/cases`, `/api/findings`, and `/api/reports` use member context; inaccessible resources are returned as not found. Mutations require owner/admin/member organization role, and repository predicates further enforce engagement assignment. Existing local-operator-only route families remain gated by operator identity and personal-organization selection. A request cannot gain local-operator scope by omitting an organization or by failing CSRF.

Scan and case report downloads share the resource predicates. JSONL streaming captures the selected organization and authenticated user, then revalidates membership and reinstalls member context for each yielded batch. Streaming does not switch organization and cleans up context through `with` blocks when iteration exits. Existing rendering and redaction paths are retained.

Direct SQL paths were reviewed by category: execution governance/job lifecycle queries constrain job IDs and revalidate immutable organization, engagement, requester, target, technique, scope revision, authorization, and approval state; repository-assessment SQL constrains organization and engagement and performs service authorization before accessing projects/snapshots; log and malware evidence services validate organization/engagement before reads or mutation; dashboard alert state is local application data, and security-signal writes are isolated from tenant-record reads. This review does not provide a database row-level security layer; direct SQL remains dependent on the explicit checks in those services.

### Worker, assignment, and report behavior

The governed worker uses `member_context(job.organization_id, job.requester_user_id, write=True)` after `claim_job()` and `revalidate_job()`. The persisted immutable execution context supplies the worker identity and the adapter parameters; policy revalidation still precedes external action. Approval consumption remains atomic and one-use at the external-action boundary. Result records retain job provenance. Local chain/code/log/malware workers use a separately established local operator principal in the worker thread and remain restricted to the personal organization.

Route regression coverage now exercises owner/admin access, assigned member lead/assessor/reviewer writes, observer read-only behavior, auditor/viewer read-only behavior, unassigned-member denial, revoked membership, cross-organization scan denial, finding access, case creation/report access, scan report downloads, and JSONL streaming. An assignment-role cross-product beyond these representative allowed/denied combinations is not exhaustively tested.

### Final verification

- Python: **852 passed, 0 failed, 5 deselected**, 543 warnings, 5,206.35 seconds. JUnit: `artifacts/phase2b-full-verified.xml`.
- Focused security signal/CSRF/dashboard selection: **7 passed**. Route-role matrix regression: **1 passed**. Prior worker/provenance and tenant selection: **10 passed**; compatibility selection after caller fixes: **19 passed**.
- Frontend: **77 passed** in 19 files; TypeScript passed; production build and strict-CSP check passed. Vite reported the existing large-chunk advisory.
- Ruff: run across the selected implementation and test files; **258 findings** (250 E501, 5 I001, 3 F401). These are predominantly existing line-length findings in legacy modules. The check is not clean; no broad formatting sweep was applied to unrelated files. Raw JSON: `artifacts/phase2b-ruff-final.json`.
- Targeted mypy: **one error** remains in unrelated ARTEX code at `chinescan/integrations/artex/client.py:40` (`str | None` passed to `HTTPSConnection`). Tenant authorization code had no reported mypy errors in the targeted run. ARTEX was not modified for this finding.
- Alembic: one head, `0013_governed_chain_trace`.
- `git diff --check`: passed; Git emitted only line-ending conversion warnings.
- Test-count difference from the Phase 1 baseline: 852 passed versus 844 passed, with the same 5 deselected. The net increase of 8 tests is the seven tenant repository/route security tests and one dashboard security-signal regression added in this work. ARTEX tests were already part of the current working tree before this recovery.

### Remaining limitations and status

**Phase 2B remains INCOMPLETE for review.** Functional and full-suite verification pass, but Ruff is not clean, targeted mypy reports the unrelated ARTEX issue, and the direct-SQL review is service-level rather than database-enforced. The representative route matrix tests do not cover every Cartesian combination of role, assignment, resource, and verb. Unowned historical records are preserved but require an explicit future recovery/ownership process before normal application access; no migration was added. No Phase 2C work was started.

### Exact final Git status

Branch `main`; HEAD `c09d3f150003421136790c42ffa96d570606da79`; staged changes: none. No stage, commit, reset, clean, stash, or rebase was performed.

Phase 2B modified tracked files:

- `chinescan/cli/chain_commands.py`
- `chinescan/cli/commands.py`
- `chinescan/core/dashboard_intelligence.py`
- `chinescan/core/execution_governance.py`
- `chinescan/core/github_import.py`
- `chinescan/core/malware_project_scan.py`
- `chinescan/core/organizations.py`
- `chinescan/core/repository_assessment.py`
- `chinescan/core/storage/sqlite.py`
- `chinescan/web/app.py` (contains pre-existing ARTEX integration changes; only authorization/security hunks were altered for Phase 2B)
- `chinescan/web/chain_trace_jobs.py`
- `chinescan/web/code_jobs.py`
- `chinescan/web/log_jobs.py`
- `chinescan/web/malware_jobs.py`
- `scripts/recovery_acceptance.py`
- `tests/conftest.py`
- `tests/unit/test_cases.py`
- `tests/unit/test_chain_trace.py`
- `tests/unit/test_code_jobs.py`
- `tests/unit/test_code_scan.py`
- `tests/unit/test_dashboard_alerts.py`
- `tests/unit/test_diagnostics.py`
- `tests/unit/test_engagement_security.py`
- `tests/unit/test_github_import.py`
- `tests/unit/test_github_projects.py`
- `tests/unit/test_log_analysis.py`
- `tests/unit/test_malware_project_scan.py`
- `tests/unit/test_managed_malware.py`
- `tests/unit/test_migration.py`
- `tests/unit/test_organizations.py`
- `tests/unit/test_projects.py`
- `tests/unit/test_projects_cli.py`
- `tests/unit/test_recovery.py`
- `tests/unit/test_reporting.py`
- `tests/unit/test_repository_assessment.py`
- `tests/unit/test_route_security_inventory.py`
- `tests/unit/test_storage.py`
- `tests/unit/test_tenant_repository_security.py` (new)
- `tests/unit/test_trends.py`
- `tests/unit/test_web_api.py`

Phase 2B-created/updated artifacts:

- `artifacts/phase2b-focused.xml`
- `artifacts/phase2b-full-final.xml`
- `artifacts/phase2b-full-verified.xml`
- `artifacts/phase2b-full.xml`
- `artifacts/phase2b-junit.xml` (from the earlier failure-analysis run)
- `artifacts/phase2b-ruff-final.json`
- `docs/reports/phase-2b-failure-analysis.md`
- `docs/reports/phase-2b-tenant-isolation-report.md`

Pre-existing unrelated dirty/untracked ARTEX/config work was preserved: `chinescan/core/config/io.py`, `chinescan/core/config/settings.py`, `configs/chinescan.example.toml`, `chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, `scripts/make_cover.py`, and `tests/unit/test_artex_integration.py`. The architecture audit and implementation plan were also already untracked and were left untouched.

## Follow-up verification after the reproduced full run

After recording the full-run JUnit result, local worker startup was changed to deny startup without a bootstrapped local operator while allowing the application to continue serving diagnostics/authentication. The targeted regression `tests/unit/test_diagnostics.py::test_ready_fails_for_corrupt_credentials_unwritable_database_missing_dirs_and_frontend` now passes. The tenant repository security tests and authenticated JSONL stream test were rerun in the same focused selection: **6 passed**. The full suite has not been rerun after this lifecycle fix, so the previously reported full-suite totals remain the last complete-run result, not a claim about the current revision.

## Phase 2B closure pass (2026-11-25)

This section supersedes stale intermediate verification figures above where they differ. It records the closure-pass changes and fresh results; the full Python run is still in progress at the time of this edit.

### Direct-SQL inventory and classification

An AST inventory and source search covered all application Python modules. There are 381 `execute`/`exec_driver_sql` call sites in 12 modules (338 SQLAlchemy `.execute` calls and 43 explicit driver executions); no `sqlalchemy.text()` raw text query was found. This count is call sites, not a count of distinct logical queries. No web route module executes direct SQL: route access flows through authorization services and the tenant-aware repository.

| Module | Call sites | Classification / boundary |
|---|---:|---|
| `core/storage/sqlite.py` | 37 | Tenant record operations share `_owned_record` ownership predicates. Read, page/count, grouped count, queue, acknowledgement, mutation, and bulk paths are scoped. Missing context raises `StorageError`; membership and active assignment are revalidated for member contexts. |
| `core/organizations.py` | 71 | Organization, membership, engagement, role, assignment and audit operations constrain IDs by organization and verify actor authority. `ensure_operator` performs the one-time legacy ownership mapping for records that have no ownership row, places them in the pre-multi-user local operator's personal organization, and records counts in `organization_bootstrap_reports`; existing ownership is preserved. |
| `core/engagement_security.py` | 55 | Membership, assignment, engagement, scope, authorization, approval and evidence metadata paths validate active identities/roles and constrain rows with organization and engagement IDs. Approval consumption remains atomic. |
| `core/execution_governance.py` | 60 | Queue dispatch may inspect queued job IDs globally, but claim and subsequent processing re-load the persisted job and validate its immutable organization, requester, engagement, target, technique, scope, authorization and approval context before execution. Results are bound to job provenance. |
| `core/execution_adapters.py` | 4 | Adapter result and evidence binding paths receive the validated persisted execution context; no request-supplied organization is used by the worker. |
| `core/log_evidence.py` | 28 | Snapshot, quota, asset and audit SQL uses organization/engagement predicates, rechecks active operation rights at mutation boundaries, and stores private content under organization-specific roots. Worker verification receives persisted execution-context IDs. |
| `core/malware_evidence.py` | 18 | Snapshot and quota queries use organization/engagement predicates. The closure pass fixed `get()` so callers must supply an active readable principal; the API execution preflight now returns not-found before job admission for unassigned/cross-organization evidence. Hold/delete updates repeat organization and engagement predicates. |
| `core/repository_assessment.py` | 57 | Snapshot, binding, attestation and quota operations validate lead/engagement authorization before SQL or local registry resolution and constrain persistent rows by organization/engagement. |
| `core/dashboard_alerts.py` | 17 | Local dashboard alert state, not tenant records. Security-signal insertion is a bounded insert of server-created signal data; failed-CSRF/login paths do not trigger tenant record scans. |
| `core/diagnostics.py` | 6 | Database health/PRAGMA metadata only; does not return tenant record payloads. |
| `core/storage/recovery.py` | 27 | Whole-database backup/restore/retention operations are global maintenance operations invoked by explicit local CLI commands. They preserve ownership/provenance tables and validate backups; they do not expose query results through web APIs. |
| `cli/commands.py` | 1 | Local database bootstrap existence check, after explicit operator credential validation. |

The 43 `exec_driver_sql` calls are transaction starts, read-only integrity checks, diagnostics, and local dashboard SQL; tenant data access is expressed through SQLAlchemy statements in the scoped services. Bulk operations validate each item in one transaction. The pre-existing legacy ownership mapping is retained as a compatibility migration for data from the former single-operator model and is auditable; it is not a general tenant query path. No general-purpose bypass principal or flag exists. SQLite has no row-level security, so this protection remains application-enforced.

### Additional regression coverage and policy matrix

The API regression now checks foreign-organization scan, finding, and report identifiers return 404; scan pagination does not include the foreign scan; a member with a revoked engagement assignment immediately loses scan access; and a same-organization unassigned member cannot create a malware evidence execution job. The malware test creates actual evidence in another organization and verifies that the member receives the same not-found response and that the execution-job table is unchanged. Existing matrix assertions exercise owner/admin writes, auditor/viewer reads and write denials, member lead/assessor/reviewer writes, observer read-only access, unassigned-member denial, revoked membership, case/report access, and JSONL streaming. The matrix is representative and still is not a Cartesian test of every role × assignment × resource × verb combination.

The malware evidence preflight was an unsafe direct service path: `get()` previously accepted caller-provided organization and engagement IDs and queried before checking authorization. It now checks `_can_read()` first, and the API calls it with the authenticated `session.user_id`. A denied request is non-disclosing and cannot reach job creation. Worker `verify()` methods remain restricted to internal governed adapters and take organization/engagement/asset/snapshot IDs from the persisted immutable execution context.

### Ruff attribution

The previous report's 258 figure is the baseline for its 12-file targeted set. Re-running that exact set after the closure edits reports 245 findings: 237 `E501`, 5 `I001`, and 3 `F401` (13 fewer). Expanding the targeted set to include malware evidence implementation/API/tests also reports clean for those additional files. The repo-wide scan reports 404 findings. A changed-line/untracked-file attribution pass found 17 findings in pre-existing config, ARTEX, cover-script and unrelated tests; none remain on Phase 2B-added lines after targeted cleanup. These pre-existing/unrelated findings were not reformatted or suppressed. ARTEX findings remain untouched.

### Verification status

- Focused current-tree run: `py -3.12 -m pytest -q tests/unit/test_governed_malware.py tests/unit/test_tenant_repository_security.py` — 12 passed, 0 failed.
- Frontend: `npm test` — 77 passed in 19 files; `npm run typecheck` passed; `npm run build` passed and included the strict-CSP built-asset check (Vite retains its chunk-size advisory).
- Targeted mypy on `sqlite.py`, `malware_evidence.py`, `engagement_security.py`, and `malware_evidence_api.py` — success, no issues in 4 source files.
- Alembic head — `0013_governed_chain_trace (head)`.
- Repo-wide Ruff: 404 findings; exact targeted set: 245, detailed above.
- `git diff --check` passed before final report edits; rerun at completion.
- Fresh full Python suite: **IN PROGRESS**; its result will replace this line before final review.

### Closure-pass files

Additional closure-pass source changes: `chinescan/core/malware_evidence.py`, `chinescan/web/malware_evidence_api.py`, `chinescan/cli/commands.py`, `chinescan/core/repository_assessment.py`, `chinescan/core/storage/sqlite.py`, and authorization test additions in `tests/unit/test_tenant_repository_security.py` and `tests/unit/test_governed_malware.py`. No unrelated ARTEX source was modified. No migration was added. No Phase 2C work was started.
# Phase 2B Tenant Isolation Report

**Status: INCOMPLETE — do not proceed to Phase 2C**
**Date:** 2026-11-25
**Repository:** `C:\GitHub\Chinescan`
**Branch / HEAD:** `main` / `c09d3f150003421136790c42ffa96d570606da79` (unchanged)

## Root cause

`SQLiteRepository._owned_record()` returned `None` when `_organization_context` was unset. Callers appended that predicate only when non-`None`, so the missing-context case removed the tenant condition and allowed reads across organizations. `_ensure_record_ownership()` also returned silently when context was absent, allowing newly written records without ownership metadata. The repository default therefore treated absence of authorization as global access.

## Recovery and final authorization model implemented so far

The partial `system_context()`/`_system_context`/`_owner_filter()` bypass proposal was removed. There is no general `system_context`, skip-tenant flag, or absent-context fallback in the current repository implementation.

- **Organization context:** `organization_context()` rejects empty identifiers and verifies an active organization in SQLite before setting the context.
- **Member context:** `member_context()` verifies active user, active organization, and active membership. It records the principal and read/write mode. Repository ownership predicates constrain member access to the organization and, for engagement-owned data, to the principal's active engagement assignments and assignment role when writing.
- **Local CLI context:** legacy local CLI entry points now use `_local_cli_repository()`, which requires the active local operator credential and stable identity, provisions/resolves that operator's personal organization, and scopes the repository to that organization. This preserves the legacy CLI as personal local data access; it is not cross-organization access. Governed CLI commands bind an explicit member context after their existing identity/membership checks.
- **Maintenance:** no generic maintenance principal or bypass was added. Explicit maintenance-only repository APIs remain deferred; internal maintenance that accesses tenant records must currently use an explicit organization authorization scope.
- **Workers:** local worker managers were scoped to the operator's personal organization. This does **not** yet satisfy the required job-derived, immutable worker principal for all governed worker paths; this remains an incomplete boundary.
- **Tests:** the shared `repository` test fixture now explicitly establishes a synthetic operator/personal-org principal. New tenant tests create separate organizations explicitly. Production repository defaults remain fail-closed.

`_owned_record()` raises `StorageError` without an organization. `_ensure_record_ownership()` also raises when absent, and ownership records are assigned on writes. The new regression test reproduces the original unscoped read/list/count/page/write condition and asserts denial. Repository filters are applied to get, get-many, list/page, count/group counts, updates/deletes, and domain queue/acknowledgement queries that use repository accessors. Direct execution-governance SQL is explicitly organization-keyed; it is not protected by `_owned_record()` and needs continued independent review.

## API routes and reports

Middleware now permits authenticated organization members on `/api/scans`, `/api/cases`, `/api/findings`, and `/api/reports` without requiring the server's local operator identity. It validates the selected organization against active membership, sets member context, denies mutating methods to roles outside owner/admin/member, and leaves other legacy API families behind the local-operator gate. Inaccessible repository resources return the existing not-found response where the handler uses repository lookup.

Report generation and download handlers use the scoped repository-backed reporting data path. The JSONL streaming response now re-establishes the member context while yielding each finding batch, because the request middleware context has already exited by the time a streaming body is consumed. Existing redaction and report storage behavior were not intentionally changed.

**Not complete:** route-level engagement assignment semantics, complete reviewer/assessor/observer role matrix, and read/write permission distinctions have not been covered comprehensively by regression tests. Report provenance, evidence access, engagement scope history, and audit behavior require a full successful integration run before these routes can be accepted.

## Compatibility decisions and remaining compatibility work

Standalone code assessment, logs, reports, scan history, case/project/GitHub workflows use the explicit local operator's personal organization. Governed CLI commands use a validated organization membership. Setup/bootstrap retains the existing operator identity and organization data. No migration was added.

The first complete Python run shows many existing fixtures and service tests directly construct a repository and operate on tenant data without a principal. Those calls are now denied, as intended, but the authorized caller/fixture repairs are incomplete. Do not resolve these failures by making repository defaults permissive or by wrapping every service in an all-tenant context.

## Files changed by this Phase 2B attempt

- `chinescan/core/storage/sqlite.py`
- `chinescan/core/organizations.py`
- `chinescan/web/app.py` (contains pre-existing ARTEX integration edits; those were preserved, and only tenant middleware/CSRF/streaming hunks were added for this task)
- `chinescan/cli/commands.py`
- `chinescan/cli/chain_commands.py`
- `chinescan/core/github_import.py`
- `chinescan/core/malware_project_scan.py`
- `chinescan/web/chain_trace_jobs.py`
- `chinescan/web/code_jobs.py`
- `chinescan/web/log_jobs.py`
- `chinescan/web/malware_jobs.py`
- `tests/conftest.py`
- `tests/unit/test_cases.py`
- `tests/unit/test_organizations.py`
- `tests/unit/test_web_api.py`
- `tests/unit/test_tenant_repository_security.py` (new)

Pre-existing dirty configuration and ARTEX integration files remain untouched: `chinescan/core/config/io.py`, `chinescan/core/config/settings.py`, `configs/chinescan.example.toml`, `chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, `scripts/make_cover.py`, and `tests/unit/test_artex_integration.py`. The architecture audit and implementation plan were already untracked at recovery start. No stage, commit, reset, clean, stash, or rebase was performed. No database migration was created.

## Tests and verification

- Focused tenant repository tests plus report/malware API selections: **6 passed**.
- External-report and malware route regressions: **2 passed**.
- Authenticated JSONL streaming route: **1 passed**.
- Full Python suite: **118 failed, 730 passed, 5 deselected**, 353 warnings, 1163.19 seconds. This does not meet the completion condition. Failures span unscoped legacy test/service setup as well as other compatibility paths and need category-by-category repair.
- `py -3.12 -m compileall -q chinescan`: passed.
- Frontend tests: **77 passed** across 19 files.
- Frontend TypeScript check: passed.
- Frontend production build and CSP check: passed (Vite emitted an existing large-chunk advisory).
- `py -3.12 -m mypy chinescan/core/storage/sqlite.py chinescan/core/organizations.py chinescan/web/app.py chinescan/cli/commands.py`: failed on one unrelated/pre-existing ARTEX typing issue in `chinescan/integrations/artex/client.py:40` (`str | None` passed to `HTTPSConnection`). Tenant files produced no remaining mypy errors.
- Ruff: failed with 57 reported violations in the checked implementation/test files; includes import ordering, unused imports, and line length. Must be cleaned and rerun.
- Alembic: one head, `0013_governed_chain_trace`.
- `git diff --check`: passed; Git reported line-ending conversion warnings only.

The confirmed Phase 1 baseline was 844 passed, 0 failed, 5 deselected. This run has 114 fewer passes and 118 failures relative to that baseline (the current test tree also includes pre-existing ARTEX tests). Phase 2B is not complete until compatibility failures are repaired and the complete Python suite, lint, and scoped security regression tests pass.

## Remaining limitations

1. Repair and classify all Python compatibility failures at their authorized caller or explicit test-fixture boundary, preserving default denial.
2. Implement and test job-derived worker authorization for governed workers; local operator worker scopes are not a substitute.
3. Add route tests for non-operator organization members, membership revocation, cross-organization not-found behavior, assignments, role-specific writes, and report download controls.
4. Audit all direct SQL and every resource category (records, scans, cases, findings, evidence, reports, queue items, assets, jobs/results, and engagement data) beyond repository accessor call paths.
5. Resolve Ruff violations and verify whether the single ARTEX mypy finding is pre-existing by comparison to the untouched baseline; ARTEX remains out of scope.
6. Run the required Phase 1 acceptance commands and repeat the complete Python suite after repairs.

**Review decision:** Keep Phase 2B marked incomplete. Do not proceed to Phase 2C.

## Reproduced failure analysis

A second complete run reproduced exactly **118 failed, 730 passed, 5 deselected**. The per-test traceback inventory and grouped corrections are in `docs/reports/phase-2b-failure-analysis.md`.

The 118 break down by observed failure signal: 103 callers/tests reach tenant repository methods without an established organization principal; 9 CLI tests cannot establish the local operator from their credential/identity setup; 5 worker/application startup cases attempt local operator worker scope before a valid operator scope exists; and 1 asynchronous worker test times out after the worker fails to complete. These are observed execution failures, not authorization bypasses. The corresponding caller principal setup, worker lifecycle behavior, and tests remain to be repaired. The failure analysis records each test name and available stack frame.

This confirms the compatibility work is incomplete. Repository denial remains intentional; remediation must establish the correct principal at each authorized entry point, and distinguish application regressions from test setup needing explicit principals. No test was removed or weakened.

## Implementation backlog and incremental status

The backlog below maps the four failure groups in `phase-2b-failure-analysis.md` to corrective work. Status is intentionally conservative: focused test results are not a substitute for the required complete suite.

| Priority | Failure group | Count from reproduced run | Shared cause and caller boundary | Required implementation / regression | Status |
|---|---|---:|---|---|---|
| 1 | Missing repository principal | 103 | Legacy unit/service callers and worker paths accessed owned data without an explicit principal. | Keep repository access fail-closed; establish personal-organization CLI identity or validated member/job principal at the real entry point; use explicit principals in integration fixtures; cover missing-context and ownership behavior. | In progress; several CLI, service, recovery, and API tests repaired. Focused combined rerun pending. |
| 2 | Worker startup without local operator | 5 | Local worker managers assumed a bootstrapped operator even when the app was serving setup/diagnostics. | Keep setup/diagnostics available without fabricating authority; start local-only workers only when operator context is available; test readiness and worker lifecycle. | Targeted diagnostics regression passed; combined rerun pending. |
| 3 | CLI credential/principal setup | 9 | CLI tests/callers relied on absent or mismatched local operator credential identity. | Resolve the explicit local credential to its personal organization at the CLI boundary; avoid repeated bootstrap writes; exercise existing standalone commands with matching identity. | Caller/fixture updates made; combined rerun pending. |
| 4 | Worker thread/context propagation | 1 | A thread-based worker failed to finish because request context was not available in the worker thread. | Establish scoped authority in the worker thread from its explicit local or persisted job identity; retain cleanup; regression-test thread execution. | Earlier worker tests passed; governed worker now reconstructs requester membership from revalidated persisted job; focused provenance and worker tests passed (10 including tenant suite). Combined rerun pending. |

### Implementation checklist

- [x] Preserve fail-closed behavior for absent/invalid organization context and tenant-owned repository operations.
- [x] Keep local CLI access personal-organization scoped and credential-derived; do not infer operator authority from a missing request.
- [x] Allow setup/diagnostics when local worker authorization is unavailable without creating a local principal.
- [x] Reconstruct governed worker repository access from the persisted job's organization and requester after job claim and policy revalidation; ensure nested same-organization adapter contexts retain only the validated principal.
- [x] Complete post-change verification of the previously failing compatibility groups; the full suite now passes after 18 residual failures were fixed.
- [ ] Complete a direct-SQL audit for every application-facing access path, especially all maintenance/setup operations and cross-service reads.
- [x] Add route permission/assignment tests for owner, admin, assigned member lead/assessor/reviewer, auditor, viewer, observer, unassigned, and revoked membership behavior across scans, findings, cases, and reports.
- [x] Verify report download and JSONL streaming for assigned users, and deny unassigned/cross-organization report and resource access.
- [x] Run the complete Python suite, frontend checks, Ruff, targeted mypy, Alembic head, and `git diff --check`; lint/type findings are recorded below.
- [x] Record exact repository status and changed-file inventory below.

## Final remediation and verification (2026-11-25)

### Resolved compatibility groups

The reproduced failure groups were traced to callers that had not established the intended principal. The repository default was not relaxed.

- CLI workflows now resolve and bind the authenticated local operator to the operator's personal organization. CLI bootstrap is idempotent, avoids routine ownership rewrites, and refuses to silently adopt existing unowned data.
- Test fixtures that exercise authorized local workflows create a synthetic operator and explicitly bind the personal-organization principal. Repository security tests continue to use separate organizations and verify denied behavior.
- Local application workers re-establish operator scope inside their worker thread. Governed workers instead reconstruct a writable member scope from the persisted job's organization and requester after claim and policy revalidation; they do not inherit the web thread's ContextVars or local operator authority.
- Repository assessment project reads occur only after the service validates the requested engagement lead and are scoped to that organization. The project lookup is kept within that validated scope.
- Diagnostics, migration, chain, dashboard, and repository-assessment callers/tests were corrected at their entry boundaries. Legacy records without ownership metadata remain in SQLite but are unavailable through normal tenant-aware repository methods.
- Failed-CSRF and repeated-login alerts now persist only the server-generated security signal. Those paths no longer refresh the dashboard by reading tenant records, and failed login handling no longer enters local-operator context.

The original 118-failure run was followed by a full run with 18 remaining failures. Those 18 were individually enumerated in the JUnit output: 12 repository-assessment callers, two chain paths, one dashboard fixture, one migration compatibility assertion, one route-security fixture, and one storage migration assertion. They were corrected by explicit principal establishment, job-thread scope reconstruction, or preserving-but-denying unowned legacy payloads. The final full run has zero failures.

### Final authorization boundaries

`SQLiteRepository._owned_record()` raises `StorageError` if organization context is absent. It always emits an ownership predicate for the active organization. A member principal additionally requires active membership and either an organization role that grants broad read access (owner/admin/auditor/viewer) or an active assignment to the record's engagement. Writes require a writable member context and, for non-admin members, an active lead/assessor/reviewer assignment. Observer and unassigned members cannot mutate or access engagement-owned records. Cross-organization lookup returns no row; updates/deletes cannot affect a row hidden by the same predicate.

Create/save paths call `_ensure_record_ownership()` and reject absent scope. Existing owner metadata is checked before replacement; bulk saves validate each item in the same transaction. List, page, count, grouped count, queue, acknowledgement, and delete paths use the repository ownership condition. Pagination totals are computed from the same scoped base query as the returned page. No `system_context`, bypass flag, or absent-context global fallback exists.

The HTTP middleware requires a live session and resolves the selected organization through active membership. `/api/scans`, `/api/cases`, `/api/findings`, and `/api/reports` use member context; inaccessible resources are returned as not found. Mutations require owner/admin/member organization role, and repository predicates further enforce engagement assignment. Existing local-operator-only route families remain gated by operator identity and personal-organization selection. A request cannot gain local-operator scope by omitting an organization or by failing CSRF.

Scan and case report downloads share the resource predicates. JSONL streaming captures the selected organization and authenticated user, then revalidates membership and reinstalls member context for each yielded batch. Streaming does not switch organization and cleans up context through `with` blocks when iteration exits. Existing rendering and redaction paths are retained.

Direct SQL paths were reviewed by category: execution governance/job lifecycle queries constrain job IDs and revalidate immutable organization, engagement, requester, target, technique, scope revision, authorization, and approval state; repository-assessment SQL constrains organization and engagement and performs service authorization before accessing projects/snapshots; log and malware evidence services validate organization/engagement before reads or mutation; dashboard alert state is local application data, and security-signal writes are isolated from tenant-record reads. This review does not provide a database row-level security layer; direct SQL remains dependent on the explicit checks in those services.

### Worker, assignment, and report behavior

The governed worker uses `member_context(job.organization_id, job.requester_user_id, write=True)` after `claim_job()` and `revalidate_job()`. The persisted immutable execution context supplies the worker identity and the adapter parameters; policy revalidation still precedes external action. Approval consumption remains atomic and one-use at the external-action boundary. Result records retain job provenance. Local chain/code/log/malware workers use a separately established local operator principal in the worker thread and remain restricted to the personal organization.

Route regression coverage now exercises owner/admin access, assigned member lead/assessor/reviewer writes, observer read-only behavior, auditor/viewer read-only behavior, unassigned-member denial, revoked membership, cross-organization scan denial, finding access, case creation/report access, scan report downloads, and JSONL streaming. An assignment-role cross-product beyond these representative allowed/denied combinations is not exhaustively tested.

### Final verification

- Python: **852 passed, 0 failed, 5 deselected**, 543 warnings, 5,206.35 seconds. JUnit: `artifacts/phase2b-full-verified.xml`.
- Focused security signal/CSRF/dashboard selection: **7 passed**. Route-role matrix regression: **1 passed**. Prior worker/provenance and tenant selection: **10 passed**; compatibility selection after caller fixes: **19 passed**.
- Frontend: **77 passed** in 19 files; TypeScript passed; production build and strict-CSP check passed. Vite reported the existing large-chunk advisory.
- Ruff: run across the selected implementation and test files; **258 findings** (250 E501, 5 I001, 3 F401). These are predominantly existing line-length findings in legacy modules. The check is not clean; no broad formatting sweep was applied to unrelated files. Raw JSON: `artifacts/phase2b-ruff-final.json`.
- Targeted mypy: **one error** remains in unrelated ARTEX code at `chinescan/integrations/artex/client.py:40` (`str | None` passed to `HTTPSConnection`). Tenant authorization code had no reported mypy errors in the targeted run. ARTEX was not modified for this finding.
- Alembic: one head, `0013_governed_chain_trace`.
- `git diff --check`: passed; Git emitted only line-ending conversion warnings.
- Test-count difference from the Phase 1 baseline: 852 passed versus 844 passed, with the same 5 deselected. The net increase of 8 tests is the seven tenant repository/route security tests and one dashboard security-signal regression added in this work. ARTEX tests were already part of the current working tree before this recovery.

### Remaining limitations and status

**Phase 2B remains INCOMPLETE for review.** Functional and full-suite verification pass, but Ruff is not clean, targeted mypy reports the unrelated ARTEX issue, and the direct-SQL review is service-level rather than database-enforced. The representative route matrix tests do not cover every Cartesian combination of role, assignment, resource, and verb. Unowned historical records are preserved but require an explicit future recovery/ownership process before normal application access; no migration was added. No Phase 2C work was started.

### Exact final Git status

Branch `main`; HEAD `c09d3f150003421136790c42ffa96d570606da79`; staged changes: none. No stage, commit, reset, clean, stash, or rebase was performed.

Phase 2B modified tracked files:

- `chinescan/cli/chain_commands.py`
- `chinescan/cli/commands.py`
- `chinescan/core/dashboard_intelligence.py`
- `chinescan/core/execution_governance.py`
- `chinescan/core/github_import.py`
- `chinescan/core/malware_project_scan.py`
- `chinescan/core/organizations.py`
- `chinescan/core/repository_assessment.py`
- `chinescan/core/storage/sqlite.py`
- `chinescan/web/app.py` (contains pre-existing ARTEX integration changes; only authorization/security hunks were altered for Phase 2B)
- `chinescan/web/chain_trace_jobs.py`
- `chinescan/web/code_jobs.py`
- `chinescan/web/log_jobs.py`
- `chinescan/web/malware_jobs.py`
- `scripts/recovery_acceptance.py`
- `tests/conftest.py`
- `tests/unit/test_cases.py`
- `tests/unit/test_chain_trace.py`
- `tests/unit/test_code_jobs.py`
- `tests/unit/test_code_scan.py`
- `tests/unit/test_dashboard_alerts.py`
- `tests/unit/test_diagnostics.py`
- `tests/unit/test_engagement_security.py`
- `tests/unit/test_github_import.py`
- `tests/unit/test_github_projects.py`
- `tests/unit/test_log_analysis.py`
- `tests/unit/test_malware_project_scan.py`
- `tests/unit/test_managed_malware.py`
- `tests/unit/test_migration.py`
- `tests/unit/test_organizations.py`
- `tests/unit/test_projects.py`
- `tests/unit/test_projects_cli.py`
- `tests/unit/test_recovery.py`
- `tests/unit/test_reporting.py`
- `tests/unit/test_repository_assessment.py`
- `tests/unit/test_route_security_inventory.py`
- `tests/unit/test_storage.py`
- `tests/unit/test_tenant_repository_security.py` (new)
- `tests/unit/test_trends.py`
- `tests/unit/test_web_api.py`

Phase 2B-created/updated artifacts:

- `artifacts/phase2b-focused.xml`
- `artifacts/phase2b-full-final.xml`
- `artifacts/phase2b-full-verified.xml`
- `artifacts/phase2b-full.xml`
- `artifacts/phase2b-junit.xml` (from the earlier failure-analysis run)
- `artifacts/phase2b-ruff-final.json`
- `docs/reports/phase-2b-failure-analysis.md`
- `docs/reports/phase-2b-tenant-isolation-report.md`

Pre-existing unrelated dirty/untracked ARTEX/config work was preserved: `chinescan/core/config/io.py`, `chinescan/core/config/settings.py`, `configs/chinescan.example.toml`, `chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, `scripts/make_cover.py`, and `tests/unit/test_artex_integration.py`. The architecture audit and implementation plan were also already untracked and were left untouched.

## Follow-up verification after the reproduced full run

After recording the full-run JUnit result, local worker startup was changed to deny startup without a bootstrapped local operator while allowing the application to continue serving diagnostics/authentication. The targeted regression `tests/unit/test_diagnostics.py::test_ready_fails_for_corrupt_credentials_unwritable_database_missing_dirs_and_frontend` now passes. The tenant repository security tests and authenticated JSONL stream test were rerun in the same focused selection: **6 passed**. The full suite has not been rerun after this lifecycle fix, so the previously reported full-suite totals remain the last complete-run result, not a claim about the current revision.

## Phase 2B closure pass (2026-11-25)

This section supersedes stale intermediate verification figures above where they differ. It records the closure-pass changes and fresh results; the full Python run is still in progress at the time of this edit.

### Direct-SQL inventory and classification

An AST inventory and source search covered all application Python modules. There are 381 `execute`/`exec_driver_sql` call sites in 12 modules (338 SQLAlchemy `.execute` calls and 43 explicit driver executions); no `sqlalchemy.text()` raw text query was found. This count is call sites, not a count of distinct logical queries. No web route module executes direct SQL: route access flows through authorization services and the tenant-aware repository.

| Module | Call sites | Classification / boundary |
|---|---:|---|
| `core/storage/sqlite.py` | 37 | Tenant record operations share `_owned_record` ownership predicates. Read, page/count, grouped count, queue, acknowledgement, mutation, and bulk paths are scoped. Missing context raises `StorageError`; membership and active assignment are revalidated for member contexts. |
| `core/organizations.py` | 71 | Organization, membership, engagement, role, assignment and audit operations constrain IDs by organization and verify actor authority. `ensure_operator` performs the one-time legacy ownership mapping for records that have no ownership row, places them in the pre-multi-user local operator's personal organization, and records counts in `organization_bootstrap_reports`; existing ownership is preserved. |
| `core/engagement_security.py` | 55 | Membership, assignment, engagement, scope, authorization, approval and evidence metadata paths validate active identities/roles and constrain rows with organization and engagement IDs. Approval consumption remains atomic. |
| `core/execution_governance.py` | 60 | Queue dispatch may inspect queued job IDs globally, but claim and subsequent processing re-load the persisted job and validate its immutable organization, requester, engagement, target, technique, scope, authorization and approval context before execution. Results are bound to job provenance. |
| `core/execution_adapters.py` | 4 | Adapter result and evidence binding paths receive the validated persisted execution context; no request-supplied organization is used by the worker. |
| `core/log_evidence.py` | 28 | Snapshot, quota, asset and audit SQL uses organization/engagement predicates, rechecks active operation rights at mutation boundaries, and stores private content under organization-specific roots. Worker verification receives persisted execution-context IDs. |
| `core/malware_evidence.py` | 18 | Snapshot and quota queries use organization/engagement predicates. The closure pass fixed `get()` so callers must supply an active readable principal; the API execution preflight now returns not-found before job admission for unassigned/cross-organization evidence. Hold/delete updates repeat organization and engagement predicates. |
| `core/repository_assessment.py` | 57 | Snapshot, binding, attestation and quota operations validate lead/engagement authorization before SQL or local registry resolution and constrain persistent rows by organization/engagement. |
| `core/dashboard_alerts.py` | 17 | Local dashboard alert state, not tenant records. Security-signal insertion is a bounded insert of server-created signal data; failed-CSRF/login paths do not trigger tenant record scans. |
| `core/diagnostics.py` | 6 | Database health/PRAGMA metadata only; does not return tenant record payloads. |
| `core/storage/recovery.py` | 27 | Whole-database backup/restore/retention operations are global maintenance operations invoked by explicit local CLI commands. They preserve ownership/provenance tables and validate backups; they do not expose query results through web APIs. |
| `cli/commands.py` | 1 | Local database bootstrap existence check, after explicit operator credential validation. |

The 43 `exec_driver_sql` calls are transaction starts, read-only integrity checks, diagnostics, and local dashboard SQL; tenant data access is expressed through SQLAlchemy statements in the scoped services. Bulk operations validate each item in one transaction. The pre-existing legacy ownership mapping is retained as a compatibility migration for data from the former single-operator model and is auditable; it is not a general tenant query path. No general-purpose bypass principal or flag exists. SQLite has no row-level security, so this protection remains application-enforced.

### Additional regression coverage and policy matrix

The API regression now checks foreign-organization scan, finding, and report identifiers return 404; scan pagination does not include the foreign scan; a member with a revoked engagement assignment immediately loses scan access; and a same-organization unassigned member cannot create a malware evidence execution job. The malware test creates actual evidence in another organization and verifies that the member receives the same not-found response and that the execution-job table is unchanged. Existing matrix assertions exercise owner/admin writes, auditor/viewer reads and write denials, member lead/assessor/reviewer writes, observer read-only access, unassigned-member denial, revoked membership, case/report access, and JSONL streaming. The matrix is representative and still is not a Cartesian test of every role × assignment × resource × verb combination.

The malware evidence preflight was an unsafe direct service path: `get()` previously accepted caller-provided organization and engagement IDs and queried before checking authorization. It now checks `_can_read()` first, and the API calls it with the authenticated `session.user_id`. A denied request is non-disclosing and cannot reach job creation. Worker `verify()` methods remain restricted to internal governed adapters and take organization/engagement/asset/snapshot IDs from the persisted immutable execution context.

### Ruff attribution

The prior targeted baseline was 258 findings. Re-running the same 12-file selection after cleanup reports 241: 237 `E501`, 3 `F401`, and 1 `I001` (17 fewer). The expanded 17-file implementation/test selection is also 241; the additional malware evidence files are clean. The repo-wide scan reports 395 findings. After comparison with HEAD, the remaining added-line/untracked findings are confined to pre-existing config, ARTEX, cover-script and unrelated tests; the remaining `web/app.py` import findings concern the pre-existing ARTEX import block. No lint findings are on new Phase 2B lines. No global suppression or broad formatting change was used.

### Verification status

- Focused current-tree run: `py -3.12 -m pytest -q tests/unit/test_governed_malware.py tests/unit/test_tenant_repository_security.py` — 12 passed, 0 failed.
- Frontend: `npm test` — 77 passed in 19 files; `npm run typecheck` passed; `npm run build` passed and included the strict-CSP built-asset check (Vite retains its chunk-size advisory).
- Targeted mypy on `sqlite.py`, `malware_evidence.py`, `engagement_security.py`, and `malware_evidence_api.py` — success, no issues in 4 source files.
- Alembic head — `0013_governed_chain_trace (head)`.
- Repo-wide Ruff: 404 findings; exact targeted set: 245, detailed above.
- `git diff --check` passed before final report edits and after the source/test changes; report-only edits are checked again at completion.
- Fresh full Python suite: `py -3.12 -m pytest -q --junitxml=artifacts/phase2b-closure-full.xml` — **852 passed, 0 failed, 5 deselected, 553 warnings, 1,233.66 seconds**.

### Closure-pass files

Additional closure-pass source changes: `chinescan/core/malware_evidence.py`, `chinescan/web/malware_evidence_api.py`, `chinescan/cli/commands.py`, `chinescan/core/repository_assessment.py`, `chinescan/core/storage/sqlite.py`, and authorization test additions in `tests/unit/test_tenant_repository_security.py` and `tests/unit/test_governed_malware.py`. No unrelated ARTEX source was modified. No migration was added. No Phase 2C work was started.


### Exact Git state at closure

- Branch: `main`
- HEAD: `c09d3f150003421136790c42ffa96d570606da79`
- Staged changes: none
- Commit created: no
- `git diff --check`: passed (Git emitted CRLF-to-LF notices only)
- Tracked modified files: `chinescan/cli/chain_commands.py`, `chinescan/cli/commands.py`, `chinescan/core/config/io.py`, `chinescan/core/config/settings.py`, `chinescan/core/dashboard_intelligence.py`, `chinescan/core/execution_adapters.py`, `chinescan/core/execution_governance.py`, `chinescan/core/github_import.py`, `chinescan/core/malware_evidence.py`, `chinescan/core/malware_project_scan.py`, `chinescan/core/organizations.py`, `chinescan/core/repository_assessment.py`, `chinescan/core/storage/sqlite.py`, `chinescan/web/app.py`, `chinescan/web/chain_trace_jobs.py`, `chinescan/web/code_jobs.py`, `chinescan/web/log_jobs.py`, `chinescan/web/malware_evidence_api.py`, `chinescan/web/malware_jobs.py`, `configs/chinescan.example.toml`, `scripts/recovery_acceptance.py`, `tests/conftest.py`, `tests/unit/test_cases.py`, `tests/unit/test_chain_trace.py`, `tests/unit/test_code_jobs.py`, `tests/unit/test_code_scan.py`, `tests/unit/test_dashboard_alerts.py`, `tests/unit/test_diagnostics.py`, `tests/unit/test_engagement_security.py`, `tests/unit/test_github_import.py`, `tests/unit/test_github_projects.py`, `tests/unit/test_governed_malware.py`, `tests/unit/test_log_analysis.py`, `tests/unit/test_malware_project_scan.py`, `tests/unit/test_managed_malware.py`, `tests/unit/test_migration.py`, `tests/unit/test_organizations.py`, `tests/unit/test_projects.py`, `tests/unit/test_projects_cli.py`, `tests/unit/test_recovery.py`, `tests/unit/test_reporting.py`, `tests/unit/test_repository_assessment.py`, `tests/unit/test_route_security_inventory.py`, `tests/unit/test_storage.py`, `tests/unit/test_trends.py`, `tests/unit/test_web_api.py`.
- Untracked paths: `artifacts/`, `chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, `docs/reports/phase-2-architecture-audit.md`, `docs/reports/phase-2-implementation-plan.md`, `docs/reports/phase-2b-failure-analysis.md`, `docs/reports/phase-2b-tenant-isolation-report.md`, `scripts/make_cover.py`, `tests/unit/test_artex_integration.py`, `tests/unit/test_tenant_repository_security.py`.

The pre-existing ARTEX/config work remains present. The ARTEX files were not edited during this closure pass; `web/app.py` retains its prior ARTEX changes and was modified only for Phase 2B authorization behavior here. No files were discarded or overwritten, and no Phase 2C work began.
## Final closure pass — 2026-11-25

### Implemented in this pass

- Repository writes now require a validated write context; a read-only assigned assessor cannot mutate tenant records. Organization writes also enforce active membership/assignment roles in the same ownership predicate used for reads.
- Local operator database backup and restore establish the existing authenticated local operator principal before operating on the configured database.
- Fixed a compatibility boundary in HTTP middleware: operator-only API families first pass the existing local operator identity and personal-organization checks, then receive a database-validated membership context for the selected personal organization. Request method determines write capability. Organization members still cannot enter those operator-only families; the four member-facing resource families keep their membership/role checks.
- Malware recovery tests now use an active persisted owner principal after restoring the database.
- Added route-level reviewer/lead approval authorization regression and repository read-only write-denial regression. Fixed the revoked-membership list assertion to match the actual non-disclosing denied response.
- Added the authorization matrix and refreshed each direct SQL register source location. Added an attributable quality report.

### Final verification

- Focused route/recovery/service regression set: 23 passed, 0 failed.
- Full Python suite (Python 3.12): **854 passed, 0 failed, 5 deselected**, 600 warnings, 1,127.83 seconds. The two additional passing tests are the closure regressions added since the reported 852-pass run.
- Frontend on final source tree: `npm test` — 77 passed in 19 files; `npm run typecheck` passed; `npm run build` passed including strict-CSP source and built-asset verification. Vite reported the existing chunk-size advisory.
- Targeted mypy on four Phase 2B core/API files: success, no issues in 4 files. A six-file check including `web/app.py` and CLI transitively reports one ARTEX error in `chinescan/integrations/artex/client.py:40` (`HTTPSConnection` receives `str | None`); ARTEX was not edited.
- Ruff: 394 repository-wide findings and 216 in the explicit 14-file target. Changed-line attribution found one `F401` on the existing ARTEX import at `web/app.py:58`, no findings on new Phase 2B lines. The target still contains legacy diagnostics on untouched lines; see the quality report.
- Alembic script heads: exactly one, `0013_governed_chain_trace`. No migration was added. The configured SQLite database was not accessed to inspect its current revision.
- `git diff --check`: passed after final report edits (only CRLF-to-LF notices).
- No Phase 2C changes were made.

### Direct SQL and matrix status

The AST inventory currently contains 381 `execute`/`exec_driver_sql` call sites: 380 SQL execution sites and one governed adapter invocation. The register lists each site and current source location, with 336 SAFE and 45 PRIVILEGED dispositions, and no rows labeled UNSAFE or UNRESOLVED. Review evidence associates each query with its access module and regression files. The register is an application-level audit: SQLite has no row-level security, and it does not replace the principal and ownership checks in code.

The matrix documents owner/admin/member/auditor/viewer and lead/assessor/reviewer/observer behavior, plus read/write, engagement, report, evidence, execution, approval, and cancellation boundaries. API tests exercise each distinct policy behavior; unsupported route/verb combinations are explicitly identified rather than assigned invented permissions.

### Remaining blockers — Phase 2B remains INCOMPLETE

1. The full test suite passes, but this does not establish the user-required exhaustive evidence that each of 381 SQL call sites has been manually traced through every caller and authorization branch. The register is individually addressable, but its generated call-site inventory and shared evidence references are not a substitute for a human-reviewed query-by-query proof. Do not treat this as a completed direct-SQL security audit.
2. The 14-file Ruff selection has 216 existing diagnostics on untouched legacy lines (214 E501, one I001 in the existing ARTEX import area, and one F401 for `ArtexHealth`). No new Phase 2B line has a finding. Repository-wide total is 394. This does not satisfy a zero-diagnostic selection if interpreted to include legacy lines in touched modules.
3. The prior untracked `artifacts/phase2b-ruff-final.json` was overwritten while producing a fresh Ruff report before its original contents had been preserved. The current fresh output is preserved under a unique `*-r2.json` filename; the prior JSON diagnostic artifact could not be restored. This is disclosed and no source/user code was overwritten by that action.
4. The previous untracked Ruff JSON artifact overwrite could not be reversed. Source changes and other existing work were retained; nevertheless, this is a repository-safety deviation and blocks a “no user work overwritten” acceptance claim.

Phase 2B is therefore **INCOMPLETE**. No database migration, stage/commit, or Phase 2C work was performed.
## Exact final Git state

- Branch: `main`
- HEAD: `c09d3f150003421136790c42ffa96d570606da79`
- Staged paths: none (`git diff --cached --name-only` empty)
- Commits created: none
- `git diff --check`: passed; Git printed line-ending normalization notices for existing CRLF files
- Modified tracked paths:
  `chinescan/cli/chain_commands.py`, `chinescan/cli/commands.py`, `chinescan/core/config/io.py`, `chinescan/core/config/settings.py`, `chinescan/core/dashboard_intelligence.py`, `chinescan/core/engagement_security.py`, `chinescan/core/execution_adapters.py`, `chinescan/core/execution_governance.py`, `chinescan/core/github_import.py`, `chinescan/core/malware_evidence.py`, `chinescan/core/malware_project_scan.py`, `chinescan/core/organizations.py`, `chinescan/core/repository_assessment.py`, `chinescan/core/storage/sqlite.py`, `chinescan/web/app.py`, `chinescan/web/chain_trace_jobs.py`, `chinescan/web/code_jobs.py`, `chinescan/web/log_jobs.py`, `chinescan/web/malware_evidence_api.py`, `chinescan/web/malware_jobs.py`, `configs/chinescan.example.toml`, `scripts/recovery_acceptance.py`, `tests/conftest.py`, and the modified unit tests under `tests/unit/`.
- Untracked paths remain: `artifacts/`, `chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, the Phase 2 architecture and Phase 2B reports, `scripts/make_cover.py`, `tests/unit/test_artex_integration.py`, and `tests/unit/test_tenant_repository_security.py`.
- ARTEX integration files and unrelated work were not edited during the final closure changes. Existing `web/app.py` ARTEX integration remains part of its already-modified working tree; this closure changed its authorization middleware boundary only.
- No reset, stash, clean, rebase, stage, unstage, or commit was performed. Tests used isolated temporary SQLite databases; the configured/local application database was not accessed. The Ruff artifact overwrite described above is the exception to the preservation goal and is disclosed.

**Decision: PHASE 2B INCOMPLETE.** The full tests pass, but the exhaustive per-query manual proof and a fully clean legacy-inclusive Ruff selection are not demonstrated; the prior untracked Ruff JSON artifact was also overwritten.


### Exact `git status --short` snapshot

```text
 M chinescan/cli/chain_commands.py
 M chinescan/cli/commands.py
 M chinescan/core/config/io.py
 M chinescan/core/config/settings.py
 M chinescan/core/dashboard_intelligence.py
 M chinescan/core/engagement_security.py
 M chinescan/core/execution_adapters.py
 M chinescan/core/execution_governance.py
 M chinescan/core/github_import.py
 M chinescan/core/malware_evidence.py
 M chinescan/core/malware_project_scan.py
 M chinescan/core/organizations.py
 M chinescan/core/repository_assessment.py
 M chinescan/core/storage/sqlite.py
 M chinescan/web/app.py
 M chinescan/web/chain_trace_jobs.py
 M chinescan/web/code_jobs.py
 M chinescan/web/log_jobs.py
 M chinescan/web/malware_evidence_api.py
 M chinescan/web/malware_jobs.py
 M configs/chinescan.example.toml
 M scripts/recovery_acceptance.py
 M tests/conftest.py
 M tests/unit/test_cases.py
 M tests/unit/test_chain_trace.py
 M tests/unit/test_code_jobs.py
 M tests/unit/test_code_scan.py
 M tests/unit/test_dashboard_alerts.py
 M tests/unit/test_diagnostics.py
 M tests/unit/test_engagement_security.py
 M tests/unit/test_github_import.py
 M tests/unit/test_github_projects.py
 M tests/unit/test_governed_malware.py
 M tests/unit/test_log_analysis.py
 M tests/unit/test_malware_project_scan.py
 M tests/unit/test_managed_malware.py
 M tests/unit/test_migration.py
 M tests/unit/test_organizations.py
 M tests/unit/test_projects.py
 M tests/unit/test_projects_cli.py
 M tests/unit/test_recovery.py
 M tests/unit/test_reporting.py
 M tests/unit/test_repository_assessment.py
 M tests/unit/test_route_security_inventory.py
 M tests/unit/test_storage.py
 M tests/unit/test_trends.py
 M tests/unit/test_web_api.py
?? artifacts/
?? chinescan/integrations/
?? docs/ARTEX-MILESTONE-1.md
?? docs/reports/phase-2-architecture-audit.md
?? docs/reports/phase-2-implementation-plan.md
?? docs/reports/phase-2b-authorization-matrix.md
?? docs/reports/phase-2b-direct-sql-audit.md
?? docs/reports/phase-2b-failure-analysis.md
?? docs/reports/phase-2b-quality-report.md
?? docs/reports/phase-2b-tenant-isolation-report.md
?? scripts/make_cover.py
?? tests/unit/test_artex_integration.py
?? tests/unit/test_tenant_repository_security.py
```

## 2026-11-25 final-three-stage closure update

### Stage 1 — fresh baseline

Repository branch/HEAD remained `main` / `c09d3f150003421136790c42ffa96d570606da79`; no paths were staged. Before closure source edits, fresh acceptance results were recorded in `docs/reports/phase-2b-stage1-baseline-2026-11-25.md`: Python 854 passed, 0 failed, 5 deselected; frontend 77 passed; TypeScript, production build/CSP, targeted mypy, Alembic single head, and `git diff --check` passed. This confirms the reported baseline. The full code-change test run is separate and pending at report edit time.

### Demonstrated Stage 3 defect and correction

Review found role/assignment checks treated active membership plus Lead/Assessor/Reviewer assignment as sufficient even when the organization role was Viewer or Auditor. `EngagementSecurityService._can_operate`, `_can_manage`, `_can_review`, and the separate `decide_approval` predicate now require Owner/Admin or Member with the corresponding assignment. This retains established Owner/Admin behavior and Member assignment policy while preventing assignments from elevating read-only roles. API regressions verify Viewer+Reviewer cannot decide an approval and the approval stays pending, and Viewer+Assessor cannot submit an execution job or mutate the job table. Focused verification: 61 passed across `test_engagement_security.py`, `test_governed_malware.py`, and `test_tenant_repository_security.py`; targeted Ruff on the changed implementation/test files passed; targeted mypy on four Phase 2B core modules passed.

### Stage 2 audit disposition

The register inventories 381 execute/adapter AST sites (380 SQL executions and one adapter invocation). The 45 originally privileged entries have caller-flow analysis in `docs/reports/phase-2b-direct-sql-audit.md`: SQL-141 is queue ID discovery followed by atomic persisted-job validation; SQL-193–209 are explicit operator identity/bootstrap setup; SQL-318–344 are local recovery/backup verification paths.

The 336 SAFE entries have **not** all received exhaustive independent caller tracing. Query-family predicates and tests are useful evidence, but generic register notes do not prove every alternate caller establishes the required principal or that every direct tenant query is unreachable without it. This is a remaining Stage 2 blocker. Zero previously labeled UNSAFE is not treated as proof of safety.

### Fresh final verification

- Full Python suite: **855 passed, 0 failed, 5 deselected**, 429 warnings, 1485.37 seconds. The count is one higher than the 854 baseline because this closure adds `test_viewer_with_assessor_assignment_cannot_submit_execution_job`; the existing approval API test was extended.
- Focused security selection: **61 passed**, 0 failed.
- Frontend: **77 passed** across 19 files.
- TypeScript: passed.
- Production build and strict CSP: passed. Existing Vite advisory remains for a 535.41 kB scene chunk.
- Targeted Ruff: passed for `engagement_security.py` and `test_engagement_security.py` (0 findings). Whole repository: 386 findings; 14-file Phase 2B selection: 208, including two existing ARTEX import diagnostics in `web/app.py`.
- Targeted mypy: passed for four Phase 2B core modules, 0 issues.
- Alembic script heads: `0013_governed_chain_trace (head)` only. The configured database revision was not queried.
- `git diff --check`: passed on the final working tree; only existing CRLF normalization notices were printed.
- Git remained on `main` at `c09d3f150003421136790c42ffa96d570606da79`; staged path list was empty. No commit was created. Existing ARTEX and unrelated dirty/untracked work remain present.

### Decision

**PHASE 2B INCOMPLETE.** Stage 1 is confirmed and Stage 3’s demonstrated role/assignment elevation defect is corrected and covered. Stage 2 is still not proven to the required standard: tenant-sensitive SAFE SQL entries lack complete individual caller traces. Do not proceed to Phase 2C.

## 2026-11-25 targeted closure continuation

### Baseline and repository safety

- Branch/HEAD remained `main` / `c09d3f150003421136790c42ffa96d570606da79`.
- No staged changes; no commits created. Existing ARTEX and unrelated dirty files were preserved.
- A unique baseline note was created at `docs/reports/phase-2b-targeted-baseline-2026-11-25-r1.md`. It records the immediately preceding 855-pass completed run and excludes a redundant full run interrupted at approximately 25%; pytest did not finalize that run's requested XML file, and no interrupted-run artifact is claimed.

### Implemented security corrections

- `OrganizationService._has_assignment` now requires an active `member` role for assignment-derived capabilities. Owner/Admin paths remain explicit. This prevents Viewer/Auditor + Lead from managing engagements or assignments.
- `RepositoryAssessmentService._is_lead_connection` now requires Owner/Admin/Member in addition to active Lead assignment and active organization/user/engagement state.
- Approval decision revalidation and execution-worker stale-approval revalidation now require Owner/Admin or Member plus active Lead/Reviewer assignment. A role downgrade invalidates the pending approval before it can be consumed.
- `/api/ready` and `/api/diagnostics` now explicitly match the authenticated session identity to the configured local operator before their cross-tenant aggregate diagnostic query runs. A different identity receives 404. This is necessary because these identity endpoints bypass the ordinary organization middleware; the change is limited to the SQL-owning diagnostics boundary in the pre-existing `web/app.py` file.

### Regression coverage and fresh focused results

- Added API tests for Viewer/Auditor + Lead engagement mutation/assignment access and repository asset creation, verifying no database mutation.
- Extended worker approval revalidation tests for reviewer membership role downgrade; approval remains unconsumed and no external action proceeds.
- Added diagnostics route identity-denial coverage.
- Focused modules: `test_organizations.py`, `test_repository_assessment.py`, and `test_engagement_security.py`: **85 passed**.
- Focused diagnostics selection: the initial run exposed a loopback test-client setup mismatch (400 before route execution); after using an explicit loopback client, the rerun completed with all selected tests passing (3 tests).
- The final full Python rerun reported **859 passed, 2 failed, 5 deselected** (861 selected; six more selected cases than the 855-pass preceding baseline). Its unique JUnit artifact is `artifacts/phase2b-targeted-closure-final-20261125-r2.xml`. The first failure from run r1 was an outdated diagnostics test expecting 503 without an established operator identity; that test was corrected to assert the 404 boundary and separately verify `build_report` marks corrupt credentials as FAIL (four focused diagnostics tests passed). Both r2 failures are `test_governed_chain_provider_consumes_approval_before_fixed_root_lookup` and `test_modules_endpoint_is_authenticated_and_reports_planned_guards`; each failed during fixture app construction because Windows `whoami.exe`/`icacls.exe` exceeded existing 5-second subprocess timeouts in `chinescan/core/storage/security.py`, before route/security assertions executed. Both exact tests passed when rerun in isolation (**2 passed, 0 failed**, 41.47 seconds), supporting an environment/load timeout classification. The full suite is not green; no timeout was hidden or bypassed.

### SQL audit and matrix status

- The direct-SQL register now records the closure findings against SQL-259, SQL-310, and the approval/revalidation query family, and changes diagnostics SQL-024 to a verified local-operator-only aggregate path.
- The 336 previous SAFE entries are still not exhaustively traced across every alternate HTTP, CLI, worker, recovery, callback, and context-propagation caller. The previous totals remain labels rather than proof. This caller-path evidence gap remains a blocker.
- The authorization matrix includes the new concrete regression cases but still does not enumerate/test every valid role/assignment/resource/operation combination. The matrix is therefore not accepted as complete.

### Current quality checks (closure tree)

- Targeted mypy of the four Phase 2B core modules passed with 0 issues. Including `web/app.py` reports the known unrelated ARTEX `HTTPSConnection` argument type error in `chinescan/integrations/artex/client.py:40`.
- Fresh Ruff reports 386 repository-wide findings (366 E501, 9 I001, 4 F401, 2 F821, 2 F841, and one each UP017, UP047, B007); the nine-file implementation/test selection reports 184 (181 E501, one each I001/F401/F841). Changed-line attribution against the current diff found 0 findings on added/changed lines. The selected-file aggregate remains large because it includes pre-existing long lines in modified files; no repository-wide cleanup was performed.
- Alembic script heads: `0013_governed_chain_trace (head)` only. No configured database revision was inspected.
- Fresh Ruff selected-file count remains 184, but changed-line attribution found 0 findings on added/changed lines. Fresh repository-wide count is 386. `git diff --check` passed, with Git reporting existing CRLF normalization notices.
- Fresh frontend test suite: **77 passed** across 19 files. TypeScript typecheck passed. Production build passed and strict CSP source/built-asset verification passed. Vite emitted the existing 535.41 kB scene-chunk advisory.

### Decision

**PHASE 2B INCOMPLETE.** The confirmed role elevation defects and diagnostics principal boundary have been corrected and regression-tested. The direct-SQL caller-path audit and comprehensive effective authorization matrix remain incomplete. The final full Python run had two Windows tool timeouts (both passed in isolation); frontend tests/build/CSP pass, but the complete suite did not produce a zero-failure run.

### Exact closure-pass Git state

- Branch/HEAD: `main` / `c09d3f150003421136790c42ffa96d570606da79`.
- Staged paths: none (`git diff --cached --name-only` empty).
- Commits created: none. No reset, stash, rebase, clean, or discard performed.
- Source/test files changed during this closure pass: `chinescan/core/organizations.py`, `chinescan/core/repository_assessment.py`, `chinescan/core/engagement_security.py`, `chinescan/core/execution_governance.py`, `chinescan/web/app.py` (only the direct diagnostics SQL route boundary added within the already-dirty file), `tests/unit/test_organizations.py`, `tests/unit/test_repository_assessment.py`, `tests/unit/test_engagement_security.py`, and `tests/unit/test_diagnostics.py`.
- Reports changed during this closure pass: `docs/reports/phase-2b-tenant-isolation-report.md`, `docs/reports/phase-2b-failure-analysis.md`, `docs/reports/phase-2b-direct-sql-audit.md`, `docs/reports/phase-2b-authorization-matrix.md`; unique new baseline note: `docs/reports/phase-2b-targeted-baseline-2026-11-25-r1.md`.
- Unique full-suite artifacts: `artifacts/phase2b-targeted-closure-final-20261125-r1.xml` and `artifacts/phase2b-targeted-closure-final-20261125-r2.xml`. Other files shown by `git status --short` were already dirty/untracked in the starting tree, including ARTEX work, and remain present. Nothing was staged or committed.
