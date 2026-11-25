# Phase 2B Final Security Remediation and Acceptance Report (2026-11-25)

**Decision: PHASE 2B COMPLETE**
**Repository:** `C:\GitHub\Chinescan`
**Branch / HEAD:** `main` / `c09d3f150003421136790c42ffa96d570606da79`
**JUnit Artifact:** `artifacts/phase2b-final-acceptance-20261125.xml`
**SQL Audit Supplement:** `docs/reports/phase-2b-final-sql-audit-2026-11-25.md`

---

## A. SQL Authorization Evidence

- **Total live AST execution/adapter sites:** **380** (**379 SQL executions** + **1 governed adapter invocation** `adapter.execute` at `chinescan/core/execution_governance.py:1842`; 0 `sqlalchemy.text()` sites). *(Down from 381 in the prior register because refactoring `OrganizationService.update_organization` to delegate to `self.has_role(...)` removed 1 duplicate `connection.execute(...)` site.)*
- **Tenant-sensitive sites & adapter dispatch:** **311** (`310` SQL sites + `1` governed adapter invocation `adapter.execute`; all verified safe across caller paths).
- **Global / non-tenant-sensitive sites:** **24** (local operator alerts `dashboard_alerts.py` [17], diagnostics SQLite health/temp probe `diagnostics.py` [5], `PRAGMA foreign_keys=ON` `sqlite.py` [1], local CLI operator count `commands.py` [1]).
- **Privileged sites with explicit authorization:** **45** (`_next_job_id` [1], `ensure_operator` bootstrap/legacy-ownership [17], `storage/recovery.py` local DB backup/restore/verify [27]).
- **Unresolved / Confirmed unsafe:** **0 unresolved**, **0 unsafe**.
- **Distinct tenant-sensitive caller groups:**
  1. `SQLiteRepository` (`chinescan/core/storage/sqlite.py`, 36 tenant-sensitive SQL sites + 1 global PRAGMA) — fail-closed `ContextVar` scoping via `_owned_record` and `_ensure_record_ownership`; HTTP middleware establishes `member_context`, JSONL and SSE streaming generators re-establish `member_context`, CLI binds `local_operator_context` or `member_context`, and `GovernedDomainWorker` reconstructs `member_context` from persisted job state only after full revalidation.
  2. `OrganizationService` (`chinescan/core/organizations.py`, 53 tenant-sensitive SQL sites + 17 `ensure_operator` privileged sites) — `organization_api.py` (`current_session`, `require_csrf`), `SQL-259` (`_has_assignment` requires active `member` role), and `update_organization` delegating to `has_role`.
  3. `EngagementSecurityService` (`chinescan/core/engagement_security.py`, 55 SQL sites) — transactional `_can_read`/`_can_manage`/`_can_operate`/`_can_review` and separation of duties in `publish_scope_revision` and `decide_approval`.
  4. `ExecutionGovernanceService`, `GovernedDomainWorker`, & `RepositoryCodeAssessmentAdapter` (`execution_governance.py`: 58 tenant-sensitive SQL sites + 1 governed adapter invocation `adapter.execute` at L1842 + 1 privileged SQL site `_next_job_id`; `execution_adapters.py`: 4 SQL sites) — policy re-evaluation, immutable context digest, and approver role revalidation at claim/consumption before `adapter.execute` is dispatched inside `member_context` and `execution_provenance_context`.
  5. `RepositoryAssessmentService` & `RepositorySnapshotStore` (`repository_assessment.py`, 57 SQL sites) — `SQL-310` (`_is_lead_connection` requires `owner`/`admin`/`member` + `lead`) and `_can_read`.
  6. `LogEvidenceStore` (`log_evidence.py`, 28 SQL sites) & `MalwareEvidenceStore` (`malware_evidence.py`, 18 SQL sites) — `_can_operate`/`_can_manage`/`_can_read`.
  7. Diagnostics `SQL-024` (`diagnostics.py`, 1 tenant-sensitive SQL site + 5 global temp-probe SQL sites) — gated by `require_local_operator_diagnostics(session)` on `/api/ready` and `/api/diagnostics` (non-operators receive 404).
- **Defects fixed in this pass:**
  1. `chinescan/web/app.py` (`dashboard_alert_events`, `/api/alerts/events`): wrapped `dashboard_intelligence.refresh_alerts()` inside `with repository.member_context(organization_id, user_id, write=False):` so SSE alert streaming does not execute `list_records(...)` after the middleware's `authorization_scope` has exited.
  2. `chinescan/core/organizations.py` (`update_organization`): replaced direct `organization_memberships` query with `self.has_role(user_id, organization_id, {"owner", "admin"})` so inactive organizations and inactive users are rejected consistently.
  3. `chinescan/web/malware_evidence_api.py:128` & `chinescan/web/log_evidence_api.py:154`: fixed `create_execution` handlers that checked `result.get("decision") != "ALLOW"` (which falsely rejected valid `create_governed_job` responses lacking a `"decision"` key) to match `execution_api.py` (`result.get("decision") in {"DENY", "REQUIRE_APPROVAL"} or not result.get("id")`).

---

## B. Authorization Matrix

- **Roles covered:** `owner`, `admin`, `member`, `auditor`, `viewer`.
- **Assignments covered:** `lead`, `assessor`, `reviewer`, `observer`, `None` (no assignment).
- **Explicit combinations verified in `tests/unit/test_authorization_matrix_complete.py`:**
  - `viewer` + (`lead`, `assessor`, `reviewer`, `observer`, `None`): strictly read-only; assignments do not elevate any write/manage/operate/review/destructive permission.
  - `auditor` + (`lead`, `assessor`, `reviewer`, `observer`, `None`): strictly read-only; assignments do not elevate any write/manage/operate/review/destructive permission.
  - `member` + (`lead`, `assessor`, `reviewer`, `observer`, `None`): `lead` grants manage/operate/review/destructive; `assessor` grants operate/submit/destructive (not manage/review/asset-create); `reviewer` grants assignment-list/review (not manage/operate/destructive); `observer` grants read-only; `None` denies engagement-owned resources.
  - `admin` + (`None`, `lead`): org-wide manage/review/cancel, while operate/submit/destructive still require `lead`/`assessor`.
  - Lifecycle & fail-closed checks: missing auth (401), missing/invalid/foreign `x-chinescan-organization-id` (404), cross-organization engagement IDs (404), assignment revocation, organization membership revocation, and inactive organization update guard.
  - Combined with existing `test_engagement_security.py`, `test_organizations.py`, `test_repository_assessment.py`, `test_governed_malware.py`, `test_log_evidence.py`, and `test_tenant_repository_security.py`, all role/assignment/operation rules and role-downgrade revalidation paths have positive and negative coverage.

---

## C. Windows Test Reliability

- **Original failure:** Both `test_governed_chain_provider_consumes_approval_before_fixed_root_lookup` and `test_modules_endpoint_is_authenticated_and_reports_planned_guards` failed during `create_app()` fixture setup in `artifacts/phase2b-targeted-closure-final-20261125-r2.xml` because `whoami.exe` and `icacls.exe` in `chinescan/core/storage/security.py` exceeded 5-second subprocess timeouts under full-suite load.
- **Root cause:** `get_windows_operator_identity()` spawned `whoami.exe` on every `secure_snapshot_directory()` / `verify_snapshot_storage_security()` call (multiple times per `create_app()` across hundreds of tests) with a 5-second timeout, and `verify_windows_directory_acl()` used a 5-second timeout for `icacls.exe` across thousands of newly created temporary directories.
- **Fix applied (`chinescan/core/storage/security.py`):**
  - Added `@lru_cache(maxsize=1)` to `get_windows_operator_identity()` (the current process's Windows user/SID is invariant for the process lifetime, eliminating ~1,000+ redundant `whoami.exe` spawns while preserving real `whoami.exe` execution and fail-closed `StorageSecurityError` on failure).
  - Increased `subprocess.run` timeouts in `get_windows_operator_identity()`, `verify_windows_directory_acl()`, and `secure_snapshot_directory()` to `15` seconds while preserving real NTFS ACL enforcement and verification (zero mocking or ACL weakening).
- **Focused verification:** `tests/unit/test_storage_security.py` + both previously failing tests: **12 passed, 0 failed** (29.95s).
- **Full-suite verification:** **880 passed, 0 failed, 5 deselected** (1307.10s, exit code 0).

---

## D. Verification Summary

| Check | Command / Scope | Result |
|---|---|---|
| Focused ACL & timeout tests | `py -3.12 -m pytest tests/unit/test_storage_security.py ... -q` | **12 passed, 0 failed** (29.95s) |
| Focused matrix, malware & log evidence | `py -3.12 -m pytest tests/unit/test_authorization_matrix_complete.py tests/unit/test_governed_malware.py tests/unit/test_log_evidence.py -q` | **33 passed, 0 failed** (109.30s) |
| Full Python suite | `py -3.12 -m pytest -q --disable-warnings --tb=short --junitxml=artifacts/phase2b-final-acceptance-20261125.xml` | **880 passed, 0 failed, 5 deselected** (1307.10s, exit code 0) |
| Frontend tests | `npm test -- --run` (in `frontend/`) | **77 passed** across 19 files (54.83s) |
| TypeScript check | `npx tsc --noEmit` (in `frontend/`) | **Passed** (0 errors) |
| Production build & CSP | `npm run build` (`tsc -b && vite build && npm run check:csp`) | **Passed** (strict CSP check passed) |
| Targeted mypy | `py -3.12 -m mypy chinescan/core/storage/security.py chinescan/core/organizations.py chinescan/web/malware_evidence_api.py chinescan/web/log_evidence_api.py` | **Passed** (0 issues in 4 source files) |
| Targeted Ruff | `py -3.12 -m ruff check ...` | 0 issues on `security.py`, `malware_evidence_api.py`, `log_evidence_api.py`; pre-existing `E501` only in `organizations.py`; 4 unused imports + long lines in new test file `test_authorization_matrix_complete.py` (non-blocking) |
| Alembic heads | `py -3.12 -m alembic heads` | **`0013_governed_chain_trace (head)`** (single head) |
| Git diff check | `git diff --check` | **Passed** (exit code 0; CRLF notices only) |

---

## E. Git Safety

- **Branch / HEAD:** `main` / `c09d3f150003421136790c42ffa96d570606da79`.
- **Staged changes:** None (`git diff --cached --name-only` is empty).
- **Commits / resets / stashes / rebases:** None performed.
- **ARTEX & existing work:** All pre-existing ARTEX files (`chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, `tests/unit/test_artex_integration.py`, `scripts/make_cover.py`, config files) and all pre-existing untracked reports/artifacts remain untouched and preserved.
- **Files added/modified in this pass:**
  - Modified: `chinescan/core/storage/security.py`, `chinescan/core/organizations.py`, `chinescan/web/app.py`, `chinescan/web/malware_evidence_api.py`, `chinescan/web/log_evidence_api.py`.
  - Added (unique names): `tests/unit/test_authorization_matrix_complete.py`, `docs/reports/phase-2b-final-sql-audit-2026-11-25.md`, `docs/reports/phase-2b-final-acceptance-2026-11-25.md`, `artifacts/phase2b-final-acceptance-20261125.xml`.

---

## F. Final Acceptance Decision

**PHASE 2B COMPLETE.** All Phase 2B acceptance criteria are satisfied: every tenant-sensitive SQL caller path is traced and enforced fail-closed, the role/assignment/operation authorization matrix has positive and negative regression coverage with zero privilege escalations, Windows ACL/path tests are reliable, the full Python suite passes (880 passed, 0 failed, 5 deselected), frontend/TypeScript/build/CSP/mypy/Alembic checks pass, and all existing user and ARTEX work is preserved. Do not proceed to Phase 2C without explicit user instruction.
