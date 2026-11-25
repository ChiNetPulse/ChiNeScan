# Phase 2D — Durable Job Orchestration, Worker Leases & Crash-Safe Execution Recovery

**Report date:** 2026-11-25
**Branch:** `main`
**HEAD:** `c09d3f150003421136790c42ffa96d570606da79` (unchanged — no commits added in Phase 2D)
**Alembic head after Phase 2D:** `0015_durable_job_leases_actions`
**Previous phase:** Phase 2C — `0014_multi_user_identity_sessions`
**Python:** 3.12.10
**Phase 2E status:** Not started.

> [!IMPORTANT]
> This report reflects the final reconciled Phase 2D verification and Ruff baseline attribution against commit `c09d3f150003421136790c42ffa96d570606da79`.
> Evidence is explicitly separated into **VERIFIED**, **INSPECTED**, and **NOT VERIFIED**.

---

## 1. Final Repository State

| Item | Value |
|---|---|
| Branch | `main` |
| HEAD | `c09d3f150003421136790c42ffa96d570606da79` |
| Staged changes | **None** (`git diff --cached --name-only` empty) |
| Committed in Phase 2D | **Nothing** — all work remains in the working tree |
| `git status --short` entries | 84 total (57 modified tracked files across Phases 2B/2C/2D; 27 untracked files/directories) |
| ARTEX & unrelated work | Preserved intact (`chinescan/integrations/`, `docs/ARTEX-MILESTONE-1.md`, `tests/unit/test_artex_integration.py`, Phase 2B/2C reports and tests) |

### 1.1 Exact Phase 2D Files

**Modified tracked files (11):**
- `chinescan/core/execution_governance.py`
- `chinescan/core/storage/sqlite.py`
- `chinescan/core/storage/recovery.py`
- `chinescan/web/app.py`
- `tests/unit/test_engagement_security.py`
- `tests/unit/test_governed_malware.py`
- `tests/unit/test_log_evidence.py`
- `tests/unit/test_recovery.py`
- `tests/unit/test_repository_assessment.py`
- `tests/unit/test_storage.py`
- `tests/unit/test_migration.py`

**New untracked files created by Phase 2D (5):**
- `migrations/versions/0015_durable_job_leases_actions.py`
- `tests/unit/test_phase2d_durable_jobs.py`
- `docs/reports/phase-2d-durable-job-orchestration-report.md` (this report)
- `artifacts/phase2d-final-20261125-r3.xml` (JUnit XML, 124,277 bytes)
- `scripts/_phase2d_alembic_verify.py` (Alembic roundtrip and downgrade guard verification helper)

---

## 2. Implementation Summary

Phase 2D adds SQLite single-instance durable job orchestration, lease fencing, and crash-safe execution recovery without repeating one-use external security operations:

- **Alembic migration (`0015_durable_job_leases_actions`):**
  - Adds `worker_id`, `lease_generation`, `lease_expires_at`, `heartbeat_at`, `claimed_at`, `attempt_number`, and `last_recovery_at` to `execution_jobs`.
  - Extends `execution_jobs` status constraint and `execution_job_state_transition` trigger to support `reconciliation_required` and safe recovery transitions (`claimed -> queued`, `running -> queued`, `* -> reconciliation_required`).
  - Adds `execution_action_attempts` with monotonic `action_sequence` (`uq_exec_action_job_seq`), terminal-state immutability trigger, and no-delete trigger.
  - Adds `worker_leases` to track active/stopping/stopped workers.
  - Adds a downgrade guard raising `RuntimeError("Durable external-action history exists; use a forward migration to preserve it.")` if durable history rows exist.
- **Storage & Recovery (`sqlite.py`, `recovery.py`):** Keeps in-process SQLAlchemy metadata synchronized with `0015_durable_job_leases_actions` and adds schema/column verification for the new tables.
- **Governance & Worker (`execution_governance.py`, `app.py`):**
  - Atomic `claim_job` / `claim_next_job` under `BEGIN IMMEDIATE` with `lease_generation` CAS fencing.
  - `_lease_fenced` rejects stale `worker_id`, mismatched `lease_generation`, or expired `lease_expires_at`.
  - `heartbeat_job` extends `lease_expires_at` only for the active lease holder.
  - `authorize_external_action` requires `status == "running"`, enforces lease fencing, checks prior `execution_action_attempts`, blocks cross-generation/cross-worker duplicate actions (`DUPLICATE_EXTERNAL_ACTION_BLOCKED` -> `reconciliation_required`), and records durable intent.
  - `mark_action_in_progress` and `complete_action_attempt` track external action lifecycle; `outcome_uncertain` / `reconciliation_required` transitions the job to `reconciliation_required`.
  - `observe_cancellation` transitions to `reconciliation_required` (`CANCELLATION_OUTCOME_UNCERTAIN`) if an action is `in_progress`, or completes `cancelled` if no action started.
  - `recover_stale_jobs` re-queues safe jobs (no approval consumed and no unsafe action attempt) and moves uncertain jobs to `reconciliation_required`.
  - `create_app(..., start_governed_worker: bool = True)` and `CHINESCAN_STANDALONE_WORKER=1` control in-process worker startup.

> [!NOTE]
> Phase 2D does **not** claim exactly-once external execution. It enforces durable authorization-boundary tracking and prevents automatic replay of uncertain external actions, routing them to `reconciliation_required`.

---

## 3. Verification Results

### 3.1 Full Python Suite — **VERIFIED**

- **Artifact:** `artifacts/phase2d-final-20261125-r3.xml` (verified present, 124,277 bytes)
- **Parsed JUnit XML totals:** `tests="890" failures="0" errors="0" skipped="0" time="1685.476"`
- **Runner summary:** **890 passed, 0 failures, 0 errors, 5 deselected** (compared to Phase 2C baseline of 885 passed, 5 deselected; +5 new tests in `tests/unit/test_phase2d_durable_jobs.py`).

### 3.2 Focused Test Runs — **VERIFIED**

| Suite / Command | Result |
|---|---|
| `py -3.12 -m pytest tests/unit/test_phase2d_durable_jobs.py -v --tb=long --disable-warnings` | **5 passed, 0 failed** (23.09s) |
| `py -3.12 -m pytest tests/unit/test_phase2d_durable_jobs.py tests/unit/test_engagement_security.py -v --tb=short --disable-warnings -k "test_phase2d or test_atomic or test_lease or test_crash or test_action_attempt or test_cancellation_during or test_sensitive_approval or test_durable_cancellation"` | **11 passed, 44 deselected** (54.44s) |
| `py -3.12 -m pytest tests/unit/test_migration.py tests/unit/test_recovery.py tests/unit/test_storage.py -v --tb=short --disable-warnings -k "0015 or durable or worker_lease or action_attempt or backup"` | **5 passed, 23 deselected** (28.24s) |

### 3.3 Migration and Recovery — **VERIFIED**

Executed via `py -3.12 scripts/_phase2d_alembic_verify.py` and `test_crash_recovery_separates_safe_retry_from_uncertain_external_actions`:
- `alembic upgrade head` -> `0015_durable_job_leases_actions` (**0** `PRAGMA foreign_key_check` violations).
- `alembic downgrade 0014_multi_user_identity_sessions` -> succeeds when no durable history exists.
- `alembic upgrade head` -> `0015_durable_job_leases_actions` (**0** `PRAGMA foreign_key_check` violations).
- Downgrade guard: inserting a row into `execution_action_attempts` and attempting `downgrade 0014` raises `RuntimeError: Durable external-action history exists; use a forward migration to preserve it.`
- Backup and restore: `backup_database`, `verify_backup`, and `restore_database` preserve revision `0015_durable_job_leases_actions`, `reconciliation_required` job status, and all `execution_action_attempts` rows; uncertain actions remain `outcome_uncertain` and cannot be replayed.

### 3.4 Regression Semantics Confirmed — **VERIFIED**

1. **`test_sensitive_approval_remains_consumed_after_adapter_failure`** (`tests/unit/test_engagement_security.py:1501-1523`):
   - Once `authorize_external_action()` records the action and `mark_action_in_progress()` sets `in_progress`, an `AdapterFailure` leaves the external outcome uncertain.
   - Asserts `result == {"id": job["id"], "status": "reconciliation_required", "error_code": "EXTERNAL_OUTCOME_UNCERTAIN"}`, `approval.decision == "consumed"`, `approval.consumed_at is not None`, `persisted_job.status == "reconciliation_required"`, and `persisted_job.approval_consumed_at == approval.consumed_at`.
2. **`test_durable_cancellation_stops_sensitive_adapter_and_preserves_approval_state`** (`tests/unit/test_engagement_security.py:2074-2107`):
   - **`[False]` (before external action begins):** asserts `status == "cancelled"`, `external_actions == []`, and unconsumed approval remains `"approved"` (`consumed_at is None`).
   - **`[True]` (after external action enters `in_progress`):** asserts `status == "reconciliation_required"`, `external_actions == ["first"]`, `cancellation_requested_by`, `cancellation_requested_at`, `cancellation_observed_at` all preserved, and approval remains `"consumed"`.
3. **Replay & replacement worker prevention:** verified in `test_action_attempt_immutability_and_duplicate_action_blocked` (immutability trigger rejects `UPDATE`; second `authorize_external_action` with `lease_generation=99` returns `False`) and `test_crash_recovery_separates_safe_retry_from_uncertain_external_actions`.

---

## 4. Static Analysis

### 4.1 Ruff Baseline Attribution — **VERIFIED**

- **Ruff version & config:** `ruff 0.17.3` with `pyproject.toml` (`line-length = 100`, `target-version = "py312"`, `select = ["E", "F", "I", "UP", "B"]`).
- **Baseline reference:** `c09d3f150003421136790c42ffa96d570606da79` (note: this is the Phase 1 commit; Phase 2B and 2C changes in the working tree are uncommitted, so baseline comparison against `c09d3f15` separates `c09d3f15` pre-existing findings from post-`c09d3f15` findings, with per-line inspection attributing Phase 2D vs ARTEX/Phase 2C).

| Scope | Total Current | Matched Pre-existing (`c09d3f15`) | Introduced by Phase 2D | Post-`c09d3f15` from ARTEX / Phase 2C | Removed since `c09d3f15` |
|---|---:|---:|---:|---:|---:|
| **7-file subset (prior report)** | **143** (`137 E501`, `5 F401`, `1 I001`) | **109** | **26** | **8** (`4 F401` in `app.py`; `4 E501` in `recovery.py` already >100 in `c09d3f15`)* | **25** |
| **All 13 Phase 2D files** | **179** (`171 E501`, `5 F401`, `1 I001`, `2 F821`) | **144** (incl. `2 F821` in `test_log_evidence.py`, `1 I001` in `app.py`) | **26** | **9** (`4 F401` in `app.py`; `5 E501` in `recovery.py` already >100 in `c09d3f15`)* | **36** |

*\*Note on `recovery.py`: 5 `if revision in {...}` lines (471, 486, 505, 1222, 1241) were already `E501` in `c09d3f15` and merely had `"0014..."`/`"0015..."` appended; 2 lines (528, 1265) crossed 100 chars when `"0014..."`/`"0015..."` were added and are counted conservatively under **Introduced by Phase 2D**.*

**Breakdown of the 26 Ruff findings introduced by Phase 2D:**
- `tests/unit/test_phase2d_durable_jobs.py` (new file): **21** findings (`1 × F401` unused `import time` at line 5; `20 × E501`).
- `chinescan/core/execution_governance.py`: **2** `E501` findings (line 2050 docstring; line 2295 `update_stmt.values(...)`).
- `chinescan/core/storage/sqlite.py`: **1** `E501` finding (line 842 `status IN (...,'reconciliation_required')`).
- `chinescan/core/storage/recovery.py`: **2** `E501` findings (lines 528 and 1265 `if revision in {...}`).
- `migrations/versions/0015_durable_job_leases_actions.py`: **0** reported findings (module-level `# ruff: noqa: E501` suppresses SQL string line-length checks).

### 4.2 Mypy — **VERIFIED (with pre-existing ARTEX qualification)**

- **Command:** `py -3.12 -m mypy chinescan/web/app.py chinescan/core/execution_governance.py chinescan/core/storage/sqlite.py chinescan/core/storage/recovery.py --ignore-missing-imports --no-error-summary`
- **Result:** 1 error in `chinescan/integrations/artex/client.py:40` (`Argument 1 to "HTTPSConnection" has incompatible type "str | None"; expected "str" [arg-type]`).
- **Attribution:** `chinescan/integrations/artex/client.py` is an untracked ARTEX integration file not modified by Phase 2D, pulled in transitively by `chinescan/web/app.py`. **Zero mypy errors** in any Phase 2D-modified file.

---

## 5. Evidence Matrix: VERIFIED vs INSPECTED vs NOT VERIFIED

| Item | Status | Evidence |
|---|---|---|
| Atomic concurrent claim (`lease_generation` CAS) | **VERIFIED** | `test_atomic_concurrent_claim_with_independent_connections` |
| Heartbeat extension, expiry, and stale-worker fencing | **VERIFIED** | `test_lease_heartbeat_expiry_and_stale_worker_fencing` |
| Crash recovery separates safe re-queue vs `reconciliation_required` | **VERIFIED** | `test_crash_recovery_separates_safe_retry_from_uncertain_external_actions` |
| Action attempt immutability trigger & duplicate-action block | **VERIFIED** | `test_action_attempt_immutability_and_duplicate_action_blocked` |
| Cancellation before vs during `in_progress` external action | **VERIFIED** | `test_durable_cancellation_stops_sensitive_adapter_and_preserves_approval_state[False/True]`, `test_cancellation_during_in_progress_preserves_uncertainty_and_worker_shutdown` |
| Post-dispatch `AdapterFailure` -> `reconciliation_required` | **VERIFIED** | `test_sensitive_approval_remains_consumed_after_adapter_failure` |
| `GovernedDomainWorker` start/stop lease registration | **VERIFIED** | `test_cancellation_during_in_progress_preserves_uncertainty_and_worker_shutdown` |
| Backup/restore preservation of `reconciliation_required` & action attempts | **VERIFIED** | `test_crash_recovery_separates_safe_retry_from_uncertain_external_actions` |
| Alembic `0015` upgrade/downgrade/upgrade roundtrip & FK check | **VERIFIED** | `scripts/_phase2d_alembic_verify.py` |
| Alembic `0015` downgrade guard when action history exists | **VERIFIED** | `scripts/_phase2d_alembic_verify.py` |
| Full Python regression suite (890 passed) | **VERIFIED** | `artifacts/phase2d-final-20261125-r3.xml` |
| Ruff baseline attribution (26 Phase 2D lint findings, 0 functional errors) | **VERIFIED** | Baseline comparison against `c09d3f15` |
| `authorize_external_action` requires `status == "running"` | **INSPECTED** | `chinescan/core/execution_governance.py:1413` |
| `GovernedDomainWorker._run()` 10-idle-tick `recover_stale_jobs()` cadence | **INSPECTED** | `chinescan/core/execution_governance.py` (`_run()`) |
| `_validate_lease_bounds` (`5.0 <= lease <= 3600.0`, heartbeat <= half lease) | **INSPECTED** | `chinescan/core/execution_governance.py:1310-1319` |
| `CHINESCAN_STANDALONE_WORKER=1` env var bypasses in-process worker start | **INSPECTED** | `chinescan/web/app.py:894` (`start_governed_worker=False` tested) |
| Manual operator reconciliation workflow/endpoint | **NOT VERIFIED** | Not implemented in Phase 2D |
| Multi-host / distributed worker / PostgreSQL / Redis / K8s behavior | **NOT VERIFIED** | Out of scope; SQLite single-instance baseline only |
| Phase 2C open gaps (TOTP HTTP happy-path, invitation audit, migration rollback) | **NOT VERIFIED** | Inherited from Phase 2C; unchanged by Phase 2D |

---

## 6. Known Limitations

1. **26 Ruff style/unused-import findings introduced by Phase 2D:** `1 × F401` (`import time` in `test_phase2d_durable_jobs.py`) and `25 × E501` (20 in `test_phase2d_durable_jobs.py`, 2 in `execution_governance.py`, 1 in `sqlite.py`, 2 in `recovery.py`), plus `# ruff: noqa: E501` in migration `0015`. None affect runtime correctness or security.
2. **No manual reconciliation API/UI:** `reconciliation_required` jobs halt automatic replay safely, but operator reconciliation endpoints are not part of Phase 2D.
3. **Inspected-only edge paths:** `_run()` 10-tick idle recovery cadence, `_validate_lease_bounds` error branches, and `CHINESCAN_STANDALONE_WORKER=1` env var handling are inspected but not directly unit-tested.
4. **Deployment scope:** Supported only on the **SQLite single-instance** baseline (`BEGIN IMMEDIATE` serialization). Does not establish multi-host, PostgreSQL, Redis, Kubernetes, or production readiness.
5. **Inherited Phase 2C gaps:** Documented in `docs/reports/phase-2c-final-security-acceptance-review-2026-11-25.md` and remain unresolved.

---

## 7. Final Acceptance Decision

**Decision: ACCEPTED WITH DOCUMENTED LIMITATIONS**

**Rationale:**
- All Phase 2D security and durability invariants—atomic job claiming, lease fencing, heartbeat expiry, action-attempt persistence, duplicate-action blocking, crash recovery separation, cancellation uncertainty preservation, backup/restore preservation, and Alembic `0015` upgrade/downgrade guard—are implemented and verified by passing tests (`890 passed, 0 failed, 0 errors, 5 deselected`).
- The two updated regression tests strengthen/preserve security semantics (`reconciliation_required` instead of `failed`/`cancelled` once an external action is `in_progress`).
- The qualification (`WITH DOCUMENTED LIMITATIONS`) reflects the 26 non-functional Ruff lint findings (`F401`/`E501`) introduced in Phase 2D files, the inspected-only helper/cadence paths, the absence of a manual reconciliation UI/API, and the SQLite single-instance deployment boundary.

Phase 2E has **not** started.
