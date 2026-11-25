# Phase 2E — Resource Governance, Execution Limits & Process Supervision

**Report date:** 2026-11-25
**Branch:** `main`
**HEAD:** `c09d3f150003421136790c42ffa96d570606da79` (unchanged — no commits added in Phase 2E)
**Alembic head:** `0015_durable_job_leases_actions` (unchanged — no migration required in Phase 2E)
**Previous accepted phase:** Phase 2D — Durable Job Orchestration, Worker Leases & Crash Recovery
**Python:** 3.12.10
**Phase 2F status:** Not started.

---

## 1. Initial Repository State

At the start of Phase 2E:
- **Branch:** `main`
- **HEAD:** `c09d3f150003421136790c42ffa96d570606da79`
- **Staged changes:** None (`git diff --cached --name-only` empty)
- **`git status --short`:** 84 entries (57 modified tracked files from Phases 2B/2C/2D; 27 untracked files/directories including ARTEX, Phase 2B/2C/2D reports, migrations `0014` and `0015`, `artifacts/`, `tests/unit/test_phase2d_durable_jobs.py`)
- **Alembic head:** `0015_durable_job_leases_actions`
- **Prior full Python suite (Phase 2D):** 890 passed, 0 failures, 0 errors, 5 deselected

All pre-existing ARTEX and unrelated working-tree changes were preserved intact.

---

## 2. Existing Resource Controls Discovered

Pre-implementation inspection identified the following existing controls:
- `chinescan/core/execution_governance.py`: hardcoded `ACTIVE_JOB_LIMIT = 4` (per-org queued+active) and `GLOBAL_ACTIVE_JOB_LIMIT = 16` (global queued+active) checked in `create_governed_job` under `BEGIN IMMEDIATE`, raising `OverflowError`; `claim_next_job` used FIFO `ORDER BY created_at LIMIT 1`.
- `chinescan/core/orchestration/code_scan.py`: `ScanBounds` dataclass (`max_files=50_000`, `max_total_bytes=1_073_741_824`, `max_file_bytes=16_777_216`, `max_depth=32`, `per_file_seconds=2.0`, `job_deadline_seconds=300`).
- `chinescan/malware_analysis/process.py`: `_WindowsJob` (Windows Job Object with `KILL_ON_JOB_CLOSE`, memory/process limits) and `_native_posix_limits` for `run_static_worker` and `run_native_parser_worker`.
- `chinescan/scanners/external.py`: `ExternalCliScanner._run` used `subprocess.Popen` with env allowlist, `MAX_OUTPUT_BYTES`, and timeout, but only called `process.kill()` (direct child only, no Job Object / process-group tree kill).
- `chinescan/chain_trace/endpoint_policy.py`: `_resolve_with_timeout` used `subprocess.run` with strict `safe_env`, `CREATE_NO_WINDOW`, and `timeout_seconds`, plus `MAX_RESPONSE_BYTES` and redirect rejection in `chinescan/chain_trace/providers/evm.py`.
- `chinescan/core/config/settings.py`: `repository_snapshot_*`, `log_evidence_*`, `malware_evidence_*`, `chain_trace_*`, `github_import_*` limits, but `max_files` / `max_total_bytes` / `max_file_bytes` / `max_depth` / `job_deadline_seconds` were unvalidated bare fields and queue/concurrency/subprocess/network bounds were absent.

---

## 3. Gaps Identified

1. **No centralized, ceiling-validated resource-governance model** for queue/active/workload limits, deadlines, archive/parser/result bounds, subprocess bounds, or network bounds.
2. **No per-org fairness or active-slot concurrency caps** in `claim_next_job` (one organization could monopolize worker slots via FIFO ordering).
3. **No execution deadline or queue-wait expiry enforcement** in `ExecutionControl`, `claim_job`/`_claim_on_connection`, or `GovernedDomainWorker.run_one` (a job could run past `job_deadline_seconds` or wait indefinitely in `queued`).
4. **No common process-tree subprocess supervision** for external CLI scanners (`ExternalCliScanner._run` did not terminate child process trees on timeout/cancellation).
5. **No tenant-isolated execution quota endpoint or local-operator-only global execution resource diagnostics endpoint.**

---

## 4. Implemented Changes

### New Files
- `chinescan/core/resource_governance.py` — Centralized `ResourceLimits` (Pydantic `frozen=True`), operator-defined hard ceilings, `ResourceLimitError` (`status_code=429`), and `ExecutionDeadlineExceeded`.
- `chinescan/core/subprocess_supervision.py` — `run_supervised_subprocess` with executable validation, `shell=False`, env allowlist, bounded stdout+stderr capture, monotonic deadline + cancellation polling, Windows `_ProcessTreeJob` (Job Object `KILL_ON_JOB_CLOSE`) / `taskkill /F /T` fallback, and POSIX `start_new_session=True` + `os.killpg(..., SIGKILL)` tree termination.
- `tests/unit/test_phase2e_resource_governance.py` — 6 focused tests covering limits/ceilings, concurrent quota races & approval preservation, fair scheduling, queue-wait & execution deadlines (pre-dispatch and in-progress), supervised subprocesses + descendant cleanup, and tenant-isolated quota / local-operator diagnostics auth.

### Modified Tracked Files
- `chinescan/core/config/settings.py` — Added validated execution/archive/parser/subprocess/network limit fields with ceiling bounds and `validate_resource_governance_limits` model validator calling `ResourceLimits.from_settings(self)`.
- `configs/chinescan.example.toml` — Documented defaults, units, safe ranges, and restart requirement.
- `chinescan/core/execution_adapters.py` — Added `deadline_monotonic`, `operation_timeout_seconds`, `max_findings_per_job`, `remaining_seconds()`, `check_deadline()` to `ExecutionControl`; integrated `check_deadline()` into `check_cancelled()`; bounded `GovernedMalwareStaticTriageAdapter` deadline via `control.remaining_seconds()`; re-raised `ExecutionDeadlineExceeded` in `GovernedLogAnalysisAdapter`.
- `chinescan/core/execution_governance.py` — Added `resource_limits` to `ExecutionGovernanceService`; enforced `per_org_queued_limit` (`org_quota_exceeded`) and `global_queued_limit` (`execution_queue_full`) in `create_governed_job`; enforced `max_queue_wait_seconds` in `_claim_on_connection` (`EXECUTION_QUEUE_WAIT_EXPIRED` -> `blocked`); enforced `per_org_active_limit`, `global_active_limit`, `workload_concurrency_limits`, and fair per-org scheduling in `claim_next_job`; added `get_organization_resource_usage` and `get_global_resource_diagnostics`; enforced monotonic deadlines in `GovernedDomainWorker.run_one` and `_heartbeat_loop` (transitioning in-progress external actions to `reconciliation_required` and pre-dispatch timeouts to `failed` / `EXECUTION_DEADLINE_EXCEEDED`).
- `chinescan/scanners/external.py` — Routed `ExternalCliScanner._run` through `run_supervised_subprocess(..., popen_factory=subprocess.Popen)`.
- `chinescan/web/execution_api.py` — Caught `ResourceLimitError` for structured HTTP `429` responses and added `GET /api/organizations/{organization_id}/engagements/{engagement_id}/executions/quota`.
- `chinescan/web/app.py` — Wired `ResourceLimits.from_settings(active_settings)` into `ExecutionGovernanceService` and `GovernedDomainWorker`, and added `GET /api/diagnostics/execution-resources` protected by `require_local_operator_diagnostics(session)` and `allow_diagnostics(request)`.

---

## 5. Resource-Governance Model (Defaults, Units & Ceilings)

All limits are validated at `Settings` load time and cannot be raised above operator-defined ceilings via environment variables:

| Limit | Default | Unit | Hard Ceiling |
|---|---:|---|---:|
| `execution_per_org_active_limit` | 2 | active jobs | 16 |
| `execution_global_active_limit` | 8 | active jobs | 64 |
| `execution_per_org_queued_limit` | 4 | queued+active jobs | 64 |
| `execution_global_queued_limit` | 16 | queued+active jobs | 256 |
| `workload_concurrency_limits` (`domain`/`repository`/`log_evidence`/`malware_evidence`/`chain_address`) | 4 / 2 / 4 / 2 / 2 | active jobs | 32 |
| `job_deadline_seconds` | 300 | seconds | 3600 |
| `execution_max_queue_wait_seconds` | 900 | seconds | 86,400 |
| `execution_operation_timeout_seconds` | 60.0 | seconds | 600.0 |
| `execution_shutdown_grace_seconds` | 5.0 | seconds | 120.0 |
| `max_files` / `max_total_bytes` / `max_file_bytes` / `max_depth` | 50,000 / 1 GiB / 16 MiB / 32 | count / bytes / depth | 200,000 / 10 GiB / 128 MiB / 64 |
| `archive_max_entries` / `archive_max_nesting` / `archive_max_decompressed_bytes` | 10,000 / 4 / 256 MiB | count / depth / bytes | 100,000 / 16 / 2 GiB |
| `parser_max_output_bytes` / `max_findings_per_job` | 4 MiB / 5,000 | bytes / findings | 32 MiB / 50,000 |
| `subprocess_timeout_seconds` / `subprocess_max_output_bytes` | 60.0 / 4 MiB | seconds / bytes | 600.0 / 32 MiB |
| `network_connect_timeout_seconds` / `network_read_timeout_seconds` / `network_max_response_bytes` | 5.0 / 10.0 / 1 MiB | seconds / bytes | 30.0 / 60.0 / 16 MiB |
| `safe_retry_max_attempts` / `safe_retry_delay_seconds` | 2 / 0.5 | count / seconds | 5 / 30.0 |

All configuration changes require process restart.

---

## 6. Per-Organization & Global Quota Behavior

- **Admission (`create_governed_job`):** Under SQLite `BEGIN IMMEDIATE`, counts `queued | claimed | running` jobs for the organization and globally. Rejections roll back cleanly with `ResourceLimitError` (`org_quota_exceeded` / `execution_queue_full`, HTTP `429`) and **never consume sensitive approvals** or leave partial jobs.
- **Fair Scheduling (`claim_next_job`):** Under `BEGIN IMMEDIATE`, enforces `per_org_active_limit`, `global_active_limit`, and `workload_concurrency_limits[asset_type]`, sorting eligible queued jobs by `(org_active_count, created_at)` so one organization's queued backlog cannot starve another organization.
- **Reservation Lifecycle:** Durable `execution_jobs` rows in `queued | claimed | running` represent active reservations. Completed, failed, blocked, and cancelled jobs release their slot; crashed/expired safe jobs are re-queued by `recover_stale_jobs`; uncertain in-progress external actions transition to `reconciliation_required` (tracked separately in `reconciliation_required_jobs` and never automatically replayed).

---

## 7. Deadline & Timeout Enforcement

- **Queue wait expiry:** Checked in `_claim_on_connection` against `max_queue_wait_seconds`; expired queued jobs transition to `blocked` (`EXECUTION_QUEUE_WAIT_EXPIRED`) with audit event `execution.deadline_exceeded`.
- **Execution deadline:** `GovernedDomainWorker.run_one` computes `deadline_monotonic` from `min(default_job_deadline_seconds, expires_remaining)` and monitors it in both `_heartbeat_loop` and `ExecutionControl.check_deadline()` (invoked at `check_cancelled()`).
- **In-progress vs pre-dispatch:** If deadline expires before external dispatch, the job fails with `EXECUTION_DEADLINE_EXCEEDED`; if an external action is already `in_progress`, it transitions to `reconciliation_required` (`EXTERNAL_OUTCOME_UNCERTAIN`).

---

## 8. Subprocess Supervision

- `chinescan/core/subprocess_supervision.py` (`run_supervised_subprocess`) validates explicit executables, sets `shell=False`, filters environment variables via allowlist, caps combined stdout+stderr (`SUBPROCESS_OUTPUT_LIMIT_EXCEEDED`), enforces timeout (`SUBPROCESS_TIMEOUT`) and job deadline (`ExecutionDeadlineExceeded`), supports `threading.Event` cancellation (`SUBPROCESS_CANCELLED`), and terminates child process trees (Windows Job Object `KILL_ON_JOB_CLOSE` + `taskkill /F /T` fallback; POSIX `start_new_session=True` + `os.killpg(..., SIGKILL)`), reaping processes in `finally`.
- `chinescan/malware_analysis/process.py` continues to enforce Windows Job Object memory/process limits (`_WindowsJob`) and POSIX `rlimit` bounds for static malware and native parser workers.
- `chinescan/chain_trace/endpoint_policy.py` continues to use `subprocess.run` with strict `safe_env`, `CREATE_NO_WINDOW`, and `timeout_seconds` for DNS resolution.

---

## 9. Worker Shutdown & Recovery Behavior

`GovernedDomainWorker.stop(grace_seconds)` marks the worker `stopping` in `worker_leases`, sets `_stopping = True` to stop new claims, signals active job cancellation events, joins the worker thread for up to `shutdown_grace_seconds`, and unregisters the worker lease. Phase 2D lease fencing, `recover_stale_jobs`, and non-replayable `reconciliation_required` semantics remain intact.

---

## 10. Network & Parser Bounds

- `chinescan/chain_trace/providers/evm.py` preserves pinned-IP TLS, fixed host allowlists, redirect rejection (`_SameHostHTTPSRedirectHandler`), and `REQUEST_TIMEOUT_SECONDS` / `MAX_RESPONSE_BYTES`.
- `GovernedMalwareStaticTriageAdapter` bounds `analyze_file(..., deadline_seconds=...)` using `control.remaining_seconds()`.
- `GovernedLogAnalysisAdapter` propagates `ExecutionDeadlineExceeded` cleanly without masking it as `LOG_ANALYSIS_FAILED`.

---

## 11. Migration & Backup/Recovery Changes

**No Alembic migration was needed.** Existing `0015_durable_job_leases_actions` tables (`execution_jobs`, `execution_action_attempts`, `worker_leases`) support Phase 2E resource accounting and deadline enforcement without schema changes. Alembic head remains `0015_durable_job_leases_actions`.

---

## 12. Test Commands & Exact Results

| Suite / Command | Result |
|---|---|
| `py -3.12 -m pytest tests/unit/test_phase2e_resource_governance.py -v --tb=short --disable-warnings` | **6 passed, 0 failed** (17.29s) |
| `py -3.12 -m pytest tests/unit/test_external_scanners.py -v --tb=short --disable-warnings` | **8 passed, 0 failed** (1.53s) |
| `py -3.12 -m pytest -q --disable-warnings --tb=short --junitxml=artifacts/phase2e-final-20261125-r2.xml` | **896 passed, 0 failures, 0 errors, 5 deselected** (1693.35s; JUnit XML `artifacts/phase2e-final-20261125-r2.xml`, 125,155 bytes, `tests="896" failures="0" errors="0" skipped="0"`) |

---

## 13. Static Analysis (`ruff` & `mypy`)

### Ruff (`ruff 0.17.3`, `pyproject.toml`: `line-length = 100`, `select = ["E", "F", "I", "UP", "B"]`)

Baseline comparison against commit `c09d3f150003421136790c42ffa96d570606da79` across the 10 Phase 2E files (83 current findings vs 70 on the 7 tracked files at `c09d3f15`):
- **Pre-existing (`c09d3f15`):** **65**
- **Post-`c09d3f15` from ARTEX / Phase 2C / Phase 2D:** **11** (`5 × E501` in `settings.py` ARTEX validators; `2 × E501` in `execution_governance.py` from Phase 2D; `4 × F401` in `app.py` from ARTEX/Phase 2C)
- **Introduced by Phase 2E:** **7** (`7 × E501` in `tests/unit/test_phase2e_resource_governance.py` only; **0 findings** in `resource_governance.py`, `subprocess_supervision.py`, `external.py`, `endpoint_policy.py`, and 0 new findings in any modified implementation file!)
- **Removed since `c09d3f15`:** **5**

### Mypy

`py -3.12 -m mypy chinescan/core/resource_governance.py chinescan/core/subprocess_supervision.py chinescan/core/config/settings.py chinescan/core/execution_adapters.py chinescan/core/execution_governance.py chinescan/scanners/external.py chinescan/chain_trace/endpoint_policy.py chinescan/web/execution_api.py --ignore-missing-imports --no-error-summary`
**Result:** **0 errors** (`All checks passed!`).

---

## 14. Final Safety Acceptance & Resource-Enforcement Closure

### 14.1 Worker Shutdown and Lease Safety — **VERIFIED**
- **No active job:** `GovernedDomainWorker.stop()` marks `worker_leases.status = "stopping"`, joins `_thread`, and calls `unregister_worker()` (`worker_leases.status = "stopped"`).
- **Active job before external dispatch:** `stop()` sets `_active_cancellations[job_id]`, `ExecutionControl.check_cancelled()` raises `ExecutionCancelled`, and `run_one()` transitions the job to `cancelled` (`failed_before_dispatch`).
- **Active job after external action enters `in_progress`:** `observe_cancellation()` / `run_one()` preserves the consumed approval and transitions the job to `reconciliation_required`.
- **Worker thread exceeds `grace_seconds`:** `stop()` does **not** call `unregister_worker()`; `worker_leases.status` remains `"stopping"`. `recover_stale_jobs(include_stopped_workers=True)` only auto-recovers `"stopped"` workers or expired leases, so ownership is not relinquished prematurely while the old thread is alive.
- **Lease expiration / replacement worker fencing:** Once `lease_expires_at` passes, `recover_stale_jobs()` moves uncertain `in_progress` actions to `reconciliation_required`. Every durable mutation (`authorize_external_action`, `mark_action_in_progress`, `complete_action_attempt`, `record_progress`, `block_running_job`, `finish_job`, `observe_cancellation`) checks `worker_id` + `lease_generation` via `_lease_fenced()`, blocking the stale worker (`return False`).
- **Verified by:** `test_worker_shutdown_preserves_lease_when_thread_stuck_and_fences_stale_worker` (`tests/unit/test_phase2e_acceptance_closure.py`).

### 14.2 Durable Resource Accounting — **VERIFIED**
- `execution_jobs` rows in `queued | claimed | running` serve as durable slot reservations.
- Slots are released on `completed`, `failed`, and `cancelled`; `re-queued` on safe crash recovery; and separated into `reconciliation_required` (never auto-replayed) when an external action was `in_progress`.
- Concurrent `recover_stale_jobs` + `create_domain_job` cannot over-allocate capacity (`BEGIN IMMEDIATE`).
- **Verified by:** `test_durable_resource_accounting_release_and_concurrent_recovery` (`tests/unit/test_phase2e_acceptance_closure.py`).

### 14.3 Configuration vs Actual Enforcement Matrix

| Control | Classification | Enforcement Site & Notes |
|---|---|---|
| `max_findings_per_job` | **ENFORCED AND TESTED** | Enforced in `RepositoryCodeAssessmentAdapter.execute` (both `persist_partial` and final persistence loop; marks scan `partial` if truncated); tested by `test_max_findings_per_job_enforced_by_repository_adapter`. |
| `archive_max_entries` | **CONFIGURED BUT NOT ENFORCED** (ceiling config) | `log_analysis/ingest.py` (`MAX_ARCHIVE_MEMBERS=1_000`) and `malware_analysis/analyzer.py` (`MAX_ARCHIVE_MEMBERS=1_000`) enforce stricter hardcoded constants; `Settings.archive_max_entries` (`10_000`) is not dynamically wired into those parsers. |
| `archive_max_nesting` | **CONFIGURED BUT NOT ENFORCED** (ceiling config) | `malware_analysis/analyzer.py` enforces hardcoded archive recursion bounds; `Settings.archive_max_nesting` (`4`) is not dynamically wired. |
| `archive_max_decompressed_bytes` | **CONFIGURED BUT NOT ENFORCED** (ceiling config) | `log_analysis/ingest.py` (`MAX_ARCHIVE_BYTES=100_000_000`) and `malware_analysis/analyzer.py` enforce stricter hardcoded constants; `Settings.archive_max_decompressed_bytes` (`256 MiB`) is not dynamically wired. |
| `parser_max_output_bytes` | **CONFIGURED BUT NOT ENFORCED** (ceiling config) | `malware_analysis/process.py` (`WORKER_OUTPUT_BYTES=3 MiB`) and `scanners/external.py` (`MAX_OUTPUT_BYTES=10 MiB`) enforce hardcoded bounds; `Settings.parser_max_output_bytes` (`4 MiB`) is not dynamically wired. |
| `network_connect_timeout_seconds` | **CONFIGURED BUT NOT ENFORCED** (ceiling config) | `chain_trace/providers/evm.py` (`REQUEST_TIMEOUT_SECONDS=15`) and `integrations/artex/client.py` (`ArtexIntegrationSettings.timeout_seconds=3.0`) enforce their own timeouts. |
| `network_read_timeout_seconds` | **CONFIGURED BUT NOT ENFORCED** (ceiling config) | Same as `network_connect_timeout_seconds` (`evm.py` and `artex/client.py` use single per-request timeout). |
| `network_max_response_bytes` | **CONFIGURED BUT NOT ENFORCED** (ceiling config) | `chain_trace/providers/evm.py` (`MAX_RESPONSE_BYTES=2_000_000`) and `artex/client.py` (`ArtexIntegrationSettings.max_response_bytes=65_536`) enforce their own response caps. |
| `safe_retry_max_attempts` | **CONFIGURED BUT NOT ENFORCED** | No automatic in-adapter retry loop uses this setting; safe retries occur only via `recover_stale_jobs` re-queueing pre-dispatch jobs. |
| `safe_retry_delay_seconds` | **CONFIGURED BUT NOT ENFORCED** | Same as `safe_retry_max_attempts`. |

### 14.4 Additional Closure Verification Results
- **Combined Closure + Phase 2D + Repository Suite (`artifacts/phase2e-closure-combined-20261125.xml`):** **29 passed, 0 failed** in 94.49s (`test_phase2e_acceptance_closure.py` 3/3, `test_phase2e_resource_governance.py` 6/6, `test_phase2d_durable_jobs.py` 5/5, `test_repository_assessment.py` 15/15).
- **Full Python Suite Artifact (`artifacts/phase2e-final-20261125-r2.xml`):** Confirmed present (125,155 bytes), `tests="896" failures="0" errors="0" skipped="0"`. (Not re-run as the only subsequent source change was capping `persist_partial` + final loop in `RepositoryCodeAssessmentAdapter` when `len(saved_findings) >= max_findings_per_job`, covered directly by the 29-test combined run.)
- **Mypy on `chinescan/core/execution_adapters.py`:** **0 errors**.
- **Ruff on `tests/unit/test_phase2e_acceptance_closure.py`:** `5 × E501`, `2 × F401` (`7` non-functional lint findings introduced in the new closure test file).

---

## 15. Verification Matrix: VERIFIED vs INSPECTED vs NOT VERIFIED

| Item | Status | Evidence |
|---|---|---|
| `ResourceLimits` validation & ceiling rejection via `Settings` | **VERIFIED** | `test_resource_limits_and_settings_reject_invalid_ceilings` |
| Per-org/global queue quotas, concurrent admission race, & approval preservation | **VERIFIED** | `test_per_org_global_quotas_concurrent_race_and_approval_preservation` |
| Per-org active limit & fair scheduling across organizations | **VERIFIED** | `test_fair_scheduling_and_workload_concurrency_limits` |
| Queue-wait expiry (`EXECUTION_QUEUE_WAIT_EXPIRED`) & execution deadlines (pre-dispatch & `in_progress` -> `reconciliation_required`) | **VERIFIED** | `test_deadlines_before_claim_and_during_execution` |
| Supervised subprocess normal/non-zero exit, output limit, cancellation, timeout, & Windows descendant cleanup | **VERIFIED** | `test_supervised_subprocess_limits_timeout_cancellation_and_tree_cleanup`, `test_external_scanners.py` (8/8) |
| Tenant-isolated `/executions/quota` & local-operator-only `/api/diagnostics/execution-resources` | **VERIFIED** | `test_quota_and_diagnostics_tenant_isolation_and_auth` |
| Full Python regression suite (896 passed) | **VERIFIED** | `artifacts/phase2e-final-20261125-r2.xml` |
| `mypy` (0 errors) & Ruff baseline attribution (0 new impl findings) | **VERIFIED** | Direct command execution |
| POSIX `start_new_session=True` + `os.killpg` process-group termination | **INSPECTED** | `chinescan/core/subprocess_supervision.py` (executed on Windows host; POSIX branch not run here) |
| `max_findings_per_job` / `archive_max_*` / `network_*` centralized ceiling config wiring | **INSPECTED** | Validated in `ResourceLimits` & `Settings`; adapter-level enforcement relies on existing `ScanBounds`, `evm.py`, and `malware_analysis` bounds |
| Hard OS-level CPU/memory enforcement on arbitrary Python threads or multi-host/PostgreSQL/Redis | **NOT VERIFIED** | Out of scope; SQLite single-instance baseline only |

---

## 16. Known Limitations & Final Git State

1. **Non-functional Ruff findings:**  × E501\ in \	ests/unit/test_phase2e_resource_governance.py\, plus  × E501\ and  × F401\ in \	ests/unit/test_phase2e_acceptance_closure.py\ (0 new Ruff findings in Phase 2E implementation files).
2. **Configured-only ceiling fields:** \rchive_max_*\, \parser_max_output_bytes\, etwork_*\, and \safe_retry_*\ are validated in \ResourceLimits\ / \Settings\ while underlying modules enforce their own stricter or hardcoded constants (\ingest.py\, \nalyzer.py\, \process.py\, \external.py\, \evm.py\, \rtex/client.py\).
3. **POSIX process-group kill path** (\os.killpg\) is **INSPECTED** only (tested on Windows 11 via Job Object + \	askkill /F /T\).
4. **Python threads** cannot forcibly interrupt arbitrary C-level blocking without a subprocess boundary.
5. **SQLite single-instance baseline only** (not multi-host, PostgreSQL, Redis, or Kubernetes).
6. **No manual reconciliation endpoint** for econciliation_required\ jobs (unchanged from Phase 2D).

**Final Git State:**
- Branch: \main- HEAD: \c09d3f150003421136790c42ffa96d570606da79- Staged: None (\git diff --cached --name-only\ empty)
- Working tree: 91 \git status --short\ entries; all unrelated/ARTEX work preserved; Phase 2F not started.

---

## Acceptance Recommendation

**ACCEPTED WITH DOCUMENTED LIMITATIONS**
