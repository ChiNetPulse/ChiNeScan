# Phase 2B Final Direct-SQL Caller-Path Authorization Audit (2026-11-25)

**Repository:** `C:\GitHub\Chinescan`
**Branch / HEAD:** `main` / `c09d3f150003421136790c42ffa96d570606da79`
**Scope:** Live Python AST scan of all `execute` and `exec_driver_sql` call sites under `chinescan/` (**380 live sites** across **139 functions** in **12 modules**: **379 SQL executions** + **1 governed adapter invocation** `adapter.execute` at `chinescan/core/execution_governance.py:1842`). `git grep` confirms zero `sqlalchemy.text()` usage.

> **Delta vs. prior 381-site register (`docs/reports/phase-2b-direct-sql-audit.md`):** The prior register inventoried 381 sites (including 71 in `organizations.py`). Refactoring `OrganizationService.update_organization` in Phase 2B to delegate to `self.has_role(...)` removed 1 duplicate `connection.execute(...)` site in `organizations.py`, bringing the live AST total from 381 to **380** (379 SQL executions + 1 governed adapter invocation). Every site is classified **exactly once** below with zero double-counting or omissions.

---

## 1. Classification Summary

| Category | Count | Disposition |
|---|---:|---|
| **Total live AST execution/adapter sites** | **380** | 379 SQL executions + 1 governed adapter invocation (`adapter.execute`) |
| **1. Tenant-sensitive queries & adapter dispatch (verified safe)** | **311** | Proven caller-level principal, organization/engagement/membership/role boundaries, and fail-closed context enforcement (310 SQL sites + 1 governed adapter invocation) |
| **2. Global / non-tenant-sensitive queries (verified safe)** | **24** | Local operator dashboard alerts (`dashboard_alerts.py`, 17), diagnostics SQLite health/temp-probe (`diagnostics.py`, 5), SQLite connection PRAGMA (`sqlite.py`, 1), local operator CLI identity/count (`commands.py`, 1) |
| **3. Privileged queries with explicit authorization** | **45** | `execution_governance.py::_next_job_id` (1), `organizations.py::ensure_operator` bootstrap/legacy-ownership (17), `storage/recovery.py` local DB backup/restore/verify (27) |
| **4. Unresolved queries** | **0** | Zero unresolved tenant-sensitive caller paths |
| **5. Confirmed unsafe queries** | **0** | All identified gaps remediated and regression-tested |

**Why the 17 `organizations.py::ensure_operator` sites are classified exclusively as Privileged (and not Global):** `ensure_operator()` is an explicit pre-multi-user/bootstrap operation invoked only after local operator credential validation (`app.py` startup, authenticated login/signup bootstrap, or `_local_cli_repository` CLI setup). It provisions/validates the operator's personal organization, maps legacy unowned records into that personal organization, and writes an `organization_bootstrap_reports` record. It is not a general global query and is counted **once** in Privileged (17 sites).

### Per-Module Breakdown (Reconciled to 380 Live Sites)

| Module | Sites | Tenant-sensitive (Verified Safe) | Global / Non-tenant-sensitive (Verified Safe) | Privileged (Verified Auth) | Unresolved | Unsafe |
|---|---:|---:|---:|---:|---:|---:|
| `chinescan/cli/commands.py` | 1 | 0 | 1 (`SQL-001` local operator count) | 0 | 0 | 0 |
| `chinescan/core/dashboard_alerts.py` | 17 | 0 | 17 (`SQL-002..018` local-instance alerts) | 0 | 0 | 0 |
| `chinescan/core/diagnostics.py` | 6 | 1 (`SQL-024` local-operator-gated aggregate) | 5 (`SQL-019..023` SQLite temp probe) | 0 | 0 | 0 |
| `chinescan/core/engagement_security.py` | 55 | 55 | 0 | 0 | 0 | 0 |
| `chinescan/core/execution_adapters.py` | 4 | 4 | 0 | 0 | 0 | 0 |
| `chinescan/core/execution_governance.py` | 60 | 59 (58 SQL + 1 `adapter.execute` at L1842) | 0 | 1 (`SQL-141` `_next_job_id`) | 0 | 0 |
| `chinescan/core/log_evidence.py` | 28 | 28 | 0 | 0 | 0 | 0 |
| `chinescan/core/malware_evidence.py` | 18 | 18 | 0 | 0 | 0 | 0 |
| `chinescan/core/organizations.py` | 70 | 53 | 0 | 17 (`SQL-193..209` `ensure_operator`) | 0 | 0 |
| `chinescan/core/repository_assessment.py` | 57 | 57 | 0 | 0 | 0 | 0 |
| `chinescan/core/storage/recovery.py` | 27 | 0 | 0 | 27 (`SQL-318..344` local backup/restore/verify) | 0 | 0 |
| `chinescan/core/storage/sqlite.py` | 37 | 36 | 1 (`SQL-352` `PRAGMA foreign_keys=ON`) | 0 | 0 | 0 |
| **Total** | **380** | **311** | **24** | **45** | **0** | **0** |

*(311 + 24 + 45 = 380 live AST sites: 379 SQL executions + 1 governed adapter invocation; 0 unresolved, 0 unsafe.)*

---

## 2. Distinct Tenant-Sensitive Caller Paths & Authorization Boundaries

### Group 1 — `SQLiteRepository` (`chinescan/core/storage/sqlite.py`: 36 tenant-sensitive sites + 1 PRAGMA)
- **Execution sites:** `organization_context` (L950), `member_context` (L987), `_ensure_record_ownership` (L1125, L1132), `_linked_engagement_id` (L1166), `_link_execution_result` (L1185, L1195), `save` (L1282, L1287, L1293), `consume_malware_acknowledgement` (L1309, L1311, L1338), `delete` (L1362), `save_many` (L1379, L1384, L1390), `save_malware_intake` (L1416, L1418, L1434), `enqueue_malware_analysis` (L1458, L1460, L1471, L1483, L1491), `claim_next_malware_job` (L1507, L1509, L1521, L1537), `get` (L1561), `get_many` (L1580), `list_records` (L1592), `page_records` (L1640, L1644), `count_records` (L1670, L1683).
- **Authorization boundary:**
  - `_owned_record(for_write=...)` (L1062–1103) raises `StorageError` if `_organization_context` (`ContextVar`) is `None` or if `for_write=True` without `_organization_write_access`.
  - When `_organization_principal_id` is set (via `member_context`), `_owned_record` intersects organization role (`owner`/`admin` for writes; `owner`/`admin`/`auditor`/`viewer` for reads) OR active `engagement_assignments` (restricted to `lead`/`assessor`/`reviewer` when writing).
  - `_ensure_record_ownership` (L1105–1140) enforces write context and records `organization_id` and `engagement_id` in `record_ownership`.
- **Reachable callers:**
  - **HTTP (`chinescan/web/app.py`):** Middleware (L1094–1193) authenticates session, validates `x-chinescan-organization-id` via `organization_service.membership_context(session.user_id, selected)`, rejects non-`owner/admin/member` on mutating methods, and enters `repository.member_context(organization_id, session.user_id, write=...)` around `call_next(request)`.
  - **HTTP Streaming (`chinescan/web/app.py`):**
    - `GET /api/scans/{scan_id}/findings.jsonl` (L2915–2995) captures `organization_id` and `user_id` and re-enters `repository.member_context(organization_id, user_id, write=False)` inside the generator.
    - **Fixed in this pass:** `GET /api/alerts/events` (`dashboard_alert_events`, L2311–2345) previously called `dashboard_intelligence.refresh_alerts()` inside `async def stream()` after the middleware's `authorization_scope` had exited. It now captures `organization_id` and `user_id` and enters `with repository.member_context(organization_id, user_id, write=False):` around `dashboard_intelligence.refresh_alerts()`.
  - **CLI (`chinescan/cli/commands.py`, `chinescan/cli/chain_commands.py`):** `_local_cli_repository()` validates local operator credentials and binds `local_operator_context()` (personal org); governed CLI commands validate active membership and bind `member_context()`.
  - **Workers (`chinescan/web/*_jobs.py`, `chinescan/core/execution_governance.py`):** Local operator managers bind `local_operator_context()` only when operator identity exists. `GovernedDomainWorker.run_one` (L1784–1868) does **not** treat persisted job fields as standalone authority: `_next_job_id()` selects only an opaque queued `job_id`; `claim_job(job_id)` atomically runs `_validate_context()` (revalidating expiration, active `engagement_assets`, full `EngagementSecurityService._decision()` for requester/org/engagement/membership/assignment/scope/authorization, `authorization_documents.sha256`, `request_digest`, snapshot/binding/attestation/chain-context integrity, and active approver role/assignment for sensitive actions); `revalidate_job()` re-checks before dispatch; `ExecutionControl.revalidate` runs `authorize_external_action()` at sensitive action boundaries; and only then does `run_one` enter `member_context(context.organization_id, context.requester_user_id, write=True)` (which itself re-verifies active user, org, membership, and write role) around `adapter.execute(...)` (L1842).
- **Context propagation:** `ContextVar` (`_organization_context`, `_organization_principal_id`, `_organization_write_access`, `_execution_provenance_context`) is isolated per thread/async task and explicitly re-established in worker threads and streaming generators.

### Group 2 — `OrganizationService` (`chinescan/core/organizations.py`: 53 tenant-sensitive + 17 `ensure_operator` privileged)
- **Execution sites:** `user_id_for_email` (L55), `personal_organization_id` (L63), `get_active_user` (L290), `current_user` (L303), `accessible_organizations` (L308), `has_role` (L329), `membership_role` (L347), `organization` (L368), `members` (L377), `create_organization` (L392–417), `update_organization` (L429–441), `update_membership` (L469–518), `add_member` (L537–584), `clients` (L592), `client` (L605), `update_client` (L621–630), `create_client` (L653), `engagements` (L661), `_can_read_engagement` (L676–691), `engagement` (L724), `update_engagement` (L749–824), `create_engagement` (L860–879), `assignments` (L895–902), `change_assignment` (L932–997), `_has_assignment` (L1013), `migration_report` (L1047).
- **Reachable callers:** `chinescan/web/organization_api.py` (all routes require `current_session`, mutating routes require `require_csrf`; `/api/organization-migration-report` additionally checks `user_id == service.operator_user_id`), `chinescan/web/app.py` middleware, `EngagementSecurityService`, `RepositoryAssessmentService`.
- **Authorization & remediation:**
  - `SQL-259` (`_has_assignment`, L1008–1043) requires `organization_memberships.c.role == "member"`, active user/org/membership/engagement, and active assignment.
  - **Fixed in this pass:** `update_organization` (L420–450) previously queried `organization_memberships` directly without checking `organizations.status == "active"` or `users.status == "active"`. It now delegates to `self.has_role(user_id, organization_id, {"owner", "admin"})`, which enforces active user, active organization, and active membership.

### Group 3 — `EngagementSecurityService` (`chinescan/core/engagement_security.py`: 55 sites)
- **Execution sites:** `_membership` (L210), `_assignment_roles` (L228), `_engagement` (L256), `_audit` (L320), `list_assets` (L342), `create_asset` (L378, L403), `update_asset` (L431, L458), `scope_revisions` (L481), `_scope_detail` (L492), `get_scope_revision` (L519), `create_scope_revision` (L541–625), `publish_scope_revision` (L660–686), `_latest_published_scope` (L718), `list_authorizations` (L736, L747), `create_authorization` (L791, L829), `revoke_authorization` (L848, L869), `put_authorization_document` (L901–941), `get_authorization_document` (L960), `list_approvals` (L984), `_decision` (L1101–1405), `_asset_id_for_target` (L1453), `evaluate_policy` (L1500), `create_approval_request` (L1546–1604), `decide_approval` (L1659–1760), `audit_history` (L1806).
- **Authorization boundary:** Every public method enforces `_can_read`, `_can_manage`, `_can_operate`, or `_can_review` inside the same database connection/transaction, intersecting organization role (`owner`/`admin`/`member` vs read-only `auditor`/`viewer`) with active engagement assignment. `publish_scope_revision` and `decide_approval` enforce separation of duties (author/requester cannot self-approve/self-publish).
- **Reachable callers:** `chinescan/web/engagement_security_api.py` (all routes enforce `current_session` and `require_csrf` on mutations), `ExecutionGovernanceService`, `LogEvidenceStore`, `MalwareEvidenceStore`, `RepositoryAssessmentService`.

### Group 4 — `ExecutionGovernanceService` & `RepositoryCodeAssessmentAdapter` (`execution_governance.py`: 59+1; `execution_adapters.py`: 4)
- **Execution sites:** `create_governed_job` (17 sites), `get_job` (L632), `get_job_provenance` (L650, L670), `list_jobs` (L735), `request_cancellation` (L753–833), `observe_cancellation` (L884–898), `_validate_context` (8 sites, L954–1171), `authorize_external_action` (5 sites, L1230–1371), `claim_job` (3 sites, L1414–1428), `block_running_job` (2 sites), `finish_job` (3 sites), `partial_result` (1 site), `GovernedDomainWorker.start` (2 sites, L1737, L1742), `GovernedDomainWorker._next_job_id` (1 privileged site, `SQL-141`, L1776), `GovernedDomainWorker.run_one` (1 SQL site at L1791 + 1 governed adapter invocation `adapter.execute` at L1842), plus `RepositoryCodeAssessmentAdapter.execute` (4 sites, L489–538).
- **Authorization boundary:**
  - Submission (`create_governed_job`) re-evaluates policy (`_decision`) requiring `_can_operate` (`owner`/`admin`/`member` + `lead`/`assessor`).
  - Reads (`get_job`, `get_job_provenance`, `list_jobs`) require `_can_read`.
  - Cancellation (`request_cancellation`) requires active membership AND (`requester_user_id == user_id` OR `_can_manage`).
  - Worker execution (`claim_job` -> `_validate_context` -> `authorize_external_action` -> adapter) re-validates persisted job organization, engagement, active asset, scope, authorization document SHA-256, request digest, and approval/approver role (`owner`/`admin` or `member`+`lead`/`reviewer`) before consuming approval or executing.
  - `RepositoryCodeAssessmentAdapter.execute.persist_partial` (L515–548) opens `organization_context` + `execution_provenance_context` (which preserves write access only if the caller already established `member_context(..., write=True)` for the same `organization_id`).
- **Reachable callers:** `chinescan/web/execution_api.py`, `chinescan/web/repository_execution_api.py`, `chinescan/web/log_evidence_api.py`, `chinescan/web/malware_evidence_api.py`, `GovernedDomainWorker`, CLI governed commands.

### Group 5 — `RepositoryAssessmentService` & `RepositorySnapshotStore` (`chinescan/core/repository_assessment.py`: 57 sites)
- **Execution sites:** `RepositoryAssessmentService` (`create_asset`, `bind`, `_validate_binding_connection`, `_is_lead_connection`, `list_assets`, `retention_candidates`, `quota`) and `RepositorySnapshotStore` (`create`, `verify`, `remove_unreferenced`, `_audit`, `hold`, `release_hold`, `delete_eligible`, `_audit_repository`).
- **Authorization boundary:** `SQL-310` (`_is_lead_connection`, L834–854) enforces `organization_memberships.c.role.in_(("owner", "admin", "member"))`, `engagement_assignments.c.role == "lead"`, and active user/org/membership/assignment/engagement. `list_assets` and `retention_candidates` enforce `security._can_read`. `hold`/`release_hold`/`delete_eligible` enforce `_is_lead_connection_allowed_closed` (`require_active_engagement=False` for post-closure retention).
- **Reachable callers:** `chinescan/web/repository_execution_api.py` (all routes require `current_session` and `require_csrf` on mutations).

### Group 6 — `LogEvidenceStore` (`chinescan/core/log_evidence.py`: 28 sites) & `MalwareEvidenceStore` (`chinescan/core/malware_evidence.py`: 18 sites)
- **Authorization boundary:**
  - `LogEvidenceStore`: `register` and `list_for` enforce `security._can_operate`; `place_hold` and `delete_explicitly` enforce `security._can_manage` (plus `completed`/`archived` engagement, no legal hold, no active job).
  - `MalwareEvidenceStore`: `register` enforces `security._can_operate` and `security.create_asset` (`_can_manage`); `get` and `list_for` enforce `security._can_read`; `set_hold` and `delete` enforce `security._can_operate` (plus `completed`/`archived` engagement, no legal hold, no active job).
- **Reachable callers:** `chinescan/web/log_evidence_api.py` and `chinescan/web/malware_evidence_api.py` (all routes enforce `current_session` and `require_csrf` on mutations).
  - **Fixed in this pass:** Both `log_evidence_api.py:154` and `malware_evidence_api.py:128` previously checked `result.get("decision") != "ALLOW"`, which rejected valid `create_governed_job` responses (since `create_governed_job` returns the queued job dict without a `"decision"` key). Both now match `execution_api.py` by checking `result.get("decision") in {"DENY", "REQUIRE_APPROVAL"} or not result.get("id")`.

### Group 7 — Diagnostics & Local Operator Control Plane (`diagnostics.py`: 6 sites, `dashboard_alerts.py`: 17 sites, `commands.py`: 1 site, `recovery.py`: 27 sites)
- **Diagnostics (`SQL-019..024`):** `/api/ready` and `/api/diagnostics` in `chinescan/web/app.py` (L1280–1340) enforce `current_session` AND `require_local_operator_diagnostics(session)` (matching `session.user_id == organization_service.operator_user_id`; non-operators receive 404). CLI diagnostics (`commands.py:640,654`) run locally on the operator machine. `SQL-024` returns only status-bucket counts, never record payloads.
- **Dashboard alerts (`SQL-002..018`):** Global local-instance alert state; all `/api/alerts*` routes in `chinescan/web/app.py` are behind `operator_only_prefixes` (local operator + personal org + write-role check).
- **Local CLI (`SQL-001`):** `_local_cli_repository()` validates local operator credentials before counting `users`/`records`.
- **Recovery (`SQL-318..344`):** `db backup` / `db restore` require `_authorize_local_database_maintenance()`; `verify_backup` reads only an explicit local bundle path. No recovery SQL is exposed over HTTP.
