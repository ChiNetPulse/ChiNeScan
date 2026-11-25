# ChiNeScan — Phase 2 Architecture Audit

**Document:** `docs/reports/phase-2-architecture-audit.md`
**Date:** 2026-11-24
**Repository:** `C:\GitHub\Chinescan`
**Current Branch:** `main`
**Baseline Commit:** `c09d3f150003421136790c42ffa96d570606da79`
**Status:** Read-only architecture audit complete

---

## Executive Summary

Phase 1 established an authoritative security and governance foundation for ChineScan:
- Persistent user and organization identities (`users`, `organizations`, `organization_memberships`).
- Clients, engagements, and engagement assignments (`clients`, `engagements`, `engagement_assignments`).
- Scope revisions, authorization documents, and centralized `ALLOW` / `DENY` / `REQUIRE_APPROVAL` policy (`engagement_security.py`).
- One-use human approvals atomically consumed at external action boundaries (`approval_requests`).
- Governed execution jobs with immutable execution context and SHA-256 digests (`execution_jobs`, `execution_governance.py`).
- Execution result provenance linking every created scan, finding, and evidence record (`execution_result_provenance`).
- Adapter contracts for domain posture, repository assessment, log analysis, static malware triage, and chain tracing (`execution_adapters.py`).
- Database migrations (`0001_initial` through `0013_governed_chain_trace`).
- Diagnostic readiness reporting, structured logging with secret redaction, and loopback web API binding.

However, ChineScan's runtime operates as a **hybrid single-operator workstation** rather than a true multi-user platform. The core authentication, session management, job dispatch, and worker execution models rely heavily on single-file local state and process-local memory:
1. **Authentication is tied to a single file:** A single operator credentials JSON file (`operator.json`) holds password hashes, TOTP secrets, and recovery tokens. No multi-user login, registration, or invitation workflow exists in the database.
2. **Sessions and rate limiters are purely in-memory:** The session store is an in-memory dictionary. Any process restart logs out all users and wipes rate-limiting state.
3. **Dual-track API & UI:** Legacy single-operator routes (`/api/projects`, `/api/code`, `/api/log`, `/api/malware`, `/api/chain`) operate on personal workspaces and require local operator credentials. Meanwhile, Phase 1 multi-tenant engagement routes (`/api/organizations/...`) exist side-by-side but lack complete frontend workflow integration.
4. **Worker is single-threaded in-process with coarse crash recovery:** The governed execution worker runs as a daemon thread inside the FastAPI server. If the server terminates, active jobs are marked `failed` on the next startup, but during runtime, worker crashes or deadlocks leave jobs in `running` indefinitely because there is no lease, heartbeat, or worker ownership tracking.
5. **Multi-user RBAC gaps:** Roles exist in schema, but there is no invitation flow (adding a member requires an existing user ID, which cannot be created through the web platform), and tenant scoping relies on ambient context vars that default to un-scoped queries if omitted.

This audit establishes the concrete architectural gap between Phase 1 and a dependable multi-user web platform, adhering strictly to the SQLite and single-instance baseline.

---

## 1. Authentication and Account Lifecycle

### 1.1 Current Implementation Baseline

Authentication is implemented across `chinescan/core/accounts.py`, `chinescan/web/auth.py`, and `chinescan/web/app.py`:
- **Credential Storage:** Stored in a standalone JSON file at `Settings().credential_path` (default: `~/.local/share/chinescan/operator.json`). It holds `email`, `identity_id`, `password_hash` (Argon2id), `auth_epoch`, `totp_secret`, `totp_recovery_code_hashes`, and `reset_token_hash`.
- **Identity Bootstrap:** In `OrganizationService.ensure_operator(...)`, the email and stable identity UUID from `operator.json` are idempotently mapped into the SQLite `users` table and assigned ownership of a personal organization (`personal-<id>`).
- **Session Management:** `SessionStore` in `chinescan/core/accounts.py` is an in-memory class with `self._sessions: dict[str, Session] = {}`.
  - Sessions contain `email`, `csrf_token`, `expires_at` (absolute TTL: 30 minutes), `idle_ttl_seconds` (10 minutes), `auth_epoch`, and `user_id`.
  - Maximum 128 active sessions tracked in memory; oldest evicted when capacity is reached.
  - Session lookup verifies the session against `operator_auth_epoch(credentials)` and `user.auth_epoch` in SQLite.
- **CSRF Defense:**
  - Double-submit style defense: On write requests (`POST`, `PUT`, `PATCH`, `DELETE`), middleware verifies `Origin` header matches `Host`.
  - `require_csrf` dependency checks that the `X-CSRF-Token` header matches `session.csrf_token` via `secrets.compare_digest`.
- **Two-Factor Authentication (TOTP):**
  - RFC 6238 TOTP using HMAC-SHA1, 30-second intervals, 6 digits.
  - Enrollment is CLI-only (`start_totp_enrollment` in `accounts.py`), pending secret valid for 10 minutes.
  - 10 one-time recovery codes hashed with Argon2id.
  - Counter tracking prevents replay attacks within the verification window.
- **Lockout & Throttling:**
  - `ProgressiveLockout` and `LoginThrottle` in `accounts.py` track failed attempts in process-local memory dictionaries (`_failures`, `_locked_until`).
  - Lockout stages: 1 minute after 5 failures, 5 minutes after 10, 15 minutes after 15+.
- **Account Recovery:**
  - Web endpoint `/api/auth/forgot-password` returns a generic message instructing the user to run `uv run chinescan web reset-password --email <email>` on the local machine.
  - The CLI issues a 32-byte URL-safe reset token valid for 15 minutes.
  - Password reset via `/api/auth/reset-password` accepts the token, updates the Argon2id hash in `operator.json`, rotates `auth_epoch`, and calls `sessions.revoke_all()`.

### 1.2 Gaps and Vulnerabilities for a Multi-User Platform

1. **Single-Credential Bottle Neck:**
   - There is no database table for user credentials or password hashes. The `users` table stores only `id`, `email_normalized`, `display_name`, `status`, `auth_epoch`, and timestamps.
   - Only the single account in `operator.json` can authenticate.
   - Web signup is disabled once `operator.json` exists (`signup_available: operator_status == "none"`).
2. **Volatile In-Memory Sessions:**
   - Any server restart, graceful reload, or crash destroys all sessions in `SessionStore`. All logged-in users are immediately logged out.
   - There is no persistent session store (e.g. SQLite `sessions` table).
3. **No Invitation or Multi-User Onboarding Flow:**
   - Organization administrators cannot invite new members by email.
   - `OrganizationService.add_member` requires an existing `target_user_id` in `users`. Because secondary users cannot register, new users can only be inserted via raw database access or tests.
4. **Process-Local Lockout Reset on Restart:**
   - Because `ProgressiveLockout` stores state in memory, an attacker can clear IP/email lockout by restarting the process or waiting for a service restart.
5. **CLI-Only TOTP Enrollment:**
   - Non-operator users have no way to access the server's CLI to enroll in TOTP, receive enrollment secrets, or retrieve recovery codes.
6. **Single-Operator Password Recovery:**
   - Password reset relies on reading and writing `operator.json` and requires local machine terminal access. There is no email transport, no invitation token mechanism, and no self-service password recovery for team members.

---

## 2. RBAC and Tenant Isolation

### 2.1 Current Implementation Baseline

Tenant modeling was introduced in Phase 1B (`chinescan/core/organizations.py`, `migrations/versions/0005_identity_organizations.py`):
- **Tenancy Hierarchy:**
  - `users` (Identity)
  - `organizations` (Top-level tenant boundary)
  - `organization_memberships` (User-to-Organization link with roles: `owner`, `admin`, `member`, `auditor`, `viewer`)
  - `clients` (Customer entities within an organization)
  - `engagements` (Assessment projects bound to an organization and optional client)
  - `engagement_assignments` (User-to-Engagement link with roles: `lead`, `assessor`, `reviewer`, `observer`)
- **Role Permissions:**
  - `owner`: Full control, invite/promote admins, modify organization status, transfer ownership.
  - `admin`: Manage members (except owner/admin promotions), create clients, engagements, assignments, authorizations.
  - `member` / `assessor`: Read engagements, submit assessment jobs, view evidence and results.
  - `lead` / `reviewer`: Approve sensitive execution requests within assigned engagements.
  - `auditor` / `viewer` / `observer`: Read-only access to scoped engagements, audit logs, reports.
- **Tenant Context in Repository:**
  - `SQLiteRepository` uses a Python `ContextVar[str | None]` (`_organization_context`) managed via `@contextmanager organization_context(org_id)`.
  - When set, queries against `records` append `_owned_record()`, which filters `record_ownership.organization_id == org_id`.

### 2.2 Gaps and Boundary Vulnerabilities

1. **Passive Tenant Isolation Bypass when Context is Unset:**
   - In `chinescan/core/storage/sqlite.py`:
     ```python
     def _owned_record(self) -> Any:
         organization_id = self._current_organization_id() or self.worker_organization_id
         if organization_id is None:
             return None
     ```
     If repository methods (`get`, `page_records`, `list_records`) are invoked outside an active `organization_context` block, `_owned_record()` returns `None`. The query skips tenant filtering entirely and returns records across all organizations.
   - This "fail-open" default in repository queries is dangerous if an API route fails to set `organization_context`.
2. **Dual-Track API Route Isolation:**
   - In `chinescan/web/app.py`:
     ```python
     if (path.startswith("/api/") and ... and not (organization_api or identity_api or public_auth_api)):
         if not organization_service.operator_user_id or session.user_id != organization_service.operator_user_id:
             return 403 "Local operator access required."
     ```
     Any route that is NOT `organization_api` (such as `/api/scans`, `/api/cases`, `/api/findings`, `/api/reports`) requires that the caller be the local operator, and restricts access to the operator's personal organization (`personal_id`).
   - Consequently, non-operator organization members cannot access the standard scan, finding, case, or reporting APIs even if they are members of the organization that owns those records.
3. **Missing Organization Context in Organization API Routes:**
   - The middleware in `app.py` sets `with repository.organization_context(org_id):` only for routes *outside* `organization_api`.
   - The routes *inside* `organization_api` rely on explicit `organization_id` checks in `OrganizationService` and `EngagementSecurityService`. While their own SQL tables are safely filtered, any call made from those services to the underlying `repository` does not have `_organization_context` set.
4. **No True Multi-Tenant User Directory:**
   - Adding a member requires knowing their exact UUID. There is no safe, privacy-preserving lookup by email, nor an invitation workflow that lets an invited user accept an invitation.

---

## 3. Job Orchestration

### 3.1 Current Implementation Baseline

Phase 1 established execution governance in `chinescan/core/execution_governance.py`:
- **Job Creation & Admission (`create_governed_job`):**
  - Admits jobs within an SQLite `BEGIN IMMEDIATE` transaction.
  - Checks per-organization active limit (`ACTIVE_JOB_LIMIT = 4`) and global active limit (`GLOBAL_ACTIVE_JOB_LIMIT = 16`).
  - Evaluates centralized policy: `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`.
  - For `REQUIRE_APPROVAL`, admits the job only if a valid, approved `approval_id` is supplied. The approval is bound to the job but **not consumed at admission**.
  - Creates an immutable `ExecutionContext` (version 1) including SHA-256 digests of scope revision, authorization document, and snapshot/evidence IDs.
  - Inserts into `execution_jobs` with `status = "queued"`.
- **Idempotency:**
  - Scoped to `(organization_id, engagement_id, requester_user_id, idempotency_key)`.
  - Re-submitting with matching parameters returns the existing job. Conflicting parameters reject the request with `ValueError`.
- **Worker Execution (`GovernedDomainWorker`):**
  - Runs in a single background thread (`_run`).
  - Pulls the oldest queued job: `select id from execution_jobs where status = 'queued' order by created_at limit 1`.
  - Claims job in `BEGIN IMMEDIATE`: transitions `queued` -> `claimed`.
  - Revalidates context and transitions `claimed` -> `running`.
  - Dispatches to registered adapter (`GovernedDomainProbe`, `GovernedRepositoryAssessment`, `GovernedLogAnalysis`, `GovernedChainImport`, `GovernedChainProvider`, `GovernedMalwareStaticTriage`).
- **Approval Consumption at Action Boundary:**
  - When the adapter reaches an external operation, it calls `control.revalidate()`, which triggers `ExecutionGovernanceService.authorize_external_action(...)`.
  - In a `BEGIN IMMEDIATE` transaction, it verifies policy, verifies that the approval has not expired or been tampered with, atomically marks the approval `consumed` in `approval_requests`, and updates `execution_jobs.approval_consumed_at`.
- **Cancellation:**
  - Persisted state: `cancellation_requested_at`, `cancellation_requested_by`, `cancellation_observed_at`.
  - If a job is `queued`, cancellation immediately transitions it to `cancelled`.
  - If `claimed` or `running`, it sets `cancellation_requested_at` and signals a local `threading.Event` in `_active_cancellations`.
  - The adapter checks `control.check_cancelled()` at checkpoints.
- **Interrupted Job Handling on Startup:**
  - When `worker.start()` is called, it queries `status in ('claimed', 'running')` and updates them to `status = 'failed'`, `error_code = 'WORKER_RESTARTED'`.

### 3.2 Gaps and Concurrency Limitations

1. **No Worker Leases or Heartbeats:**
   - `execution_jobs` table has no `worker_id`, `lease_expires_at`, or `heartbeat_at` columns.
   - If a worker thread crashes, encounters an unhandled OS signal, or deadlocks while the web server remains running, the job stays in `running` forever.
   - There is no automated stale-job reaper during runtime.
2. **Process-Local Cancellation State:**
   - Active cancellation events (`self._active_cancellations: dict[str, Event]`) are stored in an in-memory dictionary.
   - If execution were ever distributed or run in a separate worker process, signaling cancellation in the web process would never reach the worker thread via `Event.set()`. Only the polling `cancellation_check()` against the database would function.
3. **Single-Worker Concurrency Limit:**
   - `GovernedDomainWorker` processes jobs serially (`run_one()` processes one job from queue, waits for completion, then fetches next).
   - Although `ACTIVE_JOB_LIMIT` allows 4 active jobs per org, the worker thread can only execute 1 job at a time.
4. **No Standalone Worker Process:**
   - Workers are coupled directly to the FastAPI server lifespan. Running heavy code scans, log parsers, or malware triage in the web process threatens web request latency and memory limits.

---

## 4. Execution Resource Controls

### 4.1 Enforced Controls vs. Advisory Bounds

| Resource Control | Mechanism | Implementation | Status |
|---|---|---|---|
| **Job Timeout** | Wall-clock deadline | `job_deadline_seconds` (default: 300s) checked in scan loops | **Enforced (Coarse)**: Checked between file iterations, not by preemptive timer. |
| **Context Expiry** | TTL validation | `JOB_CONTEXT_TTL = 10m`; checked in `_validate_context` before execution | **Enforced**: Prevents executing stale queued jobs. |
| **Queue Concurrency** | DB row count | `ACTIVE_JOB_LIMIT = 4` (per-org), `GLOBAL_ACTIVE_JOB_LIMIT = 16` | **Enforced**: `BEGIN IMMEDIATE` prevents queue overflow. |
| **Code Scan Size** | Bounds checking | `max_files`, `max_total_bytes`, `max_file_bytes`, `max_depth` | **Enforced**: Skips files exceeding limits; records skipped counts. |
| **Log Decompression** | Extraction limit | `MAX_DECOMPRESSED_BYTES` checked during archive stream ingestion | **Enforced**: Prevents decompression bombs. |
| **Malware Quota** | Org storage quota | `malware_evidence_org_quota_bytes` (1 GB) checked before intake | **Enforced**: Rejects sample intake exceeding organization quota. |
| **Malware Sandbox** | Windows Job Object | CPU/memory limits in `JobObject` for managed sample execution | **Configured (Static Only)**: Malware analysis is static triage; execution is blocked by policy. |
| **CPU / RAM Limits** | None for Code/Log | No OS cgroup or JobObject applied to Python scanner or log parser | **Advisory / Unenforced**: Memory-intensive scans can exhaust server memory. |
| **Subprocess Output** | None | External tools (Trivy, Semgrep) mocked; real stdout/stderr uncapped | **Unenforced**: Need bounded stream readers for real external tools. |
| **Web Rate Limiting** | Token bucket | `InProcessRateLimiter` per IP/category | **Enforced (In-Memory)**: Resets on process restart. |

### 4.2 Gaps in Resource Controls

1. **Lack of Preemptive Job Execution Timeouts:**
   - The scanner checks `deadline` inside file loops. If a single file parser (e.g. Tree-sitter or regex) hangs or enters catastrophic backtracking, the thread hangs indefinitely because there is no preemptive OS-level or watchdog timer to interrupt it.
2. **Memory Leaks and Unbounded Allocations:**
   - There are no per-job memory limits. A massive log file or repository can allocate gigabytes of heap memory in the web process.
3. **No Filesystem Sandbox for Adapters:**
   - Repository assessment operates on snapshot directories on the host disk. While path traversal is prevented by normalized path resolution, there is no chroot, container, or read-only filesystem mount isolating adapter operations.

---

## 5. Evidence and Reporting

### 5.1 Current Implementation Baseline

- **Evidence Storage:**
  - Code repositories: Managed tar.gz snapshots in snapshot store, tracked in `repository_snapshots` and `repository_asset_bindings`.
  - Log evidence: Ingested file/archive records in `log_evidence_snapshots`.
  - Malware samples: Operator-managed intake directory, tracked in `malware_evidence_snapshots`.
  - Results and findings: Normalized JSON payloads in SQLite `records` table (`scan`, `finding`, `evidence`, `case`).
- **Provenance Tracking:**
  - `execution_result_provenance` table stores `(record_type, record_id, job_id, organization_id, engagement_id, created_at)`.
  - `SQLiteRepository._link_execution_result` automatically logs every newly created record during an active `execution_provenance_context`.
- **Reporting:**
  - Report formats: `json`, `full-json`, `markdown`, `html`, `csv`, `sarif`, `share-summary`.
  - Size protections: Max 10,000 findings, max 20 MB export size enforced in `app.py`.
  - Redaction: Finding evidence and file paths are redacted according to active secret patterns (`redact_finding_payload`).

### 5.2 Gaps and Boundary Vulnerabilities

1. **Reports Route Single-Operator Restriction:**
   - `/api/cases/{case_id}/report/{format}` and `/api/scans/{scan_id}/report/{format}` are currently under the legacy operator check. Non-operator organization members cannot download reports generated from their own engagement assessments.
2. **No Data Retention or Expiration Lifecycle:**
   - Scans, findings, and evidence snapshots accumulate indefinitely in SQLite and disk storage. There is no configurable retention policy (e.g. 90-day retention, automatic archiving, or operator purge).
3. **Cross-Tenant Report Download Protection:**
   - While `scan_data` fetches scans from `records`, if `_organization_context` is unset, an authenticated caller knowing another organization's `scan_id` could theoretically generate a report for it.

---

## 6. Frontend Platform

### 6.1 Current Implementation Baseline

The frontend is a Vite + React + TypeScript single-page application (`frontend/src/`):
- **Core Shell (`App.tsx`):**
  - Session verification via `/api/auth/session` on mount.
  - Sidebar navigation with glassmorphism UI theme.
  - Sections: `Overview`, `Organizations`, `Projects`, `Code assessments`, `Log analysis`, `Malware triage`, `On-chain tracing`, `Scans`, `Findings`, `Cases`, `Modules`, `System status`.
- **Phase 1 Engagement Workspaces:**
  - `OrganizationsWorkspace.tsx`: Select organization, view/create clients, engagements, members, and assignments.
  - `EngagementSecurityWorkspace.tsx`: Manage assets, scope revisions, authorizations, sensitive approvals, policy checks, and view governed domain execution jobs with provenance. Polling timer runs every 1.5s for active jobs.
  - `EngagementLogEvidenceWorkspace.tsx`: Register log evidence snapshots, trigger governed log analysis.
  - `RepositoryAssessmentWorkspace.tsx`: Register repository snapshots, attestations, bindings, and trigger governed code assessments.

### 6.2 Gaps and Inconsistencies

1. **Split-Brain Workspace Experience:**
   - The user sees `Projects`, `Code assessments`, `Log analysis`, and `Malware triage` in the main sidebar. These legacy workspaces point to local folders on the host machine and are bound exclusively to the operator's personal organization.
   - The *governed* Phase 1 multi-tenant engagement functionality is buried inside `Organizations` -> Select Organization -> Select Engagement -> Security Controls.
   - An organization member who is not the server operator cannot use the sidebar items at all.
2. **Missing UI for Governed Malware & Governed Chain Trace:**
   - Backend APIs exist for `malware_evidence` and `chain_trace` governed executions, but there are no frontend components mounted in `OrganizationsWorkspace` to manage governed malware samples or submit governed chain-tracing jobs.
3. **Manual UUID Copy-Pasting:**
   - In `OrganizationsWorkspace.tsx`, adding a member requires typing or pasting a 36-character `user_id` string into an `<input>` field. There is no user selection, search, or invitation modal.
4. **No Real-Time Push (WebSocket / SSE):**
   - Active jobs poll every 1,500ms via `Promise.all` across all active jobs. This creates unnecessary HTTP overhead and latency.
5. **No Role-Aware Navigation Filtering:**
   - The UI does not hide or adapt navigation links based on the user's role in the current organization (e.g. an `auditor` or `viewer` sees the same action buttons, which then fail with 403 on submit).

---

## 7. Deployment and Operational Readiness

### 7.1 Current Implementation Baseline

- **Database:** SQLite 3 with WAL mode and `PRAGMA foreign_keys=ON`.
- **Database Concurrency:** Multi-threaded access within a single Python process protected by `threading.RLock()` (`db_lock`) and `BEGIN IMMEDIATE` transaction clauses.
- **Network Boundary:** Server binds strictly to loopback (`127.0.0.1` / `localhost`). Middleware explicitly rejects requests with external `Host` or non-loopback client IPs.
- **Migrations:** Alembic manages migrations. `SQLiteRepository._migrate` checks revision against head and runs `upgrade head` automatically on startup.
- **Diagnostics:** `/api/ready` and `/api/diagnostics` execute diagnostic checks across config, credentials, database, directories, and frontend assets.

### 7.2 Operational Limitations and Invariants

1. **Strictly Single-Instance Architecture:**
   - SQLite does not support distributed multi-host access. Network filesystems (NFS, SMB) with SQLite cause database lock corruption and concurrency failures.
   - ChineScan must remain a single-instance, single-host deployment.
2. **Process Coupling:**
   - Because workers run inside the web server process, heavy analysis jobs can starve the FastAPI event loop or block worker threads.
   - A standalone worker CLI command (`chinescan worker`) is required to allow running the worker in a separate background OS process pointing to the same SQLite database file using `BEGIN IMMEDIATE` locks.
3. **In-Process State Persistence:**
   - Sessions, lockouts, rate limiters, and cancellation events must be migrated to durable database tables to survive server restarts.

---

## 8. Summary of Findings

| Category | Working Well (Phase 1 Foundation) | Incomplete / Gaps (Phase 2 Focus) | Critical Risk |
|---|---|---|---|
| **Auth & Identity** | Argon2id password hashing, RFC 6238 TOTP, constant-time comparisons, clean identity tables in DB. | Single `operator.json` file, in-memory `SessionStore`, no database credentials table, no invitation onboarding. | Complete session loss on restart; inability for secondary users to authenticate. |
| **RBAC & Isolation** | Granular roles (`owner`..`viewer`), assignments (`lead`..`observer`), record ownership table, audit ledger. | Fail-open `_owned_record()` if context is unset; legacy routes locked to personal org; manual UUID member addition. | Potential cross-tenant record leakage if `organization_context` is omitted. |
| **Job Orchestration** | Immutable `ExecutionContext`, SHA-256 digests, atomic approval consumption at action boundary, audit trail. | No worker leases or heartbeats, in-memory cancellation events, serial worker processing, no stale job reaper. | Jobs remain permanently stuck in `running` if a worker thread hangs or crashes. |
| **Resource Controls** | Bounded scan limits (`ScanBounds`), decompression guards, queue size caps (4 per org, 16 global). | No preemptive per-job timeout, no CPU/memory caps for scanner/log threads, in-memory rate limiting. | Complex regex or hostile input can hang worker threads indefinitely. |
| **Evidence & Reports** | Strict provenance linking, format rendering, size caps, redaction of sensitive patterns. | Reports route locked to local operator; no retention or purging lifecycle; cross-tenant download risk if context unset. | Team members cannot access assessment reports for their engagements. |
| **Frontend** | Clean glassmorphism UI, comprehensive Phase 1 security workspace, scan/finding tables. | Split-brain between legacy workstation and engagement platform; missing governed malware/chain UI; 1.5s polling. | Poor usability; non-operator users locked out of major platform features. |
| **Deployment** | Automated Alembic migrations, diagnostic readiness endpoint, loopback security guard. | In-process worker thread competes with web requests; all background tasks die on web server restart. | Process restarts disrupt active analysis and lose all session state. |

---

## 9. Recommended Implementation Order

To address these gaps systematically without destabilizing working Phase 1 capabilities, Phase 2 should proceed in seven sequential, verifiable stages:

1. **Stage 2A: Architecture Audit & Strategy** (Current stage — Read-only baseline, deliverables in `docs/reports/`).
2. **Stage 2B: Multi-User Identity, Session Persistence & Invitation Onboarding**
   - Introduce database-backed user credentials and persistent sessions.
   - Implement secure tokenized email invitations and self-service password reset.
3. **Stage 2C: Durable Job Orchestration, Worker Leases & Interrupted Job Recovery**
   - Add worker leases (`worker_id`, `lease_expires_at`, `heartbeat_at`) to `execution_jobs`.
   - Implement atomic claiming, lease renewal, runtime stale-job reconciliation, and standalone worker runner.
4. **Stage 2D: Multi-Tenant RBAC Enforcement & Route Boundary Hardening**
   - Replace fail-open `_owned_record()` with strict fail-closed tenant scoping.
   - Unify API routes so organization members can access scans, findings, cases, and reports within their permitted engagements.
5. **Stage 2E: Resource Controls, Quota Management & Execution Supervision**
   - Implement watchdog execution timeouts, per-organization job quotas, and bounded subprocess streaming.
6. **Stage 2F: Unified Multi-Tenant Frontend Workspace & Real-Time Job Monitoring**
   - Unify the UI navigation around organization/engagement context.
   - Mount governed malware and chain trace workspaces; replace polling with SSE or robust status synchronization.
7. **Stage 2G: Platform Hardening, End-to-End Concurrency Testing & Acceptance Verification**
   - Full concurrency tests (multi-worker claiming, lease expiry, race conditions).
   - Acceptance verification against Phase 2 requirements.
