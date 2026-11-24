# Engagement assets and authorization policy

Phase 1C established organization-owned engagement assets, versioned scope, authorization metadata, private authorization-document storage, one-use human approvals, and a central policy decision service. Later Phase 1D and Phase 1E-D work added governed execution paths; those later capabilities do not change the historical Phase 1C boundary.

## Data lifecycle

- Assets are attached to one organization and optionally a client and engagement. Domains are IDNA-normalized, IP addresses use canonical forms, CIDR values require strict network notation, and URLs accept HTTP(S) without user information, query, fragment, or traversal paths. No DNS resolution occurs.
- A scope revision starts as a draft. Its rules snapshot the asset type and normalized target so later asset edits cannot change historical scope. Publishing records a distinct approver. SQLite triggers prevent editing or deleting published revisions and their rules. A new revision is required for changes.
- Include rules name permitted techniques. Matching exclusions override inclusions. When multiple inclusions match, the most-specific match determines the allowed technique set.
- Authorization metadata references the current published scope, lists allowed techniques, and has an effective/expiry window. Revocation is immediate. An engagement without a linked client cannot yet record authorization.
- The optional authorization document is stored as a private SQLite BLOB, limited to 10 MiB and supported content types. Authenticated users with engagement read access can retrieve it via the API; there is no public URL. The API returns a digest and `no-store` headers. Backups therefore contain document data and must remain protected.
- Sensitive actions require approval by a distinct active organization owner/admin or active engagement lead/reviewer. Requests bind requester, organization, engagement, canonical target, technique/class, scope revision, authorization, operation digest, and expiry. Admission binds an approved request to one execution job without consuming it; the partial unique index `uq_execution_job_approval_binding` prevents binding that approval to another job. `approval_consumed_at` remains NULL until the worker reaches the external-action boundary.

## Policy decision model

`POST /api/organizations/{organization_id}/engagements/{engagement_id}/policy/evaluate` returns `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`, with `reason_code` and a safe explanation. All policy evaluations require authenticated active membership, active organization, active engagement and active lead/assessor assignment. Policy evaluation is read-only with respect to approval consumption. Requests that set `consume_approval` receive HTTP 409 (`approval_consumption_requires_execution`) and leave the approval unchanged. Only the governed worker's external-action control may consume a sensitive approval. Immediately before that operation, the worker revalidates policy and approval bindings and, in one SQLite `BEGIN IMMEDIATE` transaction, consumes the approval, records the execution job's `approval_consumed_at` marker, and writes the `execution.approval_consumed` audit event. The policy endpoint does not dispatch work.

Passive and controlled-active techniques still require current written authorization and matching scope. Sensitive classes additionally require approval. Technique identifiers are a small policy catalog, not scanner integrations.

## API and permissions

The engagement security API is mounted under `/api/organizations/{organization_id}/engagements/{engagement_id}`. Readers with engagement access may list assets, revisions, authorization metadata, approvals, and (owner/admin/auditor) audit records. Organization owners/admins and engagement leads manage assets, draft scope, authorization metadata/documents, and revocations. A distinct owner/admin or lead/reviewer publishes a scope revision and decides approvals. Backend checks are authoritative; requests that cannot be authorized fail closed with not-found behavior for inaccessible resources. Mutations retain session CSRF checks.

Endpoints cover assets (`GET/POST /assets`, `GET/PATCH /assets/{asset_id}`); scope revisions (`GET/POST /scope/revisions`, `GET /scope/revisions/{revision_id}`, `POST .../publish`); authorization metadata and private documents (`GET/POST /authorizations`, `POST .../{authorization_id}/revoke`, `PUT/GET .../{authorization_id}/document`); approvals (`GET/POST /approvals`, `GET /approvals/{approval_id}`, `POST .../{approval_id}/decision`); policy evaluation (`POST /policy/evaluate`); and audit history (`GET /audit`).

## Migration, backup, and recovery

Alembic revision `0006_engagement_scope_policy` follows `0005_identity_organizations`. It is additive and does not touch existing generic records. The root `alembic.ini` contains a default database URL, so never run the bare Alembic command during deployment preparation. First stop the local service and create a verified backup using ChineScan's supported backup command. Restore that backup into a disposable path, then construct an Alembic `Config` with that disposable absolute SQLite URL set explicitly before calling `command.upgrade(config, "head")`; verify the active URL in the command wrapper before running it. Confirm head `0006_engagement_scope_policy`, inspect table/foreign-key integrity, and run recovery verification on the disposable copy. Only after a verified backup and reviewed reconciliation should an operator schedule the same explicit-URL operation for the configured database. If upgrade fails, preserve the failed copy and restore the pre-upgrade backup; do not attempt to downgrade a database containing Phase 1C data. The migration's downgrade intentionally refuses to drop populated Phase 1C tables. No production/configured database was migrated during development.

SQLite is the supported database. PostgreSQL behavior is untested and is not claimed. Private documents are included in database backups; backup confidentiality and retention controls remain operational responsibilities.

## Execution boundary and limitations

The current governed paths distinguish operation classes:

- `chain_provider_lookup` is sensitive. The worker invokes `ExecutionControl.authorize_external_action()` through the governed chain provider adapter's pre-request callback. It revalidates policy and the operation/approval bindings immediately before the fixed provider request, then consumes the one-use approval at that boundary.
- `http_probe` / domain posture is controlled-active. It revalidates authorization and scope at the action boundary but does not require individual human approval.
- Repository code assessment, log evidence analysis, malware static triage, and local chain-trace import are passive local operations and do not perform external network actions.

A sensitive job that never reaches its action boundary cannot complete successfully; cancellation or failure before that boundary leaves the approval unused. Once consumed, the approval remains consumed even if the subsequent provider operation fails. These transaction guarantees apply to the current SQLite execution model; distributed or multi-worker concurrency has not been established. See [Phase 1D execution governance](EXECUTION-GOVERNANCE.md) and [governed chain trace](GOVERNED-CHAIN-TRACE.md).

These integrations do not govern every scanner or CLI path, and they do not establish commercial execution readiness, multi-user production readiness, PostgreSQL support, or distributed-worker support. ARTEX remains health/status-only.

The engagement workspace exposes asset, scope, authorization metadata, approval, and policy records through connected APIs. Document upload is available via the API but not yet presented as a browser upload form. Governed execution interfaces exist for the implemented workflows; this does not imply that all assessment engines are governed.
