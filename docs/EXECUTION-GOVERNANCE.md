# Phase 1D execution governance

## Implemented vertical slice

The first execution path routed through Phase 1C policy is the built-in domain posture assessment. An authenticated web session or an operator-authenticated CLI invocation submits an organization, engagement, and registered asset ID. The server loads the asset target from SQLite; a client cannot substitute a target. The policy service checks the active organization and engagement, current assignment, active engagement, latest published scope, technique permission, and current authorization before the job is persisted.

Only the built-in `service_fingerprint` technique and the bounded `light` domain profile are currently executable through this path. It performs DNS resolution followed by bounded HTTP(S) HEAD requests to resolved public IPs. It pins each connection to the resolved IP, sends no redirects, and revalidates policy before DNS and before every HTTP request. A denial marks the job blocked and stops further requests. No other scanner/provider is enabled by this API.

## Job transaction and lifecycle

Migration `0007_governed_execution_jobs` adds tenant-bound job rows, an immutable server-created execution-context snapshot, idempotency keys, queue indexes, and SQLite triggers for context immutability, legal state transitions, and retention. Migration `0008_execution_cancellation` adds cancellation request actor/time and worker-observation time. Migration `0009_execution_result_provenance` snapshots the applicable authorization-document SHA-256 and adds append-only links from a job to newly created generic scan, finding, evidence, artifact, or report records. The link write shares the record's SQLite transaction; database triggers reject changes and cross-job tenant mismatches. Job creation is serialized with `BEGIN IMMEDIATE`. An approved sensitive request binds its approval to one durable job without consuming it. The worker consumes that approval with the existing Phase 1C compare-and-set approval operation in a `BEGIN IMMEDIATE` transaction at the adapter's first external-action callback. A unique partial index prevents the same approval from being bound to multiple jobs. Policy preview, queue admission, claiming, and status reads do not consume approvals.

The current state flow is `queued → claimed → running → completed|failed|blocked|cancelled`. An authenticated cancellation request records its actor and timestamp. Queued jobs transition directly to cancelled; claimed/running jobs retain their state until the worker observes the durable request at a safe control checkpoint and transitions them to cancelled. Repeated pending requests are idempotent; terminal-job requests return a stable conflict. The worker also uses the existing process-local event for cooperative shutdown. Cancellation is not forced thread termination: arbitrary adapter code can only be stopped when it cooperates with the control checks. Queue limits are four active jobs per organization and sixteen globally. Idempotency keys prevent duplicate submissions when clients reuse a key. The worker is process-local and single-instance; it is not a distributed queue or multi-worker guarantee.

Workers re-resolve policy from current database state at claim, immediately before execution, before DNS, and before every HTTP request. They also verify that the asset is still active and unchanged, execution context has not expired, and scope/authorization still match. The job stores the adapter's structured result summary and scan/result identifier; generic record ownership is written under the per-job organization context. Adapter progress is recorded as append-only execution audit events.

## API, CLI, and frontend

- Web: `POST /api/organizations/{organization_id}/engagements/{engagement_id}/executions/domain` queues only an authorized registered domain asset. It uses the authenticated session and CSRF protection. `GET .../executions`, `GET .../executions/{job_id}`, and `GET .../executions/{job_id}/provenance` are tenant and engagement scoped. The provenance view returns the immutable job context, outcome/approval-consumption metadata, and linked record IDs without returning authorization document contents. `POST .../executions/{job_id}/cancel` permits the job requester or an organization owner/admin or assigned engagement lead, with active membership, and persists cancellation intent before signaling a local active worker.
- CLI: `chinescan domain` now requires explicit organization, engagement, and asset IDs, verifies the operator password and TOTP/recovery code when configured, checks the supplied hostname against the registered asset, and executes through the same governance service. Legacy ownership assertions and local authorization JSON do not authorize this external operation. The CLI currently supports only the light profile.
- CLI repository assessment: `chinescan code-engagement` takes organization, engagement, and repository asset IDs, authenticates the existing local operator, and admits the already-bound snapshot through the same policy and execution job service. It runs the existing repository adapter and worker synchronously in the CLI process, then returns the durable job status and result ID. It accepts no source path, scanner choice, or alternate target. Admission failure exits without invoking the standalone scanner.
- Frontend: the engagement workspace can start domain posture jobs for active domain assets, view job states and cancellation progress, request cancellation for eligible nonterminal jobs, and inspect the job context and linked scan/finding IDs. Current finding evidence is embedded in its generic finding record; there is not yet a separate governed evidence object or custody workflow.

The current web server is configured for one worker and loopback binding. The legacy `chinescan code <path>` workflow and `CodeJobManager` remain standalone local scans with no engagement authorization or governed provenance. The separate `chinescan code-engagement` command is the governed repository path. Log and static malware workflows remain local input analysis and do not execute against engagement assets. Chain trace may query an external public data provider under its existing explicit network option; it has no engagement binding and must not be treated as a commercial assessment workflow. No web or CLI commercial assessment capability is claimed for those other paths.

## Unsupported and deferred execution

## Governed local repository code assessment

Migration `0010_governed_repository_assets` adds a distinct `repository` engagement asset,
tenant-bound repository binding and attestation records, content-addressed snapshot metadata,
quota reservations, and immutable repository fields on governed execution jobs. A repository
asset target is the opaque `repo:<asset UUID>` value; API responses omit project roots,
registry paths, manifests, and private snapshot paths. Only projects already registered in the
local `ProjectService` are eligible. The API accepts the opaque project-registry ID, never a
path or remote URL, and the server resolves and revalidates the path against configured local
project rules.

Binding requires an active assigned engagement lead, a current published scope revision that
includes the exact repository asset for `repository_code_assessment`, and an active authorization
record whose permitted techniques include that code-assessment technique and whose dates are
current. The lead must submit the exact server-defined statement
`repository-code-authorization-v1`. The append-only attestation records the stable user,
organization, engagement, asset, authorization, scope revision, exact text, version, and time.
This records operator accountability; it is not independent proof of repository ownership or
legal permission. Changing the project binding is refused; changed scope or authorization
requires a new binding attestation.

Snapshots contain sorted UTF-8 relative paths, file sizes, and per-file SHA-256 digests in a
canonical versioned manifest. The snapshot digest hashes that canonical manifest. `.git`, nested
repositories, generated build/dependency directories, and common virtual-environment directories
are excluded by `repository-exclusions-v1`. Linked files/directories and reparse points are
rejected; source files are never executed, installed, or resolved online. Inventory and copy
enforce configured file-count/depth limits and the individual-byte limit. The built-in adapter
uses existing bounded `CodeScanService` rules and does not call `CodeJobManager`; both the web
repository workflow and `chinescan code-engagement` dispatch through the same governed worker. The
legacy standalone `chinescan code <path>` path is unchanged and is not represented as governed. The
adapter is classified
passive/local-only and does not perform external operations. It verifies snapshot content before
and after assessment and writes governed scan/finding records under immutable execution
provenance. Cancellation is cooperative at scanner checkpoints; already persisted partial results
remain linked to the job.

`repository_snapshot_max_bytes` defaults to 5 GiB and
`repository_snapshot_org_quota_bytes` defaults to 10 GiB. Both are validated settings. Quota
reservations serialize on SQLite `BEGIN IMMEDIATE`, and content with the same digest is counted
once. Failed creation removes its reservation and staging content; no automatic eviction occurs.
Engagements now record `closed_at` when completed or archived. Snapshot retention uses the latest
closure time among associated engagements plus 90 days; active engagements, nonterminal jobs,
and legal/investigation holds prevent explicit deletion. Cleanup is an audited, explicit operation,
not a side effect of ordinary requests. Deletion preserves snapshot metadata, hashes, execution
provenance, and audit events.

SQLite backup bundles now include referenced available snapshot content and the repository
metadata manifest. Verification detects missing/corrupt content, and restore publishes snapshot
content beside the destination database. Database-only copying is not a complete recoverable
assessment backup when repository snapshots are referenced. The configured database is not
automatically migrated by this feature. Snapshot files inherit the configured data directory's
operating-system protection; the application does not provision Windows ACLs, and POSIX mode bits
must not be treated as Windows ACL enforcement.

Repository assessment is limited to the first-party local rule scanner and one process-local
worker. Existing local CLI code scans and `CodeJobManager` remain separate and unchanged. This does
not establish distributed-worker, PostgreSQL, broad multi-user production, arbitrary-path, remote
Git, third-party scanner, or commercial execution readiness.

`chinescan.core.execution_adapters` defines a typed adapter contract, immutable `ExecutionContext`, explicit capability registry, structured result/failure types, progress reporting, cooperative cancellation, and worker-provided policy control. The registry now contains two built-in operational adapters: domain posture and local repository code assessment. Domain posture remains controlled-active and revalidates policy before DNS and each HTTP action. Repository code assessment is passive/local-only, accepts only a repository asset bound to a server-managed immutable snapshot, verifies its manifest and content digests, then reuses the bounded built-in code rules without calling `CodeJobManager`. Its immutable context binds the repository asset, binding, snapshot digest, manifest/exclusion versions, scanner identity, scan bounds, attestation, authorization, and published scope. This is an internal trusted-code boundary; Python protocols do not sandbox malicious or buggy adapter code, so adapters must be reviewed and must use the provided control before every external action.

The existing CLI code-scanning workflow and `CodeJobManager` remain local-input paths and are not redirected through the engagement adapter. The new repository adapter is a separate governed path that scans a managed snapshot, not a live source folder. Other code-analysis subprocess wrappers, log analysis, static malware triage, and chain-trace workflows remain outside engagement execution; chain trace may use its existing explicit network option. Administrative and reporting operations are not assessment adapters.

There is no governed sensitive/exploit adapter. Only the local repository code assessment and domain posture adapters are available as governed assessment paths; existing CLI scans, other code-analysis subprocess wrappers, log, malware, and chain-trace jobs remain outside them. The current execution API does not accept arbitrary targets, redirects, discovered hosts, scanner names, or techniques. A newly discovered host requires a separately registered asset and fresh policy evaluation; target expansion is not implemented. Adapter cancellation is cooperative: the repository adapter checks at scanner checkpoints and other adapters must call the control before each external action and at long-running checkpoints. Durable cancellation requests are observed by the process-local worker; they do not forcibly terminate arbitrary code and do not establish multi-worker cancellation delivery.

## Governed log evidence analysis

Migration `0011_governed_log_evidence` adds the `log_evidence` asset type, engagement-bound evidence snapshot metadata, expiring SQLite quota reservations, and immutable log snapshot fields on execution jobs. The web API accepts only configured source IDs; the governed CLI `log-evidence-register` accepts a local path only during registration and validates it against configured allowed roots. Both create an opaque `log:<asset UUID>` asset backed by a private content-addressed snapshot. Subsequent governed execution accepts only organization, engagement, and asset IDs; it never resolves or falls back to the original source path.

The snapshot manifest is sorted by UTF-8 relative path and records file size and SHA-256. Its digest is bound into the job along with the snapshot ID, format, manifest version, analysis version, and ruleset version. Links/reparse points, unsafe relative paths, unsupported files, excessive depth/count, and inputs over the existing 250 MB ingestion ceiling are rejected. The configurable `log_evidence_max_bytes` defaults to 250,000,000 bytes (bounded by the existing engine limit); `log_evidence_org_quota_bytes` defaults to 2,000,000,000 bytes. SQLite `BEGIN IMMEDIATE` serializes quota reservations. Identical content is deduplicated within an organization for quota accounting.

`builtin.governed-log-analysis` is passive and local-only. It verifies the managed snapshot before and after calling the existing bounded log-analysis engine, cooperatively checks cancellation during reads and parsing, and uses no network, enrichment, or execution of log content. Governed records are sanitized before generic persistence and linked to the durable execution job through the existing provenance context. The sanitizer redacts recognizable credential assignments, bearer values, high-entropy token-like values, email addresses, and absolute paths; this is best-effort pattern-based redaction and cannot guarantee removal of every sensitive value. Original evidence remains private and is not returned by ordinary result or job APIs.

Evidence remains retained until an authorized owner/admin explicitly deletes it after the engagement is completed or archived. This is a conservative no-automatic-deletion policy because no product retention schedule exists for log evidence. Active jobs and legal/investigation holds block deletion. Snapshot metadata and audit history are retained after content removal. Backups include referenced snapshot content; verification detects missing or corrupt evidence and restore never substitutes a live source. A database-only copy is not a complete evidence backup. Registration proves evidence custody within the application, not authorization to conduct the assessment; policy still requires valid engagement authorization and published scope. Log analysis is not a network asset assessment, and there is no special claim that evidence itself proves authorization.

The tenant-scoped API lists configured sources at `GET .../log-evidence/sources`; only stable source IDs and display names are returned. Sources with separately configured custom rule directories or IOC lists are rejected for governed registration until those inputs can be independently snapshotted and bound to the immutable job context. Built-in rules are used; the existing standalone workflow and its configured custom rules remain unchanged. The CLI commands are `log-evidence-register` and `log-engagement`; standalone `log` analysis and the process-local legacy log job manager remain separate and ungoverned. Governed admission failure does not fall back to standalone execution. The governed adapter does not consume approvals because its operation is passive/local-only. The worker remains process-local and single-instance; this does not establish distributed-worker, broad multi-user production, or commercial execution readiness.

Approval decision and atomic consumption continue to use the Phase 1C approval record and compare-and-set service. The execution worker validates requester, organization, engagement, target and asset type, technique, action class, request digest, published scope revision, authorization record, expiry, consumed state, and the approver's distinct identity and current review permission. Approval is consumed once at the first external-action boundary. Later actions in that same job revalidate the consumed approval and current policy without consuming it again. A failed or interrupted job does not restore a consumed approval; failure is recorded on the durable job and audit trail. If a sensitive adapter never reaches its action callback, the job is blocked and the approval remains approved and unused.

There is still no production sensitive operation or enabled sensitive adapter. The approval-required path is exercised by isolated test-only adapters; this validates the mechanism but does not make an exploit or other sensitive operation available. The built-in domain posture workflow remains `controlled_active` and does not consume approval. No existing CLI or worker pathway outside this governed domain posture job path is newly authorized by this mechanism.

ARTEX remains health/status-only. No assessment endpoint, result retrieval, or execution capability is inferred. A future ARTEX adapter must receive a server-created execution context and fresh policy decision before making any external request; no credentials, authorization documents, or unrelated tenant information may be forwarded.

## Operational constraints

SQLite remains the supported database. Migration `0010_governed_repository_assets` follows `0009_execution_result_provenance` and is additive. It adds the repository asset/binding/attestation/snapshot/quota schema, engagement closure timestamps, and repository-bound job context. Downgrade refuses to remove populated repository history. Backups include referenced available snapshot content; verification rejects missing or corrupt referenced content, and restore publishes the snapshot bundle beside the restored database. Do not migrate the configured database as part of development; production rollout requires a verified backup, a migration against an explicitly selected database, and post-migration recovery verification.

This is an initial single-instance enforcement slice, not multi-user production readiness or commercial production readiness. The single local operator authentication foundation, process-local sessions, process-local worker, and ungoverned public-data investigation paths remain deployment constraints.
