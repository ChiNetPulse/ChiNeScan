# Phase 5 execution infrastructure

Phase 5 adds a governed Nuclei adapter, strengthens the existing Nmap adapter, and
introduces common evidence ingestion. The implementation deliberately reuses the
Phase 2 durable job, lease, approval, provenance, and tenant repository boundaries.

## Execution isolation

Scanner subprocesses use `run_supervised_subprocess` with `shell=False`, bounded
stdout/stderr, deadlines, cancellation, and process-tree cleanup. Capability
reporting (`isolation_status()`) distinguishes between:

1. **Platform support** (`platform_supported`): whether the host is Linux POSIX.
2. **Runtime availability** (`runtime_available`): whether `resource.getrlimit`
   succeeds for `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`, and
   `RLIMIT_FSIZE`.
3. **Enforced vs. unavailable controls** (`enforced_controls`,
   `unavailable_controls`): explicitly lists which controls are active (e.g.,
   `process_tree_cleanup`, `posix_rlimits`) and which are unavailable (e.g.,
   `network_isolation`).

When hardened isolation is required (the default for Nmap and Nuclei), a Linux
POSIX worker verifies runtime `rlimit` availability and applies CPU,
address-space, process-count, open-file, and output-file limits before `exec`.
If any required isolation control (including deployment-managed network isolation
when `network_isolation_required=True`) is unavailable, `require_isolation()`
fails closed without falling back to weaker execution. On Windows, the hardened
POSIX profile fails closed; Windows Job Object / process-group cleanup is
reported as `process_tree_cleanup` only and is never represented as equivalent to
Linux `rlimit`, namespace, cgroup, or seccomp isolation.

Deployment prerequisites for Linux isolation remain the responsibility of the
deployment operator: network namespaces, seccomp profiles, container sandboxing,
and outbound egress firewalls must be provisioned externally and are never
inferred or claimed by the application status.

## Scanner adapters

Nmap remains disabled by default and supports only its existing fixed profiles and
IP/CIDR targets. Hostname expansion is intentionally unsupported until a resolver
can bind every resolved address to the immutable approved scope immediately before
execution.

Nuclei is disabled by default. The only profile is `safe_web_checks`; callers may
select approved template identifiers but cannot provide arbitrary flags, scripts,
output paths, timing controls, or targets. Every template file is resolved below
the administrator-selected directory and its SHA-256 digest must match the
administrator's approved digest before a process is started. JSONL output is
strictly bounded and normalized; malformed, oversized, or incomplete output is a
failed execution, never a successful finding set.

Both adapters are registered through the existing `AdapterRegistry` and execute
only from a persisted governed job. The job binds organization, engagement, asset,
immutable scope revision, authorization, operation parameters, adapter identity,
and request digest. The worker reconstructs its context from that record rather
than inheriting a web or local-operator principal.

## Evidence

`EvidenceIngestionService` canonicalizes normalized adapter results, computes a
SHA-256 digest, records parser/tool/version metadata, preserves the scope and
execution provenance, and uses a stable job-plus-digest identifier for idempotent
recovery. Evidence is written through the tenant-aware repository in the persisted
job's organization. A retention deadline is recorded in the envelope (365 days by
default); automated deletion and legal-hold workflows remain an operational
follow-up and must not be inferred from the metadata alone.

## Dashboard and API

The engagement workspace has a reusable scanner status surface. It displays
disabled, blocked, and ready states for Nmap and Nuclei, target-type restrictions,
profiles, and approved-template counts. It never treats visibility as permission:
execution is still admitted only by the authenticated API, membership and
assignment policy, immutable scope, approval, quota, and worker checks.

The authenticated endpoints are:

* `GET /api/integrations/nmap/status`
* `GET /api/integrations/nuclei/status`
* `GET /api/organizations/{organization_id}/engagements/{engagement_id}/nuclei/profiles`
* `POST /api/organizations/{organization_id}/engagements/{engagement_id}/nuclei/executions`
* `GET /api/organizations/{organization_id}/engagements/{engagement_id}/nuclei/executions/{job_id}/result`

## Limitations

No database migration is required: evidence remains a tenant-owned repository
record and execution binding remains in the existing job JSON context.

* **Deployment-managed network isolation:** The application cannot locally
  enforce network namespaces or egress firewalls (`network_isolation=False`).
  Hardened profiles requiring network isolation fail closed unless deployment
  controls satisfy the policy. Operators must provision network namespaces,
  seccomp, container boundaries, and egress filtering externally.
* **Windows isolation:** Windows hosts cannot enforce the POSIX `rlimit`
  hardened profile (`platform_supported=False`, `hardened_supported=False`).
  Enabled hardened scanner profiles fail closed on Windows; only
  `process_tree_cleanup` is supported.
* **No exactly-once execution guarantee:** External scanner invocations are
  at-least-once/reconcilable, not exactly-once. Durable job leases, execution
  state, idempotent `EvidenceIngestionService` persistence (job-plus-SHA256
  record IDs), and authorized reconciliation preserve integrity, and uncertain
  outcomes are never marked as successful or blindly retried.
* **Evidence retention and legal holds:** `EvidenceEnvelope` records a
  `retention_until` deadline (365 days by default; configurable 1–3650 days).
  Automated retention deletion and legal-hold workflows are not implemented in
  Phase 5; administrators remain responsible for retention enforcement and
  litigation/audit preservation.
