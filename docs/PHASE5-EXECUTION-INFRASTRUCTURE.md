# Phase 5 execution infrastructure

Phase 5 adds a governed Nuclei adapter, strengthens the existing Nmap adapter, and
introduces common evidence ingestion. The implementation deliberately reuses the
Phase 2 durable job, lease, approval, provenance, and tenant repository boundaries.

## Execution isolation

Scanner subprocesses use `run_supervised_subprocess` with `shell=False`, bounded
stdout/stderr, deadlines, cancellation, and process-tree cleanup. When hardened
isolation is required (the default for Nmap and Nuclei), a POSIX worker applies
CPU, address-space, process-count, open-file, and output-file limits before exec.
The readiness endpoint reports the host capability without exposing paths or
environment data. On Windows the hardened profile fails closed because this
application does not claim that Python limits are an equivalent sandbox. Network
namespace, seccomp, container, and egress policy enforcement remain deployment
responsibilities and are not implied by the application status.

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
record and execution binding remains in the existing job JSON context. The current
Windows host cannot prove the POSIX hardened profile, so enabled scanner instances
are correctly reported as not ready there. The application does not claim a
container sandbox, network egress firewall, exactly-once external execution, or
automatic evidence deletion. Those controls require deployment policy and a later
operational review.
