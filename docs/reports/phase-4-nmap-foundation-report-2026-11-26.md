# Phase 4 — Nmap execution foundation (implementation report)

Status: implemented and merged to `main` via PR #39 (`a82a9762460990364db7cd94ebf8e7bfb9956584`).

## Scope

This change adds a disabled-by-default, governed Nmap adapter. It uses the
existing engagement policy, immutable scope revision, execution governance,
worker lease/action lifecycle, repository ownership, provenance, and audit
boundaries. It does not add a second job or authorization system and does not
enable ARTEX execution.

## Implemented controls

- Only registered `ip` and bounded `cidr` assets are accepted. Hostname targets
  remain explicitly unsupported until a reviewed resolver can bind all DNS
  answers to the approved scope immediately before execution.
- Three fixed profiles are centrally defined: host discovery, basic TCP port
  assessment, and light service identification. Caller-supplied flags, NSE
  scripts, output paths, unrestricted timing, UDP/aggressive modes, and shell
  syntax are rejected.
- Arguments are constructed as an argv list and executed with `shell=False`.
  Nmap XML stdout is drained through a bounded pipe and the process is
  terminated on overflow; stderr is discarded to avoid leaking host/process
  details.
- Profile/port parameters are stored in the immutable execution context and
  request digest. Worker revalidation checks the digest, adapter identity,
  canonical target, and normalized parameters before dispatch.
- Results are bounded and parsed with XML entity/DOCTYPE rejection, strict IP
  address validation, host/port limits, and bounded service metadata. Results
  are stored as tenant-owned `evidence` records (`evidence_type=nmap_result`)
  and linked to the normal `scan` and execution provenance records.
- Authenticated organization/engagement routes expose fixed profiles, submit
  governed jobs, and retrieve tenant-scoped results. Integration status exposes
  only non-sensitive readiness metadata.

## Intentional limitations

- Nmap must already be installed; runtime download/install is not supported.
- Host firewall/container/service-account egress restrictions remain deployment
  controls. The SQLite single-instance foundation does not claim a complete OS
  sandbox or arbitrary network namespace isolation.
- Exactly-once external execution is not claimed. Existing uncertain-outcome
  and reconciliation semantics remain authoritative.
- Nmap output is reconnaissance evidence, not vulnerability confirmation.
- This foundation exposes authenticated API/status surfaces; a dedicated React
  scan-request/results workspace is deferred until the API contract is reviewed
  with the dashboard workflow.

## Verification

Focused Nmap tests (10 passed), the neighboring authorization/adapter/durable
job selection (133 passed), and the local full Python suite (936 passed, 5
deselected) passed before release. The merged CI quality run passed with 930
passed, 10 skipped, and 5 deselected; it reported 79.89% coverage against the
configured 80% threshold, while Ruff, strict mypy, pip-audit, and Bandit all
passed. Frontend tests (81), TypeScript, production build/CSP, Rust checks,
Alembic single-head, container scanning, and secret scanning passed in CI.
The post-merge `main` CI run `45786186459` completed successfully. The
coverage diagnostic remains a quality follow-up; it did not fail the workflow.
