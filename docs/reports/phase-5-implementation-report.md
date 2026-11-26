# Phase 5 implementation report

## Scope

This release branch implements the Phase 5 execution-infrastructure foundation:
fail-closed scanner isolation, centralized scanner resource ceilings, common
tenant-bound evidence ingestion, governed Nuclei support, and an authenticated
scanner readiness workspace. Existing Phase 1–4 authorization, durable execution,
approval, and ARTEX behavior were preserved.

## Changes

* `chinescan/core/execution_isolation.py` detects platform capability and applies
  POSIX resource limits. Hardened requests fail closed on unsupported Windows
  hosts.
* `chinescan/core/subprocess_supervision.py` accepts the isolation profile while
  retaining bounded output, deadlines, cancellation, and process-tree cleanup.
* `chinescan/core/resource_governance.py` and settings add administrative CPU,
  memory, process, open-file, and temporary-output ceilings.
* Nmap uses the common isolation boundary when hardened mode is enabled and emits
  bounded telemetry.
* `chinescan/integrations/nuclei/` provides fixed-profile, approved-template,
  no-shell execution and bounded JSONL parsing. Nuclei is disabled by default.
* `EvidenceIngestionService` canonicalizes, hashes, tenant-scopes, provenance-binds,
  and idempotently persists normalized scanner evidence with a retention deadline.
* The governed adapter registry and job context support `vulnerability_scan`
  without creating a parallel job system.
* Authenticated Nuclei routes and the reusable engagement scanner workspace expose
  readiness and governed status only.

## Verification performed

Focused Python tests cover platform fail-closed isolation, Nmap compatibility,
Nuclei profile and parser bounds, template digest verification, evidence
idempotency/collision handling, and resource governance. Existing Nmap and Phase 2E
regressions pass. The final focused run passed 7 tests. Frontend type checking,
production build, strict CSP, and the full frontend suite pass: 21 files / 82
tests, including the scanner workspace render test.

The full backend suite passed 946 tests with 5 deselected in the final-state run
after the isolation/readiness tightening. A subsequent adapter preflight and
status-regression correction was verified by the focused Nmap/Nuclei selection;
the full-suite result remains valid for the shared infrastructure and the focused
selection covers those final localized edits.

The local full suite does not replace release CI. This Windows host cannot verify
POSIX hard limits, network namespaces, seccomp, or deployment-level egress
filtering.

## Security limitations

The implementation does not claim exactly-once external execution, a container
sandbox, hostname-target support, automated evidence deletion/legal holds, or
distributed worker isolation. ARTEX remains health-only and disabled by default.

* **Deployment-managed network isolation:** `network_isolation` is always reported
  as `False` by the application; hardened profiles requiring network isolation
  fail closed unless externally provisioned network namespaces and egress
  firewalls satisfy deployment policy.
* **Windows host isolation:** Windows hosts report `platform_supported=False` and
  `hardened_supported=False`, failing closed for hardened scanner profiles while
  retaining `process_tree_cleanup` (Job Object / process-group termination).
* **Execution semantics:** External scanner jobs are durable, lease-governed, and
  reconcilable with idempotent `EvidenceIngestionService` persistence, not
  strictly exactly-once; uncertain outcomes remain non-terminal until reconciled.
* **Evidence retention & legal holds:** `EvidenceEnvelope.retention_until` records
  a 365-day default retention deadline; automated deletion and legal-hold
  workflows remain deferred to a later operational milestone and must be managed
  by administrators.
