# Phase 5 implementation plan

This release extends the Phase 4 governed scanner foundation without adding a
second authorization or job system.

1. Add a fail-closed isolation policy and wire bounded CPU, memory, process,
   file, temporary-storage, timeout, and output controls into supervised scanner
   execution. Windows remains an explicitly unsupported hardened-worker host;
   Linux capability checks are reported rather than inferred.
2. Add a common evidence-ingestion service that canonicalizes payloads, records
   SHA-256 provenance, uses stable job-bound identifiers, and persists through
   the existing tenant-scoped repository.
3. Add a disabled-by-default Nuclei adapter with fixed profiles, approved
   template hashes, bounded JSONL parsing, and the existing governed execution
   lifecycle.
4. Expose non-sensitive scanner readiness/status through authenticated APIs and
   a reusable dashboard workspace.
5. Add regression tests, update deployment/security documentation, and run the
   complete Python, frontend, Rust, migration, lint, type, dependency, secret,
   and container checks.

No schema migration is planned: existing execution jobs and tenant-owned JSON
records can carry the additional immutable scanner and evidence metadata without
changing the SQLite migration chain.
