# Phase 6 acceptance report

Status: **PHASE 6 RELEASE BLOCKED**

This report records the currently implemented Phase 6 foundation and the
native Linux bootstrap added during the final implementation continuation. It
does not claim production isolation or deployment acceptance. The release
remains blocked until filesystem, delegated-resource, enforceable network, and
Windows host controls are provisioned and independently verified.

## Linux application-level acceptance

### Current gap matrix

| Area | Existing implementation | Remaining gap | Required evidence |
| --- | --- | --- | --- |
| Linux namespaces/seccomp | Actual worker bootstrap creates combined namespaces and installs the application filter | Native-host acceptance and bounding-set drop remain incomplete | Worker namespace IDs, `/proc` status, denied syscall probes, descendant checks |
| Linux cgroups v2 | Execution-scoped child creation code with CPU/memory/PID writes and cleanup | Explicit delegated subtree is unavailable on this host | Delegated root, controller files, worker membership, limit enforcement, cleanup after crash |
| Linux filesystem | Landlock integration with explicit roots and fail-closed startup | Current WSL2/Docker kernels expose no Landlock ABI; no equivalent private root is configured | Landlock ABI, denied read/write probes, child inheritance, cleanup |
| Linux networking | Actual deny-all network namespace path; application destination validation | Approved egress, DNS, IPv4/IPv6, redirect/proxy and firewall policy | Direct TCP/UDP, DNS, IPv4/IPv6, child and bypass tests under deployment policy |
| Windows host isolation | Job Object lifecycle and resource limits | Restricted token, AppContainer, ACL and native network enforcement | Native Windows token/ACL/network/process-tree acceptance |
| Recovery/reconciliation | Durable attempts, uncertainty state, authorized reconciliation | Full host/container crash and restart acceptance | Reproducible before/after state and audit evidence |
| Evidence lifecycle | Retention, holds, transaction-safe deletion, audit events | External stores/backups and restart/race acceptance | Hold-vs-delete race, interrupted deletion, restart, store-boundary evidence |

### Network policy architecture

`DENY_ALL` remains the default. The new `NetworkPolicy` contract binds approved
destinations to a scope revision, authorization ID, expiry, validated IPv4/IPv6
addresses, protocols, and ports. Private, loopback, link-local, multicast,
reserved, unspecified, and IPv4-mapped prohibited destinations are rejected.
`APPROVED_DESTINATIONS` is fail-closed unless
`CHINESCAN_NETWORK_POLICY_HELPER` points to a deployment-owned executable using
the documented policy-helper contract in `docs/DEPLOYMENT.md`. The helper must
install and verify the namespace/firewall/resolver boundary before `exec`; the
application does not claim host firewall enforcement without that helper.

### Environment

Acceptance was performed from Windows 11 using Kali GNU/Linux Rolling 2026.2
under WSL2 and Docker Desktop Linux Engine 29.9.3. Kali reported kernel
`6.18.58.1-microsoft-standard-WSL2`, `cgroup2fs`, controllers
`cpuset cpu io memory hugetlb pids rdma`, and `/usr/bin/unshare`. Docker used
cgroup v2 with the built-in seccomp profile. The ordinary WSL cgroup hierarchy
was root-owned and did not provide a delegated child cgroup to the application;
no host cgroup files or system policy were modified.

### Acceptance matrix

| Control | Supported | Available | Initialized | Enforced | Independently verified | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| POSIX CPU/address-space/process/file rlimits | Yes | Yes in Linux child | Yes | Yes | Yes | `run_supervised_subprocess` probe completed; application-managed profile applies rlimits |
| Process-tree supervision | Yes | Yes | Yes | Yes | Yes | Existing supervisor tests and worker lifecycle tests |
| User namespace | Kernel-dependent | Docker/WSL facility | Yes for native namespace profile | Yes for native namespace profile | Yes in strict Docker probe | Actual worker namespace ID differed from the Docker parent; worker `Uid: 999` |
| Mount namespace | Kernel-dependent | Docker/WSL facility | Yes for native namespace profile | Yes for native namespace profile | Yes in strict Docker probe | Actual worker was launched through `unshare --mount`; filesystem boundary is still separately unavailable |
| PID namespace | Kernel-dependent | Docker/WSL facility | Yes for native namespace profile | Yes for native namespace profile | Yes in strict Docker probe | Actual worker `NSpid: 1` and PID namespace ID differed from parent |
| Network namespace | Kernel/deployment-dependent | Docker/WSL facility | Yes for explicit deny-all namespace profile | Yes for deny-all profile | Yes in strict worker probe | Actual worker namespace differed from parent; direct TCP attempt returned `OSError`; approved allowlist is not installed |
| cgroups v2 CPU/memory/PID | Yes in Docker | Docker yes; WSL delegation unavailable | No in current environment | No by ChineScan | No | Execution-scoped cgroup code exists, but the worker cgroup root is not delegated/writable |
| Seccomp | Kernel/runtime-dependent | Native filter available in strict Docker probe | Yes | Yes for native seccomp profile | Yes in strict Docker probe | Worker showed `Seccomp: 2`, `Seccomp_filters: 2` from the ChineScan bootstrap with Docker seccomp unconfined |
| `no_new_privs` | Kernel/runtime-dependent | Strict Docker probe | Yes | Yes for native seccomp profile | Yes in strict Docker probe | Worker showed `NoNewPrivs: 1` |
| Capability reduction | Runtime-dependent | Effective/permitted sets available | Yes | Yes for effective/permitted/inheritable/ambient sets | Yes in strict Docker probe | All four sets were zero; `CapBnd` remains deployment-controlled and is not claimed as verified |
| Read-only filesystem | Deployment-dependent | Docker `--read-only`; Landlock unavailable in current kernels | No for governed profile | No by ChineScan | No | Landlock integration fails closed with `landlock_unavailable`; Docker read-only evidence remains deployment-only |
| Network egress policy | Deployment-dependent | Deny-all namespace available; approved policy unavailable | Yes for explicit deny-all profile | Yes for deny-all only | Yes for direct TCP denial | No approved IPv4/IPv6, DNS, redirect, proxy, or firewall allowlist is installed |

The probe was run with:

```text
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop=ALL \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 256m --cpus 0.5 \
  -v C:\\GitHub\\Chinescan:/src:ro -w /src --entrypoint python \
  chinescan:phase6-local scripts/phase6_linux_acceptance.py
```

The initial probe reported Docker-provided `Seccomp: 2`, `Seccomp_filters: 2`,
`NoNewPrivs: 1`, zero effective/bounding capabilities, Docker namespace IDs,
cgroup `0::/`, and a denied `/etc` write. Those values remain deployment-only
evidence. A subsequent strict probe exercised the actual ChineScan native
bootstrap with Docker's seccomp set to `unconfined`, so the observed seccomp,
no-new-privileges, namespace, and capability-set values are application-level
evidence. It did not prove cgroup delegation, a read-only filesystem boundary,
or approved egress enforcement.

The strict application probe used the same restricted container settings with
`--security-opt seccomp=unconfined`, `PYTHONPATH=/src`, and an
`IsolationProfile(linux_namespaces_required=True,
linux_seccomp_required=True)` passed to the actual
`run_supervised_subprocess` path. Observed from the child: `Uid: 999`, changed
user/mount/PID/UTS/IPC namespace identifiers, `NSpid: 1`, `NoNewPrivs: 1`,
`Seccomp: 2`, `Seccomp_filters: 2`, and zero `CapInh`, `CapPrm`, `CapEff`, and
`CapAmb`. `CapBnd` remains deployment-controlled and is not claimed as
verified.

An additional actual-worker probe requested namespace plus network isolation in
a Docker bridge network with Docker seccomp set to `unconfined`. The worker
reported a distinct network namespace and a direct TCP connection attempt
returned `OSError`. This demonstrates application network-namespace deny-all
behavior and child inheritance, but not an approved egress allowlist, DNS
policy, redirect policy, or firewall-backed destination policy.

The WSL namespace probe confirmed that a combined `unshare --user
--map-root-user --mount --pid --fork --mount-proc --net` path can create
namespaces in that shell. The current worker launcher now invokes the
corresponding combined namespace path for profiles that request it. The WSL
shell had no active seccomp filter, Landlock returned `ENOSYS`, and ordinary
cgroup delegation was not available.

## Implemented

- Added a platform-aware capability snapshot model. Hardened execution fails
  closed unless every required control is actually enforced; Linux namespace,
  cgroup, seccomp, and egress controls are not inferred from platform names.
- Added explicit execution transition validation, including an uncertainty
  state that cannot automatically return to queued execution.
- Added capability snapshots tied to an organization and optional job.
- Added organization-scoped retention policies, durable legal holds, hold
  associations, retention jobs, and retention audit events.
- Added a retention worker operation that checks active holds in the same write
  transaction immediately before deleting evidence. It removes provenance and
  local database ownership rows only after the organization check succeeds.
- Added authenticated organization-scoped API endpoints for capability status,
  retention policies, legal holds, release, retention jobs, and audit history.
- Added a React Phase 6 governance workspace showing only backend-reported
  enforced controls and providing authorized policy/hold actions.
- Added read-only deployment preflight at `scripts/phase6_preflight.py`.
- Declared the existing `defusedxml` runtime import as an explicit locked
  application dependency so the production container starts from a clean
  install.

### Enforcement boundary

The following are actually enforced in the current implementation: supervised
process-tree cleanup; POSIX CPU, address-space, process-count, open-file, and
file-size rlimits; and, for the native Linux profile, combined namespaces,
`no_new_privs`, the application seccomp filter, and effective/permitted/
inheritable/ambient capability clearing when the bootstrap succeeds. Windows
Job Object kill-on-close, CPU, memory, and active-process limits remain
enforced when native Job Object setup succeeds. Linux delegated cgroups,
Landlock filesystem isolation on the current kernels, approved network egress
filtering, and capability bounding-set reduction are not currently verified.
Windows
restricted tokens, AppContainer, filesystem ACL boundaries, and network
filtering likewise remain unavailable. Capability detection and deployment
preflight report these as unavailable; they do not report them as active.

## Verification evidence

### Historical results versus final reruns

| Historical result | Final disposition |
| --- | --- |
| `934 passed, 20 failed` | Resolved: recovery schema allowlist and migration-head assertions were updated for `0016_phase6_governance`; assertions were preserved. |
| Rust redaction stress timing failure | Superseded: delimiter scanning was made linear; Rust fmt, Clippy, and all 55 tests now pass. |
| Bandit unavailable in the earlier environment | Superseded: locked Bandit is installed and reports zero medium/high findings. |
| Stale-environment `dnspython`/`opentelemetry-api` audit findings | Superseded: locked `pip-audit --skip-editable` reports no known vulnerabilities. |
| Two dashboard failures in the first locked rerun | Environment-only: the selected environment lacked the optional native engine. Rebuilding/installing it made the focused tests and final full suite pass. |

### Executed versus unavailable checks

The Python, Rust, frontend, typing, formatting, Bandit, pip-audit, migration,
and local preflight commands listed below were executed. Gitleaks was not
installed on this host. Linux native namespace/seccomp bootstrap acceptance was
executed in the restricted Docker probe; delegated cgroup, filesystem-boundary,
approved-egress, Windows restricted-token/AppContainer/ACL/network integration,
firewall deployment acceptance, browser acceptance, and managed-worker
deployment acceptance were not executed and are not represented as passing.
Windows Job Object managed-worker tests were executed separately and are listed
below.

| Check | Result |
| --- | --- |
| locked Python suite with CI-prescribed native engine (final after native bootstrap changes) | **954 passed, 5 deselected**, 387 warnings, 27m20s |
| `py -3.12 -m pytest tests/unit/test_phase6_governance.py -q` | 3 passed |
| `py -3.12 -m pytest tests/unit/test_phase6_governance.py tests/unit/test_migration.py tests/unit/test_recovery.py tests/unit/test_storage.py -q` | 31 passed |
| Phase 6 API route security regression | 1 passed; invalid organization paths return 404 rather than leaking errors |
| `npm run typecheck` | Passed |
| `npm run test` | **82 passed in 21 files** |
| `npm run build` and CSP check | Passed; Vite warning for existing large chunks |
| frontend final rerun (`npm test -- --reporter=dot`) | **82 passed in 21 files**; the earlier combined-run timing failure was not reproduced |
| `py -3.12 -m ruff check` on Phase 6 files | Passed |
| `ruff format --check` on Phase 6/recovery files | Passed after formatting two Phase 6-related files |
| `mypy --strict chinescan` | Passed; 133 source files |
| locked `pip-audit --skip-editable` | Passed; no known vulnerabilities |
| locked Bandit (`--severity-level medium`) | Passed; 0 medium/high issues |
| Gitleaks v8.30.1 via Docker, full working tree/history | Passed; 239 commits scanned, no leaks found |
| Alembic heads | One head: `0016_phase6_governance` |
| `py -3.12 scripts/phase6_preflight.py` | Read-only preflight; network and hardened readiness remain unverified |
| `scripts/phase6_linux_acceptance.py` in restricted Docker container | Executed actual `run_supervised_subprocess`; baseline Docker controls observed; network-required profile rejected closed |
| strict native Linux bootstrap probe in restricted Docker container | Passed: actual worker namespaces, seccomp, `no_new_privs`, and capability-set reduction observed; cgroup/filesystem/network gates remained unverified |
| Phase 5 + Phase 6 focused acceptance | **26 passed, 2 Linux-only tests unavailable on Windows** |
| network policy and recovery focused acceptance | **26 passed, 2 Linux-only tests unavailable**; policy validation/helper fail-closed behavior plus lease, fencing, uncertain-outcome, idempotency, backup/restore, and reconciliation tests |
| Rust fmt / Clippy (`-D warnings`) / tests | Passed; 55 tests, 0 failures |
| `docker build -f docker/Dockerfile -t chinescan:phase6-local .` | Passed |
| restricted container smoke (`--read-only --tmpfs /tmp --cap-drop=ALL --security-opt=no-new-privileges:true`) | `--help` and `version` passed after explicit `defusedxml` dependency fix |
| Windows managed-malware acceptance | 35 passed; native Job Object subset 3 passed |

## Gates and limitations

- Gate A: incomplete. The actual Linux bootstrap now enforces and verifies
  namespaces, seccomp, no-new-privileges, and capability-set reduction in a
  restricted Docker probe, but delegated cgroups, filesystem isolation, and
  approved egress remain unavailable or unverified. Required profiles fail
  closed rather than falling back to rlimits-only execution.
- Gate B: incomplete. Windows capability reporting is platform-specific and
  does not claim Linux equivalence. Supervised subprocesses now receive
  verified Job Object kill-on-close, CPU, memory, and process-count limits,
  but restricted tokens, AppContainer, filesystem ACL, and network enforcement
  remain unavailable and no Windows deployment acceptance run was performed.
- Gate C: incomplete. Application destination validation remains distinct from
  enforceable firewall/network-namespace policy; no network policy is claimed.
- Gate D: partially implemented. Existing Phase 5 action attempts and
  reconciliation are preserved; Phase 6 adds transition validation, but a full
  crash/restart acceptance run remains outstanding.
- Gate E: implemented for local SQLite evidence records and tested for active
  hold blocking, release, deletion, and tenant ownership. Backups, object
  stores, exports, caches, and external indexes are not physically erased by
  this service and must be governed by their own lifecycle controls.
- Gate F/G: incomplete until the full repository suite, platform CI, and real
  deployment verification have run.
- Full-repository Ruff is blocked only by the preserved untracked
  `scripts/make_cover.py` line exceeding the repository line length; Ruff passes
  on all Phase 6 and changed tracked files. The untracked file was not modified.

## Original full-suite failure disposition

The initial `934 passed, 20 failed` run failed because recovery schema validation
did not recognize the Phase 6 tables and several tests still asserted the old
`0015_durable_job_leases_actions` migration head. The recovery allowlist now
recognizes `0016_phase6_governance`; migration/backup/restore assertions now
expect the single valid Phase 6 head. The continuation full run passed 954 tests.
The first locked rerun without the optional native engine in the selected
virtual environment produced two environment-only dashboard failures; after
rebuilding/installing the Rust extension, the full suite passed without changing
assertions.

## Additional tool results

- `py -3.12 -m mypy --strict` for the Phase 6 backend/API: passed.
- Ruff checks for Phase 6 backend, migration, preflight, and tests: passed.
- Strict API route security check passed after adding the Phase 6 routes; invalid
  tenant paths are handled as not-found responses.
- Capability records now expose explicit `initialized` and `verified` flags;
  unverified platform/runtime availability is not promoted to enforcement.
- The Rust timing failure was traced to repeated suffix searches in assignment
  redaction. The implementation now scans delimiter bytes linearly; the stress
  test passes repeatedly and the complete Rust suite passes.
- Bandit is available in the locked development environment and reports no
  medium/high findings.
- The locked pip-audit environment reports no known vulnerabilities. The
  earlier `dnspython`/`opentelemetry-api` findings came from a stale, non-locked
  environment and are not present in the locked dependency set.
- Gitleaks local binary is not installed, but the CI-pinned Docker execution
  scanned 239 commits and the full working tree with no leaks found.
- Linux cgroup/approved-egress integration, native Windows
  restricted-token/AppContainer/network integration, deployment-level firewall
  enforcement, browser acceptance, and Windows managed malware-worker
  deployment acceptance remain unverified. The local image build and restricted
  CLI smoke acceptance are verified separately above.
- The container build and restricted smoke test are now verified locally, but
  this is not evidence of scanner namespace, seccomp, cgroup, or egress
  enforcement; the container image currently starts the CLI only under the
  documented non-root/read-only restrictions.

No pull request, commit, merge, or production-readiness claim is made by this
working tree. The implementation is on `release/phase-6` and remains subject
to review.

## Final continuation status

**IMPLEMENTATION PARTIALLY COMPLETE — SPECIFIC BLOCKERS REMAIN**

The actual Linux worker bootstrap now provides demonstrated namespaces,
seccomp, no-new-privileges, and capability-set reduction in the tested Docker
execution path. Release remains blocked by execution-scoped filesystem
isolation, delegated cgroup enforcement, approved OS/deployment-level network
egress, and native Windows restricted-token, ACL, AppContainer, and network
acceptance. These controls require implementation and/or native host and
deployment verification before general Phase 6 review.

## PostgreSQL/Supabase continuation (local only)

This continuation added a PostgreSQL-compatible adapter without changing the
SQLite default. `CHINESCAN_DATABASE_URL` selects `PostgresRepository`; the
adapter requires the reviewed baseline at Alembic revision
`0016_phase6_governance`, uses psycopg 3 with pre-ping/pooling, binds the
existing authenticated organization context to transaction-local PostgreSQL
settings, and fails closed on a missing or unreviewed schema. It never
automigrates a deployment database.

The local baseline is
`supabase/migrations/20261127000000_chinescan_baseline.sql`. It contains the
current SQLAlchemy metadata tables, indexes, foreign keys, browser-deny
posture, organization membership helper functions, organization policies, and
PostgreSQL translations of the historical SQLite guards for published scopes,
execution and action-attempt context/state, result provenance, repository and
evidence metadata, and append-only audit events.

The policy SQL is designed for the existing custom session model: the backend
must set `SET LOCAL chinescan.user_id` and
`SET LOCAL chinescan.organization_id` only after existing session and
membership authorization succeeds. Browser roles retain no application-table
grants. This is a local implementation and static review, not proof of live
Supabase behavior.

### PostgreSQL checks executed

| Check | Result |
| --- | --- |
| PostgreSQL adapter/config/integration tests | **13 passed, 1 skipped**; the integration test skipped because no `CHINESCAN_TEST_POSTGRES_URL` was configured and psycopg is not installed in the current interpreter |
| Ruff on PostgreSQL adapter/tests | Passed |
| Strict mypy on PostgreSQL adapter | Passed |
| `py -3.12 -m uv lock --check` | Passed; no dependency installation performed |
| `git diff --check` | Passed |
| Full Python suite after this continuation | **966 passed, 3 skipped, 5 deselected, 407 warnings**; no failures |

### Not yet verified

The current Windows control host has no usable local PostgreSQL server and no
installed psycopg runtime, and Docker Engine was not available for a disposable
database run. Therefore the 40-table baseline has not been applied to a live
PostgreSQL instance, RLS policies and PL/pgSQL triggers have not been executed,
PostgreSQL transaction/lease recovery has not been concurrency-tested, and no
Supabase remote project was accessed. These are acceptance blockers, not passed
checks.

### Storage and data migration boundary

The existing log and malware evidence stores are local content-addressed
managed directories; no evidence files were migrated to Supabase Storage. A
future private object adapter must verify object key, size, digest, and manifest
after upload, keep deletion/legal-hold decisions in the governed database,
support interrupted upload/delete recovery, and preserve the local backup
boundary. The documented SQLite-to-PostgreSQL plan requires a verified stopped
application backup, foreign-key-ordered export, count/constraint/state
validation in a disposable PostgreSQL database, and rollback by switching the
backend back to the untouched SQLite backup. Two writable databases are not
supported.

## Updated acceptance decision

**RELEASE BLOCKED — REQUIRED CONTROLS OR EVIDENCE MISSING**

The local adapter and migration foundation are implemented and the full Python
regression suite is green, but PostgreSQL execution/RLS acceptance is not yet
demonstrated. Existing Phase 6 blockers also remain: native Linux delegated
cgroups/Landlock/approved-egress deployment evidence and native Windows
restricted-token/AppContainer/ACL/network acceptance. No live Supabase,
Oracle, or Vercel deployment was modified.

## Public deployment preparation

The ordinary public-deployment path now has local configuration support for a
loopback Oracle systemd service, nginx TLS forwarding, and backend environment
variables under `deploy/oracle/`. The backend also has a narrowly opt-in
trusted-proxy mode. Its regression test accepted an allowlisted forwarded
HTTPS origin and rejected an unlisted origin; Ruff and strict mypy passed.
Scanner execution remains guarded and no scanner capability was enabled.

No Supabase migration was applied, no Oracle service was deployed, and no
Vercel project was configured or tested. The remaining external prerequisites
are an authorized Supabase database connection and migration acceptance, an
Oracle deployment identity with permission to install the service/reverse
proxy and configure host firewall/TLS, and a Vercel project plus final
frontend/API hostname. These are deployment blockers, not local code failures.

### Remote deployment inspection

Read-only Vercel CLI inspection succeeded under the existing account, but the
only visible project, `chinetpulse`, is linked to the separate
`ChiNetpulse/Chinetpulse` repository with a SvelteKit `web` root. It is not a
safe deployment target for this repository's Vite frontend. Supabase CLI is
not installed, and the current SSH configuration does not provide a usable
Oracle username or identity for the supplied VM. No remote migration,
deployment, or infrastructure mutation was attempted.

## Final pre-merge review

The standalone Supabase package is:

- `supabase/migrations/20261127000000_chinescan_baseline.sql` — complete
  transaction-wrapped baseline for the current 40-table metadata schema;
- `supabase/manual/README.md` — manual execution order, prerequisites, and
  recovery guidance;
- `supabase/manual/verify_chinescan.sql` — read-only post-migration checks
  with expected results.

The migration now pins `search_path` to `public` inside its transaction. The
Oracle bootstrap rejects missing users, missing templates, placeholder
environment or Nginx values, missing application environments, and missing
Nginx before enabling the service. No extensions or undocumented Supabase
commands are required.

The SQL is intentionally a new-project baseline rather than a reversible
upgrade. Existing objects cause the transaction to fail rather than being
silently overwritten. PostgreSQL execution, RLS, and trigger behavior remain
unverified until the SQL is run in the intended Supabase project.
