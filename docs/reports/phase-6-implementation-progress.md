# Phase 6 implementation progress

Branch: `release/phase-6`

## Completed before this continuation

- Phase 6 governance, migration `0016_phase6_governance`, authenticated API,
  dashboard, retention/legal holds, recovery, and audit history.
- POSIX rlimits and supervised process-tree cleanup.
- Windows Job Object kill-on-close, CPU, memory, and process-count controls.
- Capability reporting and deployment preflight with explicit fail-closed
  behavior.
- Locked dependency/security checks, Rust and frontend acceptance, container
  smoke acceptance, and Gitleaks evidence recorded in the acceptance report.

## This continuation

### PostgreSQL/Supabase local foundation

- Added an opt-in `PostgresRepository` selected by `CHINESCAN_DATABASE_URL`;
  SQLite remains the default and its recovery/backup behavior is unchanged.
- Added the reviewed 40-table PostgreSQL baseline at
  `supabase/migrations/20261127000000_chinescan_baseline.sql`. It records the
  existing Alembic revision, enables RLS, denies browser table access, and
  installs organization-member helpers plus PostgreSQL equivalents for the
  historical immutable, append-only, provenance, scope, and execution-state
  guards.
- The adapter binds the existing authenticated organization context to
  transaction-local `chinescan.user_id`, `chinescan.organization_id`, and
  `chinescan.write_access` settings. It refuses to start against a missing or
  unreviewed schema and never auto-migrates a deployment database.
- Added locked psycopg packaging, configuration validation, Docker build
  opt-in, baseline/RLS static tests, and a PostgreSQL integration test that
  runs when `CHINESCAN_TEST_POSTGRES_URL` is provided.
- Added a controlled SQLite-to-PostgreSQL cutover/rollback plan and documented
  that current evidence remains local content-addressed storage; no evidence
  migration or live object-storage change was performed.

### Public deployment preparation

- Added a narrowly opt-in trusted reverse-proxy origin path. It still requires
  loopback ingress, HTTPS forwarded protocol, an explicitly allowlisted
  frontend origin, and a matching forwarded host; direct public host access
  and unlisted origins remain rejected.
- Added Oracle deployment templates under `deploy/oracle/` for systemd,
  nginx/TLS forwarding, and backend environment configuration. These are not
  remote deployment evidence.
- Preserved fail-closed scanner availability. No scanner profile was enabled
  by this deployment preparation.
- Added `deploy/oracle/bootstrap.sh`, `scripts/oracle_healthcheck.sh`, and
  `scripts/vercel_production_check.ps1` for repeatable operator execution.
- Read-only Vercel inspection found an authenticated account, but the existing
  `chinetpulse` project is linked to a different GitHub repository and SvelteKit
  `web` root. It is not a safe target for this Vite frontend.
- Supabase CLI is not installed, and no usable Oracle SSH user/identity is
  configured in the current environment. No remote mutation was attempted.

- Added a Linux worker bootstrap used by `run_supervised_subprocess` for
  profiles requesting native namespaces or seccomp. The bootstrap applies
  `no_new_privs`, clears effective/permitted/inheritable capabilities, and
  installs a deny-list seccomp filter before `exec`.
- Added execution-scoped cgroup v2 creation and cleanup code, but the current
  WSL/Docker environment does not delegate a writable worker cgroup, so that
  path remains fail-closed and unverified.
- Added combined user/mount/PID/UTS/IPC namespace launch wiring, with network
  namespace support when requested. A strict Docker probe verified changed
  user/PID namespace IDs, `Uid: 999`, `NoNewPrivs: 1`, `Seccomp: 2`,
  `Seccomp_filters: 2`, and zero effective/permitted/inheritable/ambient
  capabilities in the actual ChineScan child.
- Integrated Landlock filesystem-boundary setup into the worker bootstrap for
  explicit read/write roots. The current Docker and WSL2 kernels report no
  Landlock ABI, so hardened filesystem startup rejects with
  `landlock_unavailable`.
- Hardened cgroup setup now requires an explicitly configured delegated
  subtree, rejects `/sys/fs/cgroup` itself, and verifies delegated CPU,
  memory, and PID controllers before creating an execution child.
- Filesystem-only Landlock setup now applies `no_new_privs` before restriction.
- Added portable unit coverage for bootstrap command construction and
  fail-closed behavior. Focused Phase 5/6 plus Linux tests pass: 17 passed,
  1 Linux-only test unavailable on Windows.
- Verified the actual worker can enter a separate network namespace and deny a
  direct TCP connection (`OSError`) when the namespace profile is explicitly
  requested. This is deny-all enforcement only; approved-destination egress
  policy is not implemented and governed network profiles remain fail-closed.
- Added immutable `NetworkPolicy` and `ApprovedDestination` validation bound to
  scope revision, authorization, expiry, addresses, protocols, and ports.
  Approved mode is wired to an explicit deployment-owned helper contract and
  fails closed when `CHINESCAN_NETWORK_POLICY_HELPER` is absent or invalid.
- Reused the existing durable recovery lifecycle rather than adding another:
  the Phase 2D acceptance tests cover concurrent claims, lease expiry, stale
  worker fencing, safe retry, uncertain external outcomes, backup/restore,
  duplicate-action blocking, cancellation, and authorized reconciliation.
- Windows restricted-token/AppContainer/ACL/WFP integration: not started.
- Recovery/lifecycle changes: not started.

## Current continuation milestone

The filesystem boundary is integrated through Landlock and fails closed when
the current kernel does not provide it. Approved-destination policy is now
represented and wired to a deployment helper, but the helper and native
firewall acceptance remain deployment work. The PostgreSQL adapter, baseline,
RLS SQL, and trigger translations are local implementation work; live
PostgreSQL execution and RLS acceptance remain outstanding because no
disposable PostgreSQL service is available on this host. Recovery code-side
contracts are implemented; process/container restart acceptance remains
outstanding.

## Host/deployment dependencies

- Current control host is Windows 11 with Kali WSL2 and Docker Desktop Linux
  Engine. Native Linux and native Windows acceptance require the relevant host.
- No system-wide firewall, cgroup hierarchy, Docker socket, or credential was
  modified.

## Exact next action

Start a disposable PostgreSQL 16+ service with the locked psycopg extra, apply
the local baseline in a throwaway database, run the integration/RLS acceptance
suite, and inspect the generated SQL on the server. Do not connect to
Supabase. Then execute the native Linux approved-egress/cgroup acceptance and
the Windows restricted-token/ACL/network acceptance.

## Current Git state

- Branch: `release/phase-6`
- No commit, push, merge, reset, rebase, clean, stash, or broad staging.
- Existing untracked `artifacts/` and `scripts/make_cover.py` preserved.

## Known blockers

PostgreSQL server-backed migration/RLS acceptance is blocked by the absent
local server/driver. Linux filesystem/cgroup/approved-egress acceptance and
Windows restricted-token, AppContainer, ACL, and network acceptance remain
incomplete. The current host additionally lacks Landlock and delegated cgroup
support.

## Verification after this milestone

- Full locked Python suite: 954 passed, 5 deselected, 387 warnings, 27m20s.
- Strict mypy: passed for 133 source files.
- Ruff and formatting: passed for the changed implementation and tests.
- Focused network/isolation/recovery tests: 26 passed, 2 Linux-only tests unavailable on the
  Windows control host.
- Strict Docker worker probe: native namespace, seccomp, no-new-privileges,
  and effective capability-set evidence observed; cgroup, filesystem, and
  approved-egress controls remained blocked or unverified.
- PostgreSQL/configuration acceptance: **13 passed, 1 skipped**; the skip is
  the live PostgreSQL integration test because `CHINESCAN_TEST_POSTGRES_URL`
  was not configured and psycopg is not installed in the current interpreter.
- Full Python suite after this continuation: **966 passed, 3 skipped, 5
  deselected, 407 warnings** in 43m06s. No failures.
- `py -3.12 -m uv lock --check`: passed; no dependency installation was
  performed.
- `git diff --check`: passed.
- Trusted-proxy origin regression: **2 passed**; allowlisted forwarded HTTPS
  origin accepted and unlisted origin rejected.
- Ruff and strict mypy on the trusted-proxy change: passed.

### First application superuser bootstrap

- Added the fixed-email bootstrap flow for `cipherchi@proton.me`; no password
  or cleartext token is stored in source or SQL.
- Added PostgreSQL `SECURITY DEFINER` functions for one-time provisioning and
  token consumption, restricted to `chinescan_backend`; `anon`,
  `authenticated`, and `service_role` cannot execute them.
- Added the protected CLI and authenticated setup endpoint. The endpoint is
  unavailable on SQLite and only operates against the reviewed PostgreSQL
  deployment.
- Added platform-role persistence and loading into the existing organization
  and identity services. The first administrator receives an active owner
  membership in the dedicated administration organization.
- Fresh disposable PostgreSQL 16 migration and assertion verification passed.
- Fresh disposable PostgreSQL bootstrap acceptance passed: **1 passed**;
  duplicate bootstrap, fixed-email enforcement, one-time token use, sign-in,
  owner membership, and audit events were verified.
- Fixed a verification SQL PL/pgSQL variable collision, direct CLI import
  behavior, and public execution privileges on bootstrap functions.

### Exact next action

Apply the reviewed migration manually in the intended new Supabase project,
run the verification SQL as `chinescan_backend`, then run the protected
bootstrap CLI from the backend host. No remote Supabase action has been taken
by this worktree.
