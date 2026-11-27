# ChineScan

ChineScan is an authenticated security-assessment workstation and governed
application backend for code assessment, log analysis, static malware triage,
authorized domain posture checks, investigations, reporting, evidence, and
recovery. It is designed to preserve analyst control: findings are leads for
review, malware samples are never executed or uploaded, and scanner execution
fails closed when its required isolation boundary is unavailable.

## Current status

The repository contains the Phase 1–6 application, governance, PostgreSQL
integration, deployment preparation, and release documentation. The
`release/phase-6` work is suitable for review and controlled deployment
preparation, but it does not by itself prove production deployment or native
cross-platform scanner acceptance.

The following are locally implemented and tested:

- Authenticated FastAPI backend and Vite + React dashboard.
- SQLite persistence with Alembic migrations, backup, recovery, durable jobs,
  leases, reconciliation, audit history, evidence retention, legal holds, and
  tenant-scoped organization workflows.
- Optional PostgreSQL adapter selected by `CHINESCAN_DATABASE_URL`; SQLite
  remains the default local backend.
- Supabase-compatible 40-table baseline SQL, role-aware RLS, integrity
  triggers, transaction-local organization identity binding, and verification
  SQL.
- One-time first application-superuser bootstrap for the fixed email
  `cipherchi@proton.me`. This is an application identity, not a PostgreSQL
  administrator, Supabase project owner, `service_role`, or
  `chinescan_backend`.
- POSIX resource limits, supervised process-tree cleanup, Linux namespace and
  seccomp bootstrap paths, Landlock/cgroup fail-closed checks, Windows Job
  Object controls, and immutable approved-destination policy models.
- Static malware triage, optional Rust redaction acceleration with Python
  fallback, report export, and authenticated governance views.

Important deployment limitations remain. Native Linux delegated cgroups,
Landlock availability, approved-destination firewall enforcement, native
Windows restricted-token/AppContainer/ACL/network acceptance, and full
deployment crash/restart acceptance require suitable hosts and privileges.
The live Supabase project, Oracle VM, and Vercel production deployment have
not been changed by this repository work. Scanner profiles requiring an
unverified control remain unavailable.

## Architecture

### Local and backend services

- **FastAPI / Python:** authenticated API, CLI services, governance, jobs,
  recovery, evidence metadata, reports, and scanner adapters.
- **SQLite:** default local database and local content-addressed evidence
  storage.
- **PostgreSQL/Supabase:** opt-in durable database backend. The adapter
  requires the reviewed `chinescan_backend` login and does not silently fall
  back to SQLite.
- **Rust:** optional PyO3 redaction engine; Python redaction remains the safe
  fallback.
- **Workers:** governed subprocess execution with authorization, immutable
  scope binding, capability snapshots, supervision, resource controls, and
  fail-closed isolation profiles.

### Intended hybrid deployment

- **Vercel:** the existing `frontend/` Vite + React static application.
- **Oracle AMD VM:** FastAPI backend, ordinary backend services, local
  content-addressed evidence, and guarded worker orchestration.
- **Supabase:** PostgreSQL only after the reviewed baseline is manually
  applied and verified.

Vercel must receive only public frontend configuration such as
`VITE_API_BASE_URL`. Database URLs, backend passwords, service-role keys,
bootstrap tokens, and evidence credentials are backend-only.

## Authentication and authorization

ChineScan uses custom application authentication and session management; it
does not replace that model with Supabase Auth. Passwords use the existing
Argon2 policy. Sessions, CSRF protection, login throttling, organization
memberships, roles, approvals, audit events, and immutable scope revisions are
enforced by the backend.

The PostgreSQL backend connects as the dedicated `chinescan_backend` role,
which must be `LOGIN`, `NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEROLE`, and not an
owner of application tables. The Supabase `service_role` is separate and is
not used as the direct backend login. Browser roles have no application-table
privileges. PostgreSQL transactions bind `chinescan.user_id`,
`chinescan.organization_id`, and write access before RLS-protected work.

The first administrator sequence is deliberately separate from database-role
provisioning:

1. Provision or verify `chinescan_backend` with a password supplied
   out-of-band.
2. Apply `supabase/migrations/20261127000000_chinescan_baseline.sql` manually
   in the intended new Supabase project.
3. Run `supabase/manual/verify_chinescan.sql` as `chinescan_backend`.
4. Run `py -3.12 scripts/bootstrap_first_superuser.py` from the protected
   backend host.
5. Deliver the short-lived setup token out-of-band.
6. POST it with a newly chosen password to
   `/api/auth/first-superuser/setup`.
7. Verify sign-in, platform role, owner membership, and audit history.

The live Supabase migration and first-superuser provisioning have not been
performed by this repository work.

## Local setup

Requires Python 3.12+ and Node.js/npm for the dashboard. From the repository
root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

For PostgreSQL development, install the optional driver extra:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[postgres]"
```

Build the frontend:

```powershell
Set-Location frontend
npm ci
npm run build
Set-Location ..
```

The authenticated local dashboard binds to loopback by default:

```powershell
.\.venv\Scripts\python.exe -m chinescan web serve
```

Do not expose the local dashboard publicly. Use the explicit supported
startup helper only when local dashboard use is intended.

## Configuration

Configuration is loaded from the existing settings and environment model.
Common deployment variables include:

- `CHINESCAN_DATABASE_URL`: protected PostgreSQL URL; only the reviewed
  `chinescan_backend` role is accepted for PostgreSQL deployments.
- `CHINESCAN_CORS_ALLOWED_ORIGINS`: explicit frontend origins.
- `CHINESCAN_TRUSTED_PROXY_MODE`: opt-in trusted-proxy handling; it requires
  loopback ingress, HTTPS forwarded protocol, and an allowlisted origin.
- `CHINESCAN_OPERATOR_CREDENTIAL_FILE`: local credential-file location where
  applicable.
- `VITE_API_BASE_URL`: public frontend API base URL, if a same-origin proxy is
  not used.

Use `.env.example`, `frontend/.env.example`, and
`deploy/oracle/chinescan.env.template` as templates. They contain placeholders
only. Never commit `.env`, database passwords, service-role keys, setup tokens,
or production credentials.

## Database and evidence

Alembic’s expected application revision is `0016_phase6_governance`. The
Supabase SQL package is a reviewed baseline for a new project and records that
revision. It creates 40 application tables, RLS policies, 15 integrity
triggers, helper functions, explicit backend grants, and browser privilege
denial.

The complete SQL and manual verification procedure are in
`supabase/manual/README.md` and
`docs/reports/phase-6-supabase-migration-review.md`. The baseline is not a
reversible production migration: for a non-empty project, stop and use a
reviewed backup or forward migration rather than ad hoc drops.

Evidence currently remains in Oracle/local content-addressed storage. This
release does not claim that Supabase Storage, backups, exports, caches, or
external evidence copies are governed by the local deletion lifecycle.

## Testing and CI

Useful local checks:

```powershell
py -3.12 -m pytest -q
py -3.12 -m ruff check .
py -3.12 -m ruff format --check .
py -3.12 -m mypy --strict chinescan
git diff --check
```

Rust checks:

```powershell
Set-Location engine
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
Set-Location ..
```

Frontend checks:

```powershell
Set-Location frontend
npm ci
npm run typecheck
npm test -- --run
npm run build
Set-Location ..
```

The GitHub Actions workflow runs Python quality, coverage, pip-audit,
Bandit, Rust formatting/Clippy/tests/audit, frontend tests/typecheck/build,
browser acceptance, Windows worker checks, secret scanning, container checks,
and a disposable PostgreSQL migration/RLS/bootstrap job. Production secrets
are not required for pull requests. Production deployment and Supabase
administrator bootstrap are manual and separately controlled.

## Deployment preparation

Oracle templates are under `deploy/oracle/`: systemd, Nginx, environment,
bootstrap, and health-check files. They are operator templates, not evidence
that the Oracle VM is deployed or accepted. See `deploy/oracle/README.md` and
`docs/HYBRID-DEPLOYMENT.md` for prerequisites, resource limits, HTTPS, trusted
proxy configuration, and the remaining acceptance gates.

`vercel.json` targets the Vite frontend in `frontend/`. Configure the
repository’s Vercel project to use `main` as its production branch and set
only public frontend variables. Do not reuse the unrelated Chinetpulse
Portfolio Vercel project.

## Security boundaries and known gaps

- Static malware triage never detonates samples or uploads them.
- Domain posture checks require explicit target authorization.
- URL validation and ARTEX pinned transport do not by themselves provide
  OS-level scanner egress isolation.
- Hardened execution remains unavailable when mandatory namespace, cgroup,
  filesystem, seccomp, capability, or network controls are not initialized
  and verified.
- Docker demonstrations are not proof of application-managed production
  isolation.
- Linux cgroup delegation, Landlock, approved egress/firewall policy, native
  Windows restricted tokens/AppContainer/ACL/WFP, and native deployment
  acceptance remain environment-dependent or incomplete as recorded in
  `docs/reports/phase-6-acceptance-report.md`.
- Exactly-once external execution is not claimed; uncertain outcomes require
  reconciliation.

Use ChineScan only on assets and data you own or are explicitly authorized to
assess.

## License

Apache-2.0. See [LICENSE](LICENSE).
