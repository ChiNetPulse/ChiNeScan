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
  triggers, and tenant-scoped isolation.
- POSIX resource limits, supervised process-tree cleanup, Linux namespace and
  seccomp bootstrap paths, Landlock/cgroup fail-closed checks, Windows Job
  Object controls, and immutable approved-destination policy models.
- Static malware triage, optional Rust redaction acceleration with Python
  fallback, report export, and authenticated governance views.

Important deployment limitations remain. Native Linux delegated cgroups,
Landlock availability, approved-destination firewall enforcement, native
Windows restricted-token/AppContainer/ACL/network acceptance, and full
deployment crash/restart acceptance require suitable hosts and privileges.
Scanner profiles requiring an unverified control remain unavailable.

## Architecture

### Local and backend services

- **FastAPI / Python:** authenticated API, CLI services, governance, jobs,
  recovery, evidence metadata, reports, and scanner adapters.
- **SQLite:** default local database and local content-addressed evidence
  storage.
- **PostgreSQL/Supabase:** opt-in durable database backend configured via
  `CHINESCAN_DATABASE_URL`. The adapter requires a dedicated least-privilege
  database role and does not silently fall back to SQLite.
- **Rust:** optional PyO3 redaction engine; Python redaction remains the safe
  fallback.
- **Workers:** governed subprocess execution with authorization, immutable
  scope binding, capability snapshots, supervision, resource controls, and
  fail-closed isolation profiles.

### Hybrid deployment overview

- **Frontend (`frontend/`):** Vite + React static application.
- **Backend host:** FastAPI backend, ordinary backend services, local
  content-addressed evidence, and guarded worker orchestration.
- **Database:** PostgreSQL / Supabase after schema migrations are applied and
  verified.

Frontend deployments must receive only public configuration such as
`VITE_API_BASE_URL`. Database URLs, backend passwords, API keys, and evidence
credentials are backend-only.

## Authentication and authorization

ChineScan uses application-managed authentication and session handling with
Argon2 password hashing, CSRF protection, login throttling, organization
memberships, role-based access control, approvals, audit events, and immutable
scope revisions enforced by the backend.

When PostgreSQL is enabled, the backend connects with a dedicated
least-privilege database role (without elevated database or RLS-bypass privileges) and
enforces row-level tenant isolation per transaction. Browser roles have no
direct application-table privileges.

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

- `CHINESCAN_DATABASE_URL`: protected PostgreSQL connection URL using a
  dedicated least-privilege backend role.
- `CHINESCAN_CORS_ALLOWED_ORIGINS`: explicit frontend origins.
- `CHINESCAN_TRUSTED_PROXY_MODE`: opt-in trusted-proxy handling; it requires
  loopback ingress, HTTPS forwarded protocol, and an allowlisted origin.
- `CHINESCAN_OPERATOR_CREDENTIAL_FILE`: local credential-file location where
  applicable.
- `VITE_API_BASE_URL`: public frontend API base URL, if a same-origin proxy is
  not used.

Use `.env.example`, `frontend/.env.example`, and
`deploy/oracle/chinescan.env.template` as templates. They contain placeholders
only. Never commit `.env`, database passwords, API keys, or production
credentials.

## Database and evidence

Alembic’s expected application revision is `0016_phase6_governance`. The
PostgreSQL baseline creates 40 application tables, RLS policies, 15 integrity
triggers, helper functions, and browser privilege denial.

Evidence currently remains in local content-addressed storage. This release
does not claim that remote object storage, backups, exports, caches, or
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
are not required for pull requests. Production deployment is separately
controlled.

## Deployment preparation

Deployment templates are under `deploy/oracle/`: systemd, Nginx, environment,
bootstrap, and health-check files. See `deploy/oracle/README.md` and
`docs/HYBRID-DEPLOYMENT.md` for prerequisites, resource limits, HTTPS, trusted
proxy configuration, and the remaining acceptance gates.

`vercel.json` targets the Vite frontend in `frontend/`. Configure the
frontend deployment to use `main` as its production branch and set only public
frontend variables.

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
