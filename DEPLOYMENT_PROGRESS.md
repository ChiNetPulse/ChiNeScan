# ChineScan Deployment Progress

Last updated: 2026-11-28T11:40:00+01:00
Target: Oracle Cloud VM (`141.145.152.200`) + Supabase PostgreSQL (`eqxqrelhqomtyimbuwzu`) + Vercel (`https://chinescan.vercel.app`)
Branch: `main` (started at `083e2532`)

## Checklist

- [x] **Phase 1: Repository & architecture inspection**
  - `main` at `083e2532`. Inspected all deploy templates, settings, `postgres.py`, `vercel.json`.
  - Backend listens on `127.0.0.1:8765`. Selected Vercel rewrite topology.
- [x] **Phase 2: Oracle VM base OS preparation**
  - Ubuntu 26.04.1 LTS, 951 MB RAM, 45 GB free, private IP `10.0.1.197`.
  - `nginx 1.28.3`, `certbot` installed. `chinescan` system user/group created.
  - `uv 0.13.10` at `/usr/local/bin/uv`.
  - Repo cloned to `/opt/chinescan` as `chinescan:chinescan 0750`.
  - `/etc/chinescan` (`root:chinescan 0750`), `/var/lib/chinescan` (`chinescan:chinescan 0750`).
- [x] **Phase 3: Python 3.12 & dependencies**
  - CPython `3.12.16` and 47 locked packages installed via `uv sync --locked --extra postgres`.
  - `psycopg==3.3.9`, `chinescan==0.1.0` confirmed.
- [x] **Phase 4: Systemd service, Nginx, VM firewall**
  - `/etc/systemd/system/chinescan.service` installed and enabled.
  - Nginx on `10.0.1.197:8765` → `127.0.0.1:8765` with `X-Forwarded-Proto: https`, `X-Forwarded-Host: chinescan.vercel.app`, rate limit 30r/s.
  - `iptables` port 8765 open, persisted via `netfilter-persistent`.
  - Oracle Cloud VCN Security List: TCP port 8765 ingress added.
- [x] **Phase 5: Environment & Supabase configuration**
  - `/etc/chinescan/chinescan.env` created with correct URL, `0640 root:chinescan`.
  - URL: `postgresql+psycopg://chinescan_backend.eqxqrelhqomtyimbuwzu:<REDACTED>@aws-0-eu-central-1.pooler.supabase.com:5432/postgres?sslmode=require`
  - Previous errors fixed: stray `10@` fragment removed; username corrected from `postgres.` to `chinescan_backend.`.
- [ ] **Phase 6: Supabase RLS fix for `alembic_version`** — *Pending user SQL Editor action*
  - Root cause: `alembic_version` has RLS enabled but no permissive policy for `chinescan_backend` → rows hidden → revision reads as `None` → schema check fails.
  - Fix: `CREATE POLICY "alembic_version_backend" ON public.alembic_version AS PERMISSIVE FOR SELECT TO chinescan_backend USING (true);`
  - Migration SQL updated locally (committed in this session).
- [ ] **Phase 7: Service health & public API verification**
- [ ] **Phase 8: Vercel frontend deployment & end-to-end test**
- [ ] **Phase 9: Final `DEPLOYMENT.md` commit**

## Diagnosed Errors & Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `failed to resolve host '10@aws-0...'` | Stray `10@` fragment + wrong username `postgres.` | Corrected URL in `/etc/chinescan/chinescan.env` |
| `StorageError: schema is not reviewed baseline` | `alembic_version` has RLS enabled with no policy for `chinescan_backend` → SELECT returns 0 rows → `revision=None` | Add RLS policy (see Phase 6) |

## Git Changes (this session)

| File | Change | Status |
|------|--------|--------|
| `vercel.json` | Added `/api/:path*` rewrite to `http://141.145.152.200:8765/api/:path*` | To commit |
| `supabase/migrations/20261127000000_chinescan_baseline.sql` | Added `ALTER TABLE public.alembic_version ENABLE ROW LEVEL SECURITY` + `CREATE POLICY "alembic_version_backend"` | To commit |
| `.gitignore` | Added `artifacts/` (CI-generated JUnit XML and ruff JSON reports) | To commit |
| `DEPLOYMENT_PROGRESS.md` | This file — deployment checkpoint | To commit |
| `scripts/make_cover.py` | Playwright social preview helper — user intentionally left untracked | Preserved untracked |

## Pending Operator Actions

1. **Apply RLS policy to Supabase SQL Editor** (`eqxqrelhqomtyimbuwzu` project):
   ```sql
   CREATE POLICY "alembic_version_backend" ON public.alembic_version
     AS PERMISSIVE FOR SELECT TO chinescan_backend USING (true);
   ```
   Then restart: `sudo systemctl restart chinescan.service`
2. **Vercel deployment**: Push to `main` → Vercel auto-deploys from connected repo.
