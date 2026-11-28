# ChineScan Deployment Progress

Last updated: 2026-11-28T12:35:00+01:00
Target: Oracle Cloud VM (`141.145.152.200`) + Supabase PostgreSQL (`eqxqrelhqomtyimbuwzu`) + Vercel (`https://chinescan.vercel.app`)
Production Branch: `main` (code commit `9d9355b5`)

## Checklist

- [x] **Phase 1: Repository & architecture inspection**
  - Inspected `deploy/oracle/*`, `chinescan/core/config/settings.py`, `chinescan/web/app.py`, `chinescan/core/storage/postgres.py`, `vercel.json`.
  - Backend listens on `127.0.0.1:8765`, fronted by Nginx on `10.0.1.197:8765`.
- [x] **Phase 2: Oracle VM base OS preparation**
  - Ubuntu 26.04.1 LTS, 951 MB RAM, 45 GB free, private IP `10.0.1.197`.
  - `nginx 1.28.3`, `certbot`, `uv 0.13.10`, `chinescan` user/group, `/opt/chinescan`, `/etc/chinescan`, `/var/lib/chinescan` configured.
- [x] **Phase 3: Python 3.12 & dependencies**
  - CPython `3.12.16` and 47 locked packages installed via `uv sync --locked --extra postgres`.
- [x] **Phase 4: Systemd service, Nginx, VM & VCN firewall**
  - `/etc/systemd/system/chinescan.service` installed and enabled.
  - Nginx active on `10.0.1.197:8765` -> `127.0.0.1:8765` with `X-Forwarded-Proto: https`, `X-Forwarded-Host: chinescan.vercel.app`, rate limit `30r/s` (`burst=60`).
  - `iptables` + `netfilter-persistent` + Oracle Cloud VCN ingress for TCP `8765` active.
- [x] **Phase 5: Environment & Supabase PostgreSQL configuration**
  - `/etc/chinescan/chinescan.env` configured (`0640 root:chinescan`) with `chinescan_backend.eqxqrelhqomtyimbuwzu` via Supabase Session Pooler (`aws-0-eu-central-1.pooler.supabase.com:5432`, `sslmode=require`).
- [x] **Phase 6: CI & PostgreSQL compatibility fixes**
  - Renamed `alembic_version` RLS policy in `supabase/migrations/20261127000000_chinescan_baseline.sql` and live Supabase DB to `alembic_version_read` (`26d50fc4`), preserving the 40-policy `_backend` count invariant.
  - `ChiNeScan CI` (`46138287830`) passed all 8 jobs including `PostgreSQL migration and bootstrap acceptance` and `quality`.
  - Replaced all 46 SQLite-only `BEGIN IMMEDIATE` calls across 9 `chinescan/core/` modules with dialect-aware `begin_immediate(connection)` (`426634f0`, `9d9355b5`) so FastAPI lifespan startup succeeds on PostgreSQL.
- [x] **Phase 7: Obsolete Phase 1-5 branch cleanup**
  - Deleted merged local & remote branches: `release/phase-1-2`, `release/phase-3`, `release/phase-5`; pruned stale `origin` refs.
  - Preserved `main`, `release/phase-6`, `release/phase-4`, `release/phase-4-report` (Phase 4 branches contain commits not reachable as ancestors of `main`).
- [x] **Phase 8: Vercel frontend deployment & end-to-end verification**
  - Linked `cipherchi/chinescan` to `ChiNetPulse/ChiNeScan` with `.vercelignore` and `vercel.json` `/api/:path*` rewrite.
  - `https://chinescan.vercel.app/` returns `HTTP/1.1 200 OK`.
  - `http://141.145.152.200:8765/api/health` and `https://chinescan.vercel.app/api/health` return `200 OK` (`{"status":"ok","app_name":"ChiNeScan","version":"0.1.0",...}`).
  - `https://chinescan.vercel.app/api/ready` (unauthenticated) returns `401 Unauthorized`.
  - `POST https://chinescan.vercel.app/api/auth/login` with `Origin: https://chinescan.vercel.app` returns `401 Invalid email or password.` (verifying `trusted_proxy`, `X-Forwarded-Proto: https`, `X-Forwarded-Host: chinescan.vercel.app`, CORS origin validation, and Supabase DB query).
- [x] **Phase 9: Final `DEPLOYMENT.md` & progress update**
