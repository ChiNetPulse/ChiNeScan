# ChineScan Production Deployment

## Architecture Overview

- **Frontend**: Vite + React application hosted on Vercel at `https://chinescan.vercel.app`
- **API Rewrite**: `vercel.json` proxies `/api/:path*` from Vercel to `http://141.145.152.200:8765/api/:path*` so browser requests remain same-origin over HTTPS (`SameSite=Strict`, `Secure`, `HttpOnly` session cookies).
- **Backend Host**: Oracle Cloud Ubuntu 26.04.1 LTS VM (`141.145.152.200`, private IP `10.0.1.197`)
  - **Nginx**: Listens on `10.0.1.197:8765` with rate limiting (`30r/s`, `burst=60`), sets `X-Forwarded-Proto: https` and `X-Forwarded-Host: chinescan.vercel.app`, and proxies to `http://127.0.0.1:8765`.
  - **Application Service**: `chinescan.service` (systemd, unprivileged user `chinescan`) runs `/opt/chinescan/.venv/bin/chinescan web serve --host 127.0.0.1 --port 8765 --secure-cookie` using Python `3.12.16` managed by `uv`.
- **Database**: Supabase PostgreSQL (`eqxqrelhqomtyimbuwzu`, `eu-central-1`) connected via Session Pooler (`aws-0-eu-central-1.pooler.supabase.com:5432`, `sslmode=require`) using the dedicated least-privilege `chinescan_backend` role (`NOSUPERUSER`, `NOBYPASSRLS`).

## Environment Configuration (Oracle VM)

Configuration lives exclusively on the Oracle VM at `/etc/chinescan/chinescan.env` (`0640`, owned by `root:chinescan`, never committed to Git):

- `CHINESCAN_DATABASE_URL`: PostgreSQL + `psycopg` Session Pooler URL for `chinescan_backend.eqxqrelhqomtyimbuwzu`
- `CHINESCAN_CORS_ALLOWED_ORIGINS=["https://chinescan.vercel.app"]`
- `CHINESCAN_TRUSTED_PROXY=true`
- `CHINESCAN_SECURE_COOKIE=true`
- `CHINESCAN_DATABASE_PATH=/var/lib/chinescan/chinescan.sqlite3`
- `CHINESCAN_REPORTS_DIR=/var/lib/chinescan/reports`
- `CHINESCAN_OPERATOR_CREDENTIAL_FILE=/var/lib/chinescan/operator.json`

## Operations & Verification Commands

On the Oracle VM:

```bash
sudo systemctl status chinescan.service
sudo journalctl -u chinescan -n 50 --no-pager
curl -sf http://127.0.0.1:8765/api/health
```

Updating the backend on the Oracle VM after pushing to `main`:

```bash
sudo -u chinescan git -C /opt/chinescan pull origin main
sudo systemctl restart chinescan.service
```

Public health & auth boundary verification:

```bash
curl -sf https://chinescan.vercel.app/api/health
curl -i https://chinescan.vercel.app/api/ready   # Expect HTTP 401
```

## First Superuser Provisioning

The initial platform superuser (`cipherchi@proton.me`) is provisioned using a one-time, 15-minute, SHA-256-hashed setup token with no default password:

1. On the Oracle VM, issue the one-time token:

```bash
sudo -u chinescan bash -c 'set -a && source /etc/chinescan/chinescan.env && set +a && /opt/chinescan/.venv/bin/python /opt/chinescan/scripts/bootstrap_first_superuser.py --storage-root /var/lib/chinescan'
```

2. Complete activation by posting the token and your chosen password to `/api/auth/first-superuser/setup` (same-origin over HTTPS):

```bash
curl -i -X POST https://chinescan.vercel.app/api/auth/first-superuser/setup \
  -H "Content-Type: application/json" \
  -H "Origin: https://chinescan.vercel.app" \
  -d '{"email":"cipherchi@proton.me","token":"<ONE_TIME_TOKEN>","password":"<CHOSEN_PASSWORD>"}'
```

3. Restart `chinescan.service` after activation if needed so background workers initialize with the active superuser operator context.
