# Oracle ordinary-backend deployment

These files deploy only the ordinary FastAPI backend. They do not enable
scanner execution and do not apply database migrations.

## Host prerequisites

On the approved Ubuntu host, an administrator must provide:

- Python 3.12+, `python3.12-venv`, and the repository's locked `uv` workflow;
- `nginx`, `curl`, `ca-certificates`, and a certificate provisioned for the
  final API hostname;
- a `chinescan` system user and group with ownership of `/opt/chinescan` and
  `/var/lib/chinescan`;
- outbound TLS access to the Supabase PostgreSQL endpoint;
- inbound TCP 443 only (port 8765 remains loopback-only);
- a protected `/etc/chinescan/chinescan.env` with a non-placeholder
  `CHINESCAN_DATABASE_URL` and the final frontend origin.

Install the application environment from the reviewed lockfile and include
the PostgreSQL extra. Do not use the default SQLite-only container or put the
database URL in Vercel variables.

## Installation sequence

1. Place the reviewed repository at `/opt/chinescan` and create the locked
   virtual environment.
2. Create `/etc/chinescan/chinescan.env` from
   `chinescan.env.template`, set mode `0640`, and ensure it contains no
   placeholders.
3. Replace all example hostnames and certificate paths in the Nginx template.
4. Apply the Supabase SQL package separately and verify its output.
5. Run `sudo bash /opt/chinescan/deploy/oracle/bootstrap.sh`.
6. Run `bash /opt/chinescan/scripts/oracle_healthcheck.sh https://<api-host>`.

The bootstrap rejects missing users, placeholder configuration, missing Nginx,
and absent application environments. It does not create users, install
packages, provision TLS, or modify Supabase.
