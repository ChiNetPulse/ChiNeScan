# Hybrid deployment plan

## Current architecture

- **Vercel:** the existing Vite/React application in `frontend/`. The Vercel
  project root is `frontend`, the build command is `npm run build`, and the
  output directory is `dist` when configured from that root.
- **Oracle AMD VM:** the existing FastAPI application and ordinary backend
  services. The default `chinescan web serve` bind remains loopback. A reverse
  proxy must terminate HTTPS and forward to the loopback listener.
- **Supabase:** target PostgreSQL service for the opt-in local
  `PostgresRepository`; the reviewed baseline is local only and no remote
  schema has been created.

## Frontend/API routing

The Vite frontend accepts the public build-time variable
`VITE_API_BASE_URL`. Leave it empty when `/api` is reverse-proxied by the
frontend origin. Direct cross-origin API use requires an explicitly configured
backend CORS origin, but the current backend session cookie is
`HttpOnly`, `Secure` when enabled, and `SameSite=Strict`; therefore a direct
Vercel-to-Oracle browser session is not a supported production topology.
Use a same-origin rewrite/reverse proxy or review the authentication contract
before enabling another topology.

The backend accepts `CHINESCAN_CORS_ALLOWED_ORIGINS` as a JSON list, for
example:

```text
CHINESCAN_CORS_ALLOWED_ORIGINS=["https://dashboard.example.com"]
```

Never use `*` with credentialed requests. `CHINESCAN_SECURE_COOKIE=true` (or
the CLI `--secure-cookie` option) is required behind HTTPS.

## Backend startup

```text
chinescan web serve --host 127.0.0.1 --port 8765 --secure-cookie
```

Do not bind the application directly to a public interface without a reviewed
TLS reverse proxy and host firewall policy. The current command supports a
custom host for controlled deployments, but loopback remains the default.

## Supabase database integration

The repository now has an explicit PostgreSQL adapter and a generated baseline
at `supabase/migrations/20261127000000_chinescan_baseline.sql`. The adapter is
opt-in through `CHINESCAN_DATABASE_URL` and requires the reviewed baseline to
already be present at revision `0016_phase6_governance`.

The existing SQLite recovery verifier and backup commands remain SQLite-only.
PostgreSQL deployments must use PostgreSQL/Supabase backup and restore
procedures until an equivalent application-level backup adapter is implemented.

Before PostgreSQL cutover, implement and test:

1. PostgreSQL execution against a real local/test PostgreSQL instance.
2. PostgreSQL equivalents for every remaining historical SQLite trigger and
   scope guard.
3. Transaction and lease behavior under PostgreSQL concurrency.
4. A controlled SQLite-to-PostgreSQL data migration and verified rollback.
5. RLS policies mapped to the existing organization, engagement, role,
   approval, audit, and evidence authorization model. The local baseline now
   installs organization-member policies and SECURITY DEFINER membership
   helpers. The backend must set `SET LOCAL chinescan.user_id` and
   `SET LOCAL chinescan.organization_id` only after the existing session and
   membership checks succeed; browser roles still have no table grants.
6. Private storage integration only after evidence lifecycle tests pass. The
   current evidence stores are local, content-addressed managed directories;
   no object-storage migration is performed by this change. A future adapter
   must upload to a private bucket only after the local digest and manifest
   are finalized, verify the remote object digest/size, and retain the local
   record as the source of legal-hold and deletion decisions.

### SQLite migration and rollback plan

The SQLite database is not modified or discarded. Before any cutover, take a
verified file-level backup while the application is stopped, export rows in
foreign-key order, preserve identifiers and timestamps, and validate counts,
unique constraints, foreign keys, append-only history, and execution-job
state transitions in a disposable PostgreSQL database. Keep the original
SQLite file read-only as the rollback source. Cut over by switching
`CHINESCAN_DATABASE_URL` only after a verification report is accepted; roll
back by stopping the backend, restoring the previous SQLite configuration,
and retaining the PostgreSQL database for forensic comparison. Do not run two
writable databases concurrently. PostgreSQL backups and Supabase recovery
procedures remain separate from the application-level SQLite recovery verifier.

Until a real PostgreSQL test instance or the authorized Supabase project passes
the adapter and RLS acceptance suite, Supabase status is **Implemented locally
— acceptance pending** and **not remote configured**.

For a PostgreSQL-capable container image, build with the optional extra:

```text
docker build --build-arg CHINESCAN_POSTGRES=1 -f docker/Dockerfile -t chinescan-postgres:local .
```

The normal image remains SQLite-only. The PostgreSQL image still requires a
reviewed `CHINESCAN_DATABASE_URL` and a pre-applied baseline.

## Feature availability

The public deployment may expose authenticated ordinary dashboard and API
behavior only after the backend persistence and authentication topology are
verified. Scanner execution remains unavailable unless the existing Phase 6
worker isolation preflight and deployment-backed network policy pass. No
unrestricted fallback is permitted.
