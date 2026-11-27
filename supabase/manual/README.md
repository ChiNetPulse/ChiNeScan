# ChineScan manual Supabase migration package

## Execution order

1. As a Supabase administrator, create the dedicated backend login before
   running the migration. Use a strong password supplied out-of-band; never
   put it in this repository or the frontend:

   ```sql
   CREATE ROLE chinescan_backend LOGIN PASSWORD '<strong-random-password>'
     NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
   ```

   If the role already exists, verify it instead of recreating it:

   ```sql
   SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, rolcreaterole
     FROM pg_roles
    WHERE rolname = 'chinescan_backend';
   ```

   Expected values are `rolcanlogin = true`, `rolsuper = false`,
   `rolbypassrls = false`, and `rolcreaterole = false`.
2. Confirm the target is the new ChineScan Supabase project and that the
   project contains no application tables or user-created data to preserve.
3. Open the Supabase SQL Editor and execute the complete file
   `supabase/migrations/20261127000000_chinescan_baseline.sql` once.
4. Review the transaction result. A failure should roll back the transaction;
   do not repeatedly apply edited fragments.
5. Configure the Oracle backend's protected `CHINESCAN_DATABASE_URL` with the
   `chinescan_backend` username and the out-of-band password. The adapter
   rejects any other database role.
6. Execute `supabase/manual/verify_chinescan.sql` using the same
   `chinescan_backend` connection and retain its output.
7. Run `scripts/bootstrap_first_superuser.py` from a protected Oracle/backend
   environment. It creates only `cipherchi@proton.me` as the first application
   superuser, stores only a SHA-256 token hash, and prints the one-time setup
   token once. Do not place the token in SQL, source control, logs, or frontend
   configuration.
8. Deliver that token out-of-band to the administrator and POST it with a
   newly chosen password to `/api/auth/first-superuser/setup`:

   ```json
   {"email":"cipherchi@proton.me","token":"<one-time-token>","password":"<new-password>"}
   ```

   The endpoint validates the fixed email, password policy, token hash, expiry,
   and unused state, then creates the authenticated session. A second attempt
   is rejected.
9. Verify administrator sign-in, the `superuser` platform role, active owner
   membership in the administration organization, and an audit event named
   `platform.superuser_password_initialized`.
10. Run the PostgreSQL integration tests with real fixture IDs only after the
   migration and role checks pass.

The migration uses PostgreSQL core features and the standard Supabase roles
`anon`, `authenticated`, and `service_role`; it requires no extension or
undocumented dashboard command. It also requires the explicitly provisioned
`chinescan_backend` login described above. The migration does not create a
password-bearing login because managed Supabase environments may restrict
`CREATE ROLE`, and credentials must remain outside source control.
`SET LOCAL search_path = public` makes the unqualified metadata DDL
deterministic in the SQL Editor transaction.

The verification script is assertion-based, not a report-only query: it
requires exactly 40 application tables, RLS on all 40, 40 service-role
policies, 40 explicit backend-role policies (31 membership-bound and 9
backend-only), 15 named integrity triggers, four restricted `SECURITY
DEFINER` membership helpers, and the single Alembic revision
`0016_phase6_governance`. It checks the actual `chinescan_backend` role's
grants and rejects execution under a superuser, `BYPASSRLS` role, or
table-owning backend role because those roles would make database-enforced
tenant isolation ineffective.

The application uses a custom session/membership model, not Supabase Auth.
Browser roles receive no application-table grants. The backend must establish
the existing session and membership first, then set transaction-local
`chinescan.user_id` and `chinescan.organization_id`; the adapter does this on
each PostgreSQL transaction. The direct PostgreSQL role must be
`chinescan_backend`, and the adapter does not impersonate Supabase's
`service_role`. `service_role` is a Supabase API role and must not be
confused with the direct database login. The adapter verifies the actual
role, its grants, its policies, and its non-owner/non-BYPASSRLS attributes.
Do not expose the database URL or service-role key to Vercel.

The first application superuser is not a PostgreSQL role, Supabase project
owner, or `service_role`. It is a row in `users` with
`platform_role = 'superuser'`, an active owner membership in the dedicated
administration organization, and credentials established only through the
one-time setup token. Ordinary signup and organization membership operations
cannot assign `platform_role = 'superuser'`.

## Recovery and rollback

This baseline is intended for a new project and is not a reversible production
migration. It creates the application schema, policies, functions, and
triggers. If verification fails, stop, retain the SQL Editor error and
database state, and do not run ad hoc DROP statements. On an empty disposable
project, the project can be reset through the Supabase administrative workflow
after review. On a project containing data, restore from a verified Supabase
backup or use a reviewed forward migration; do not delete tables to force a
rerun.

No evidence files are migrated by this package. ChineScan continues using its
Oracle-local content-addressed evidence directories until a separately tested
private object-storage adapter exists.
