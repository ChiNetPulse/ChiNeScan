# Supabase integration status

This directory is local CLI scaffolding and a reviewed PostgreSQL baseline
generated from the existing SQLAlchemy metadata. It is not linked to a remote
project and contains no production credentials.

The migration is not a claim of remote deployment. It creates the current
application tables, indexes, foreign keys, service-role policies, organization
membership helpers, and PostgreSQL translations of the reviewed SQLite
immutability, provenance, state-transition, and append-only guards. Browser
roles are denied application-table access. Organization policies are safe only
when the backend sets the two transaction-local `chinescan.*` identity values
after authenticating the existing session; no browser role is granted direct
table access.

The policy SQL is statically reviewed but has not yet been executed against a
PostgreSQL server in this environment. Treat RLS and trigger behavior as
acceptance-pending until the disposable PostgreSQL suite passes.

The PostgreSQL adapter refuses to start unless this baseline is already
applied and the Alembic revision is `0016_phase6_governance`. It never falls
back to SQLite or silently runs an unreviewed migration chain.

Do not run `supabase db push` until the migration has been reviewed and the
remote project has been explicitly authorized.

When the PostgreSQL adapter and migration set are reviewed, link explicitly:

```text
supabase login
supabase link --project-ref <project-ref>
supabase db push
```

The project reference and all credentials must be supplied through the
operator environment. Never place them in this repository.
