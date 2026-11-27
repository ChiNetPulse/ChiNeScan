-- ChineScan Supabase baseline verification.
-- Run after creating the chinescan_backend role and applying:
--   supabase/migrations/20261127000000_chinescan_baseline.sql
--
-- Execute this using the same chinescan_backend connection configured in
-- CHINESCAN_DATABASE_URL. Assertions are fail-closed and the transaction is
-- rolled back. No persistent test data is created.

BEGIN;
SET LOCAL search_path = public;

DO $$
DECLARE
  expected_tables text[] := ARRAY[
    'auth_lockouts', 'organization_bootstrap_reports', 'records', 'users',
    'worker_leases', 'organizations', 'user_credentials', 'user_recovery_codes',
    'user_sessions', 'clients', 'legal_holds', 'log_evidence_quota_reservations',
    'malware_evidence_quota_reservations', 'organization_audit_events',
    'organization_invitations', 'organization_memberships',
    'repository_quota_reservations', 'repository_snapshots', 'retention_audit_events',
    'retention_jobs', 'engagements', 'legal_hold_records', 'assessment_audit_events',
    'engagement_assets', 'engagement_assignments', 'record_ownership',
    'retention_policies', 'scope_revisions', 'authorization_records',
    'log_evidence_snapshots', 'malware_evidence_snapshots', 'repository_asset_bindings',
    'scope_rules', 'approval_requests', 'authorization_documents',
    'repository_attestations', 'execution_jobs', 'execution_action_attempts',
    'execution_capability_snapshots', 'execution_result_provenance'
  ];
  actual_count integer;
  unexpected_count integer;
  missing_count integer;
  rls_count integer;
  service_policy_count integer;
  backend_policy_count integer;
  member_policy_count integer;
  backend_only_policy_count integer;
  trigger_count integer;
  helper_count integer;
  bootstrap_function_count integer;
  role_bypasses_rls boolean;
  role_can_login boolean;
  role_is_superuser boolean;
  role_can_create_role boolean;
  owned_table_count integer;
  missing_privilege_count integer;
  missing_helper_grant_count integer;
  table_name text;
  privilege text;
BEGIN
  IF current_user <> 'chinescan_backend' THEN
    RAISE EXCEPTION 'verification must run as chinescan_backend, current role is %', current_user;
  END IF;
  SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole
    INTO role_can_login, role_is_superuser, role_bypasses_rls, role_can_create_role
    FROM pg_roles WHERE rolname = current_user;
  IF NOT role_can_login OR role_is_superuser OR role_bypasses_rls OR role_can_create_role THEN
    RAISE EXCEPTION 'chinescan_backend must be LOGIN, NOSUPERUSER, NOBYPASSRLS, NOCREATEROLE';
  END IF;

  IF cardinality(expected_tables) <> 40 THEN
    RAISE EXCEPTION 'verification script defect: expected table list contains % entries', cardinality(expected_tables);
  END IF;
  SELECT count(*) INTO actual_count
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY(expected_tables);
  IF actual_count <> 40 THEN RAISE EXCEPTION 'expected exactly 40 application tables, found %', actual_count; END IF;
  SELECT count(*) INTO unexpected_count
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind = 'r'
     AND c.relname <> 'alembic_version' AND NOT (c.relname = ANY(expected_tables));
  IF unexpected_count <> 0 THEN RAISE EXCEPTION 'unexpected public application tables: %', unexpected_count; END IF;
  SELECT count(*) INTO missing_count
    FROM unnest(expected_tables) expected(name)
   WHERE NOT EXISTS (
     SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = expected.name
   );
  IF missing_count <> 0 THEN RAISE EXCEPTION 'missing expected application tables: %', missing_count; END IF;

  SELECT count(*) INTO rls_count
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY(expected_tables)
     AND c.relrowsecurity;
  IF rls_count <> 40 THEN RAISE EXCEPTION 'all 40 application tables must have RLS enabled; enabled=%', rls_count; END IF;
  IF (SELECT count(*) FROM public.alembic_version) <> 1
     OR (SELECT version_num FROM public.alembic_version LIMIT 1) <> '0016_phase6_governance' THEN
    RAISE EXCEPTION 'alembic_version must contain exactly 0016_phase6_governance';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE information_schema.columns.table_schema = 'public'
       AND information_schema.columns.table_name = 'users'
       AND information_schema.columns.column_name = 'platform_role'
  ) THEN
    RAISE EXCEPTION 'users.platform_role is required for platform superuser authorization';
  END IF;

  SELECT count(*) INTO service_policy_count FROM pg_policies
   WHERE schemaname = 'public' AND policyname LIKE '%\_service\_role' ESCAPE '\';
  IF service_policy_count <> 40 THEN RAISE EXCEPTION 'expected exactly 40 service-role policies, found %', service_policy_count; END IF;
  SELECT count(*) INTO backend_policy_count FROM pg_policies
   WHERE schemaname = 'public' AND policyname LIKE '%\_backend' ESCAPE '\'
     AND roles @> ARRAY['chinescan_backend'::name];
  IF backend_policy_count <> 40 THEN RAISE EXCEPTION 'expected exactly 40 backend-role policies, found %', backend_policy_count; END IF;
  SELECT count(*) INTO member_policy_count FROM pg_policies
   WHERE schemaname = 'public' AND policyname LIKE '%\_organization\_member\_backend' ESCAPE '\'
     AND roles @> ARRAY['chinescan_backend'::name];
  IF member_policy_count <> 31 THEN RAISE EXCEPTION 'expected exactly 31 organization membership policies, found %', member_policy_count; END IF;
  SELECT count(*) INTO backend_only_policy_count FROM pg_policies
   WHERE schemaname = 'public' AND policyname LIKE '%\_backend' ESCAPE '\'
     AND policyname NOT LIKE '%\_organization\_member\_backend' ESCAPE '\'
     AND roles @> ARRAY['chinescan_backend'::name];
  IF backend_only_policy_count <> 9 THEN RAISE EXCEPTION 'expected exactly 9 non-organization backend policies, found %', backend_only_policy_count; END IF;

  FOREACH table_name IN ARRAY expected_tables LOOP
    FOREACH privilege IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] LOOP
      IF NOT has_table_privilege(current_user, format('public.%I', table_name), privilege) THEN
        missing_privilege_count := COALESCE(missing_privilege_count, 0) + 1;
      END IF;
      IF has_table_privilege('anon', format('public.%I', table_name), privilege)
         OR has_table_privilege('authenticated', format('public.%I', table_name), privilege) THEN
        RAISE EXCEPTION 'browser role has % privilege on public.%', privilege, table_name;
      END IF;
    END LOOP;
  END LOOP;
  IF COALESCE(missing_privilege_count, 0) <> 0 THEN
    RAISE EXCEPTION 'backend role is missing % required table privileges', missing_privilege_count;
  END IF;

  SELECT count(*) INTO owned_table_count
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY(expected_tables)
     AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user);
  IF owned_table_count <> 0 THEN RAISE EXCEPTION 'backend role owns % application tables', owned_table_count; END IF;

  SELECT
    CASE WHEN has_function_privilege(current_user, 'public.chinescan_current_user_id()', 'EXECUTE') THEN 0 ELSE 1 END
    + CASE WHEN has_function_privilege(current_user, 'public.chinescan_current_organization_id()', 'EXECUTE') THEN 0 ELSE 1 END
    + CASE WHEN has_function_privilege(current_user, 'public.chinescan_is_org_member(text)', 'EXECUTE') THEN 0 ELSE 1 END
    + CASE WHEN has_function_privilege(current_user, 'public.chinescan_is_org_admin(text)', 'EXECUTE') THEN 0 ELSE 1 END
    INTO missing_helper_grant_count;
  IF missing_helper_grant_count <> 0 THEN RAISE EXCEPTION 'backend role is missing % helper EXECUTE grants', missing_helper_grant_count; END IF;

  SELECT count(*) INTO trigger_count
    FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
   WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace
     AND t.tgname = ANY(ARRAY[
       'execution_job_guard', 'execution_job_auth_document_guard', 'execution_action_attempt_guard',
       'execution_job_state_guard', 'organization_audit_events_append_only',
       'assessment_audit_events_append_only', 'retention_audit_events_append_only',
       'execution_result_provenance_guard', 'log_evidence_snapshot_guard',
       'malware_evidence_snapshot_guard', 'repository_asset_bindings_append_only',
       'repository_attestations_append_only', 'repository_snapshot_metadata_guard',
       'scope_revision_published_guard', 'scope_rule_published_guard'
     ]);
  IF trigger_count <> 15 THEN RAISE EXCEPTION 'expected 15 named integrity triggers, found %', trigger_count; END IF;

  SELECT count(*) INTO helper_count
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND p.proname = ANY(ARRAY[
       'chinescan_current_user_id', 'chinescan_current_organization_id',
       'chinescan_is_org_member', 'chinescan_is_org_admin'
     ])
     AND p.prosecdef AND p.proconfig @> ARRAY['search_path=public, pg_temp'];
  IF helper_count <> 4 THEN RAISE EXCEPTION 'expected 4 restricted SECURITY DEFINER membership helpers, found %', helper_count; END IF;

  SELECT count(*) INTO bootstrap_function_count
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND p.proname IN (
       'chinescan_bootstrap_first_superuser',
       'chinescan_complete_first_superuser_setup'
     )
     AND p.prosecdef
     AND p.proconfig @> ARRAY['search_path=public, pg_temp'];
  IF bootstrap_function_count <> 2 THEN
    RAISE EXCEPTION 'expected two restricted SECURITY DEFINER first-superuser functions, found %', bootstrap_function_count;
  END IF;
  IF NOT has_function_privilege(
    current_user,
    'public.chinescan_bootstrap_first_superuser(text,text,text,text,double precision)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    current_user,
    'public.chinescan_complete_first_superuser_setup(text,text,text)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'backend role is missing first-superuser function EXECUTE privileges';
  END IF;
  IF has_function_privilege('anon', 'public.chinescan_bootstrap_first_superuser(text,text,text,text,double precision)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'public.chinescan_bootstrap_first_superuser(text,text,text,text,double precision)', 'EXECUTE')
     OR has_function_privilege('service_role', 'public.chinescan_bootstrap_first_superuser(text,text,text,text,double precision)', 'EXECUTE')
     OR has_function_privilege('anon', 'public.chinescan_complete_first_superuser_setup(text,text,text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'public.chinescan_complete_first_superuser_setup(text,text,text)', 'EXECUTE')
     OR has_function_privilege('service_role', 'public.chinescan_complete_first_superuser_setup(text,text,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'browser or service roles must not execute first-superuser bootstrap functions';
  END IF;
END $$;

-- Real cross-organization behavior and draft/published trigger behavior are
-- exercised by tests/integration/test_postgres_backend.py with fixture IDs.
-- Those tests use this same role, transaction-local identity binding, and
-- rollback-only transactions; this SQL file intentionally creates no fixtures.
SELECT current_user AS backend_role,
       current_setting('chinescan.user_id', true) AS bound_user,
       current_setting('chinescan.organization_id', true) AS bound_organization;

ROLLBACK;
