-- Apply this to an existing live Supabase database when the initial
-- bootstrap token expired before activation and a fresh token is needed.
--
-- Prerequisites: the baseline migration (20261127000000_chinescan_baseline.sql)
-- has already been applied, and the chinescan_backend role exists.
--
-- Run as the Supabase project owner (postgres role) in the SQL Editor.
-- Do NOT run this as chinescan_backend.

CREATE OR REPLACE FUNCTION public.chinescan_reissue_first_superuser_token(
  p_email      text,
  p_token_hash text,
  p_expires_at double precision
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  selected_user_id text;
  stamp            text := clock_timestamp()::text;
BEGIN
  IF lower(trim(p_email)) <> 'cipherchi@proton.me' THEN
    RAISE EXCEPTION 'token reissue is restricted to the fixed first-superuser email';
  END IF;
  IF p_token_hash IS NULL OR length(p_token_hash) <> 64
     OR p_expires_at <= extract(epoch FROM clock_timestamp()) THEN
    RAISE EXCEPTION 'reissue bootstrap material is invalid';
  END IF;
  -- The account must exist with no password set and no prior token consumption.
  -- FOR UPDATE prevents concurrent reissue races.
  SELECT account.id INTO selected_user_id
    FROM public.users account
    JOIN public.user_credentials credential ON credential.user_id = account.id
   WHERE account.email_normalized = 'cipherchi@proton.me'
     AND account.platform_role   = 'superuser'
     AND account.status          = 'active'
     AND credential.password_hash       IS NULL
     AND credential.bootstrap_used_at   IS NULL
   FOR UPDATE;
  IF selected_user_id IS NULL THEN
    RAISE EXCEPTION 'no eligible unactivated first-superuser account found; reissue is not permitted';
  END IF;
  -- Atomically replace only the expired token hash and expiry.
  UPDATE public.user_credentials
     SET bootstrap_token_hash  = p_token_hash,
         bootstrap_expires_at  = p_expires_at,
         updated_at            = stamp
   WHERE user_id = selected_user_id;
  RETURN selected_user_id;
END
$$;

REVOKE ALL ON FUNCTION public.chinescan_reissue_first_superuser_token(text, text, double precision)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.chinescan_reissue_first_superuser_token(text, text, double precision)
  TO chinescan_backend;
