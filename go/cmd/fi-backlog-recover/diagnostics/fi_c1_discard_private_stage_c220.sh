#!/bin/sh
# One-time C220 discard of the ABANDONED FI C1 private development stage.
# No replay, no preservation of private rows, no canonical fi or custody edits.
# DROP TABLE / DROP SCHEMA use RESTRICT (NEVER CASCADE).
set -eu
umask 077
fail(){ printf 'C1 PRIVATE DISCARD STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  fail 'root on physical c220 required'
[ "$#" -eq 1 ] && [ "$1" = --apply ] ||
  fail 'usage: FI_C1_DISCARD_PRIVATE_STAGE_APPROVED=DROP_ABANDONED_C1_ONLY sh script --apply'
[ "$(printenv FI_C1_DISCARD_PRIVATE_STAGE_APPROVED 2>/dev/null || :)" = DROP_ABANDONED_C1_ONLY ] ||
  fail 'explicit private development stage discard approval required'
jls -j fi-sor jid >/dev/null 2>&1 || fail 'real fi-sor jail not running'
if jls -j fi-sor-db jid >/dev/null 2>&1; then
  fail 'ambiguous additional fi-sor-db jail running'
fi
if jexec fi-sor pgrep -f '/usr/local/sbin/fi-c1-sor-worker' >/dev/null 2>&1; then
  fail 'C1 SoR worker running'
fi
if jls -j fi-ingest jid >/dev/null 2>&1 &&
   jexec fi-ingest pgrep -f '/usr/local/sbin/fi-c1-ingest-worker' >/dev/null 2>&1; then
  fail 'C1 ingest worker running'
fi
sock=/var/db/fi/sor/run
jexec -U postgres fi-sor pg_isready -h "$sock" -p 5432 >/dev/null 2>&1 ||
  fail 'real PostgreSQL socket unavailable'
actual=$(jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
  -h "$sock" -p 5432 -d fi -c 'SHOW data_directory') ||
  fail 'cannot establish actual SoR cluster'
[ "$actual" = /var/db/fi/sor/postgres ] ||
  fail "unexpected SoR PGDATA: $actual"

echo '===== DISCARD ABANDONED PRIVATE C1 DEVELOPMENT STAGE ONLY ====='
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -A -F '|' \
  -h "$sock" -p 5432 -d fi <<'SQL'
BEGIN;
SET LOCAL lock_timeout='10s';
SET LOCAL statement_timeout='600s';
DO $guard$
DECLARE
  r_count bigint;
  g_count bigint;
  p_tables integer;
  l_tables integer;
  gen_count integer;
  own_gen_count integer;
  artifact_count integer;
  source_count integer;
  typed_count integer;
  typed_total bigint;
  sql_sessions integer;
  tables text;
BEGIN
  IF current_database()<>'fi' OR current_user<>'postgres'
     OR pg_is_in_recovery()
     OR current_setting('data_directory')<>'/var/db/fi/sor/postgres'
     OR current_setting('server_version_num')::integer < 180000
     OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user)
  THEN RAISE EXCEPTION 'C1 discard: unexpected database, user, cluster or version';
  END IF;
  SELECT count(*) INTO g_count FROM fi.recorded_generation;
  SELECT count(*) INTO r_count FROM fi.source_record;
  IF g_count<>6249 OR r_count<>54114023 THEN
    RAISE EXCEPTION 'C1 discard: canonical FI baseline changed generations=% records=%',g_count,r_count;
  END IF;
  IF EXISTS (
    SELECT 1 FROM fi.recorded_generation
    WHERE source_id='iss-fs-22a.iss.local'
      AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
  ) THEN RAISE EXCEPTION 'C1 discard: target generation already canonical';
  END IF;
  SELECT count(*) INTO sql_sessions FROM pg_stat_activity
  WHERE datname='fi' AND pid<>pg_backend_pid()
    AND (usename='fi_ingest' OR application_name LIKE 'fi-c1%');
  IF sql_sessions<>0 THEN
    RAISE EXCEPTION 'C1 discard: concurrent C1 SQL connections=%',sql_sessions;
  END IF;
  SELECT count(*) INTO p_tables
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='fi_recovery_projection' AND c.relkind IN ('r','p');
  SELECT count(*) INTO l_tables
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='fi_recovery' AND c.relkind IN ('r','p');
  IF p_tables<>49 OR l_tables<>4 OR
     to_regclass('fi_recovery.verified_artifact_window') IS NULL OR
     to_regclass('fi_recovery.pending_source_record') IS NULL OR
     to_regclass('fi_recovery.source_window') IS NULL OR
     to_regclass('fi_recovery.typed_window') IS NULL
  THEN RAISE EXCEPTION 'C1 discard: private stage differs from observed 49+4 tables';
  END IF;
  SELECT count(*),count(*) FILTER (
    WHERE source_id='iss-fs-22a.iss.local'
      AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
      AND record_count=15140785
  ) INTO gen_count,own_gen_count
  FROM fi_recovery_projection.recorded_generation;
  IF gen_count<>1 OR own_gen_count<>1 THEN
    RAISE EXCEPTION 'C1 discard: unrelated or changed private generation';
  END IF;
  SELECT count(*) INTO artifact_count FROM fi_recovery.verified_artifact_window;
  SELECT count(*) INTO source_count FROM fi_recovery.source_window;
  SELECT count(*),coalesce(sum(committed_records),0)
    INTO typed_count,typed_total FROM fi_recovery.typed_window;
  IF artifact_count<>89 OR source_count<>88 OR typed_count<>88 OR typed_total<>2770101 THEN
    RAISE EXCEPTION 'C1 discard: private marker baseline changed a=% s=% t=% records=%',
      artifact_count,source_count,typed_count,typed_total;
  END IF;
  -- Drop ALL private tables in one command. RESTRICT refuses external FK
  -- and view dependencies. No CASCADE or canonical-schema DDL allowed.
  SELECT string_agg(format('%I.%I',n.nspname,c.relname),', ' ORDER BY n.nspname,c.relname)
  INTO tables FROM pg_class c
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname IN ('fi_recovery_projection','fi_recovery')
    AND c.relkind IN ('r','p');
  IF tables IS NULL THEN RAISE EXCEPTION 'C1 discard: no private tables'; END IF;
  EXECUTE 'DROP TABLE ' || tables || ' RESTRICT';
END
$guard$;
-- An unrecognized remaining private object forces rollback, never CASCADE.
DROP SCHEMA fi_recovery_projection RESTRICT;
DROP SCHEMA fi_recovery RESTRICT;
DO $proof$
DECLARE r_count bigint; g_count bigint; f_tables integer;
BEGIN
  IF to_regnamespace('fi_recovery_projection') IS NOT NULL OR
     to_regnamespace('fi_recovery') IS NOT NULL THEN
    RAISE EXCEPTION 'C1 discard: private schemas remain';
  END IF;
  SELECT count(*) INTO g_count FROM fi.recorded_generation;
  SELECT count(*) INTO r_count FROM fi.source_record;
  SELECT count(*) INTO f_tables
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='fi' AND c.relkind IN ('r','p');
  IF g_count<>6249 OR r_count<>54114023 OR f_tables<>49 THEN
    RAISE EXCEPTION 'C1 discard: canonical FI changed unexpectedly';
  END IF;
END
$proof$;
COMMIT;
SELECT 'C1_PRIVATE_STAGE_ABSENT' AS section,
       to_regnamespace('fi_recovery_projection') IS NULL AND
       to_regnamespace('fi_recovery') IS NULL AS removed;
SQL
echo 'FI C1 private development stage removed; canonical FI and signed custody remain.'
