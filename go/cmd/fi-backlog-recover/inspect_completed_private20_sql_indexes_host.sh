#!/bin/sh
# FI POST-RUN ONLY: inspect retained relation statistics in the verified
# W3-W22 private PostgreSQL clone without replaying signed records.
#
# This script runs on fi-backend-b as root. It only starts the specifically
# pinned, cleanly stopped fi-dev clone with localhost-disabled sockets,
# autovacuum disabled FOR INSPECTION, and read-only SQL by default. The
# source of record, 911 systems, seed database, and active branch are not used.
# PostgreSQL startup/shutdown may write internal server files; this is SQL-
# read-only inspection, not a forensic bit-for-bit read-only disk mount.
set -eu
umask 077

fail() { printf 'FI POSTRUN STOP: %s\n' "$*" >&2; exit 1; }

[ "$(id -un)" = root ] || fail 'run as root on fi-backend-b'
for command in jexec jls ps awk grep cat date mkdir wc tar; do
    command -v "$command" >/dev/null 2>&1 || fail "missing $command"
done

name=clone-11-08-26
ref=b01ff0d8cb6559797de052f34b18bd84a395dc4c
root=/home/jwood/fi-window-bench-optfield-v20-c-20261110T103933Z
out=/var/tmp/fi-window-chunks-v20-c-20261110T103933Z
cluster="$root/$name"
socket="$cluster/socket"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
report="$out/postrun-sql-index-review-$stamp"
jailroot=$(jls -j fi-dev path) || fail 'fi-dev not running'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev JID unavailable'
sorjid=$(jls -j fi-sor-db jid) || fail 'SoR JID unavailable'
[ "$devjid" != "$sorjid" ] || fail 'fi-dev and SoR have matching JIDs'
[ -f "$jailroot$root/SOURCE_COMMIT" ] || fail 'original pinned source manifest absent'
[ "$(cat "$jailroot$root/SOURCE_COMMIT")" = "$ref" ] || fail 'unexpected private source commit'
[ -d "$jailroot$cluster/data" ] && [ -d "$jailroot$socket" ] ||
    fail 'original stopped private PostgreSQL data/socket missing'
[ ! -L "$jailroot$root" ] && [ ! -L "$jailroot$cluster" ] &&
    [ ! -L "$jailroot$cluster/data" ] && [ ! -L "$jailroot$socket" ] ||
    fail 'private PostgreSQL path contains a symlink'
[ -f "$out/RUN_MANIFEST.txt" ] && [ -f "$out/SUMMARY.txt" ] ||
    fail 'original completed run manifest/summary missing'
grep -Fq "source_commit=$ref" "$out/RUN_MANIFEST.txt" ||
    fail 'source commit does not match completed run'
grep -Fq 'FI VACUUM CANDIDATE20 RECOVERED ' "$out/SUMMARY.txt" ||
    fail 'completed signed W3-W22 recovery acceptance missing'
[ ! -e "$report" ] || fail 'review output directory already exists'
[ "${#socket}" -le 88 ] || fail 'unexpected PostgreSQL socket path length'

existing=$(ps -axww -o pid,jid,user,rss,command | awk -v jid="$devjid" '
    $2 == jid && $5 == "/usr/local/bin/postgres" && $6 == "-D" { n++ }
    END { print n + 0 }
')
[ "$existing" -eq 0 ] ||
    fail "$existing PostgreSQL postmasters already running in fi-dev"
jexec -U jwood fi-dev pg_ctl -D "$cluster/data" status >/dev/null 2>&1 &&
    fail 'private clone is already running'

mkdir -m 700 "$report" || fail 'cannot create report directory'
started=0
cleanup() {
    code=$?
    trap - 0 1 2 15
    if [ "$started" -eq 1 ]; then
        printf 'FI POSTRUN CLEANUP stopping retained clone\n'
        jexec -U jwood fi-dev pg_ctl -D "$cluster/data" -m fast -w -t 60 stop ||
            code=1
    fi
    printf 'FI POSTRUN FINISHED exit=%s report=%s\n' "$code" "$report"
    exit "$code"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15

# Mark started before pg_ctl: trap attempts cleanup even on partial start.
started=1
jexec -U jwood fi-dev pg_ctl -D "$cluster/data" \
    -l "$cluster/postrun-inspection-$stamp.log" \
    -o "-p 55981 -k $socket -c listen_addresses= -c unix_socket_permissions=0700 -c autovacuum=off -c default_transaction_read_only=on" \
    -w start || fail 'private PostgreSQL postrun start failed'

# All sessions connect solely to a private Unix socket. No user password,
# application token, SQL mutations, or public database connection is needed.
sql() {
    jexec -U jwood fi-dev psql \
        "host=$socket port=55981 user=fi_m1_admin dbname=fi sslmode=disable" \
        -X -qAt -v ON_ERROR_STOP=1 -P pager=off -c "$1"
}
run_sql() {
    jexec -U jwood fi-dev psql \
        "host=$socket port=55981 user=fi_m1_admin dbname=fi sslmode=disable" \
        -X -qAt -v ON_ERROR_STOP=1 -P pager=off
}

[ "$(sql "SHOW autovacuum")" = off ] || fail 'autovacuum is not disabled for inspection'
[ "$(sql "SHOW default_transaction_read_only")" = on ] ||
    fail 'SQL is not read-only for inspection'
state=$(sql "SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window")
[ "$state" = '23|2988103|22' ] || fail "retained clone has unexpected durable source state $state"
authoritative=$(sql "SELECT (SELECT count(*) FROM fi.recorded_generation) + (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')")
[ "$authoritative" = 0 ] || fail 'unexpected authoritative/Accepted records in clone'

printf 'FI POSTRUN CLONE VERIFIED source=%s checkpoint=%s SQL=read-only auto_vacuum=off\n' "$ref" "$state" |
    tee "$report/VERIFICATION.txt"

# PostgreSQL 18 cumulative counters persist across a clean shutdown, but the
# post-run snapshots can include setup/restore and restart activity. Expose
# stats_reset and totals so these are not mistaken for precise W3-W22 deltas.
run_sql > "$report/STATISTICS_IDENTITY.jsonl" <<'SQL'
SELECT row_to_json(x)::text
FROM (
    SELECT clock_timestamp() AS inspected_utc, current_database() AS database,
           pg_postmaster_start_time() AS server_started,
           d.stats_reset AS database_stats_reset,
           w.stats_reset AS wal_stats_reset,
           w.wal_records, w.wal_bytes, w.wal_buffers_full,
           current_setting('autovacuum') AS inspection_autovacuum,
           current_setting('transaction_read_only') AS sql_read_only
    FROM pg_stat_database d CROSS JOIN pg_stat_wal w
    WHERE d.datname=current_database()
) x;
SQL

# Preserve FI tables, child partitions AND their mapped TOAST relations.
# Do not sum parent pg_total_relation_size with its TOAST/partition sizes.
run_sql > "$report/RELATION_MAINTENANCE.jsonl" <<'SQL'
SELECT row_to_json(x)::text
FROM (
    SELECT s.schemaname AS schema, s.relname AS relation,
           s.relid::text AS relation_oid, c.relkind AS relation_kind,
           CASE WHEN owner.oid IS NOT NULL
                THEN ns.nspname || '.' || owner.relname END AS toast_owner,
           c.reloptions AS relation_options,
           s.seq_scan, s.idx_scan,
           s.n_tup_ins, s.n_tup_upd, s.n_tup_del,
           s.n_live_tup, s.n_dead_tup,
           s.n_mod_since_analyze, s.n_ins_since_vacuum,
           s.vacuum_count, s.autovacuum_count,
           s.analyze_count, s.autoanalyze_count,
           s.total_vacuum_time, s.total_autovacuum_time,
           s.total_analyze_time, s.total_autoanalyze_time,
           s.last_vacuum, s.last_autovacuum,
           s.last_analyze, s.last_autoanalyze,
           pg_relation_size(s.relid) AS heap_bytes,
           pg_indexes_size(s.relid) AS index_bytes,
           pg_total_relation_size(s.relid) AS relation_total_bytes
    FROM pg_stat_all_tables s
    JOIN pg_class c ON c.oid=s.relid
    LEFT JOIN pg_class owner ON owner.reltoastrelid=s.relid
    LEFT JOIN pg_namespace ns ON ns.oid=owner.relnamespace
    WHERE s.schemaname LIKE 'fi%'
       OR (s.schemaname='pg_toast' AND ns.nspname LIKE 'fi%')
    ORDER BY s.total_autovacuum_time DESC NULLS LAST,
             s.total_autoanalyze_time DESC NULLS LAST, s.n_tup_ins DESC
) x;
SQL

run_sql > "$report/FI_INDEXES.jsonl" <<'SQL'
SELECT row_to_json(x)::text
FROM (
    SELECT s.schemaname AS schema, s.relname AS relation,
           s.indexrelname AS index_name,
           s.idx_scan, s.idx_tup_read, s.idx_tup_fetch,
           pg_relation_size(s.indexrelid) AS index_bytes
    FROM pg_stat_user_indexes s
    WHERE s.schemaname LIKE 'fi%'
    ORDER BY pg_relation_size(s.indexrelid) DESC
) x;
SQL

# Inspect metadata only for the exact SQL relations implicated by the
# W3-W22 evidence; this does NOT time index insertion or remove constraints.
run_sql > "$report/TARGET_INDEX_DEFINITIONS.jsonl" <<'SQL'
SELECT row_to_json(q)::text FROM (
 SELECT n.nspname AS schema_name, t.relname AS table_name,
        i.relname AS index_name, pg_get_indexdef(i.oid) AS definition,
        pg_relation_size(i.oid) AS index_bytes,
        st.idx_scan,st.idx_tup_read,st.idx_tup_fetch,
        ix.indisunique,ix.indisprimary,ix.indisvalid,ix.indisready
 FROM pg_class t
 JOIN pg_namespace n ON n.oid=t.relnamespace
 JOIN pg_index ix ON ix.indrelid=t.oid
 JOIN pg_class i ON i.oid=ix.indexrelid
 LEFT JOIN pg_stat_all_indexes st ON st.indexrelid=ix.indexrelid
 WHERE n.nspname='fi_recovery_projection'
 AND (t.relname IN ('file_observation','file_metadata_observation',
   'content_hash_observation','windows_security_event','windows_security_event_field')
 OR t.relname ~ '^windows_security_event_field_w[0-9]{6} <<'SQL'
SELECT json_build_object(
    'pg_stat_database', (SELECT row_to_json(d) FROM pg_stat_database d WHERE d.datname=current_database()),
    'pg_stat_wal', (SELECT row_to_json(w) FROM pg_stat_wal w),
    'pg_stat_checkpointer', (SELECT row_to_json(c) FROM pg_stat_checkpointer c),
    'pg_stat_io', (SELECT json_agg(row_to_json(i)) FROM pg_stat_io i)
)::text;
SQL

run_sql > "$report/TOP_MAINTENANCE.csv" <<'SQL'
COPY (
    SELECT s.schemaname, s.relname,
           coalesce(ns.nspname || '.' || owner.relname,'') AS toast_owner,
           s.autovacuum_count,
           s.total_autovacuum_time AS autovacuum_ms,
           s.autoanalyze_count,
           s.total_autoanalyze_time AS autoanalyze_ms,
           s.n_tup_ins, s.n_dead_tup,
           pg_relation_size(s.relid) AS heap_bytes
    FROM pg_stat_all_tables s
    LEFT JOIN pg_class owner ON owner.reltoastrelid=s.relid
    LEFT JOIN pg_namespace ns ON ns.oid=owner.relnamespace
    WHERE s.schemaname LIKE 'fi%'
       OR (s.schemaname='pg_toast' AND ns.nspname LIKE 'fi%')
    ORDER BY s.total_autovacuum_time DESC NULLS LAST,
             s.total_autoanalyze_time DESC NULLS LAST
    LIMIT 75
) TO STDOUT WITH (FORMAT csv, HEADER true);
SQL

[ -s "$report/STATISTICS_IDENTITY.jsonl" ] &&
[ -s "$report/RELATION_MAINTENANCE.jsonl" ] &&
[ -s "$report/FI_INDEXES.jsonl" ] &&
[ -s "$report/PG_AFTER_RESTART.jsonl" ] &&
[ -s "$report/TOP_MAINTENANCE.csv" ] &&
[ -s "$report/TARGET_INDEX_DEFINITIONS.jsonl" ] &&
[ -s "$report/TARGET_CONSTRAINTS.jsonl" ] &&
[ -s "$report/TARGET_RELATION_SIZES.jsonl" ] ||
    fail 'postrun metrics collection incomplete'

cat > "$report/README.txt" <<'README'
FI W128 private replay post-run relation-level statistics, PostgreSQL 18.
The original W3-W22 signed replay and postrun acceptance completed.
A pinned clone was restarted with autovacuum=off and default_transaction_read_only=on.
This is SQL read-only inspection; PostgreSQL startup/shutdown can alter on-disk
metadata and tiny amounts of cumulative activity. No original SoR was touched.
Relations include fi_* schemas, child partitions and FI-owned pg_toast tables.
Relational and TOAST sizes can overlap: do not sum total relation size blindly.
Vacuum and analyze counters are CUMULATIVE since each statistic reset, possibly
including the original seed import and PostgreSQL restart.
No per-index INSERT CPU time or actual I/O wait time can be reconstructed.
This review complements the already captured pre/post pg_stat_io/WAL deltas.
README

bundle="$report/fi-postrun-sql-index-review-$stamp.tar.gz"
(
    cd "$report" || exit 1
    tar -czf "$bundle" README.txt VERIFICATION.txt \
        STATISTICS_IDENTITY.jsonl RELATION_MAINTENANCE.jsonl \
        FI_INDEXES.jsonl PG_AFTER_RESTART.jsonl TOP_MAINTENANCE.csv \
        TARGET_INDEX_DEFINITIONS.jsonl TARGET_CONSTRAINTS.jsonl \
        TARGET_RELATION_SIZES.jsonl
) || fail 'postrun review bundle creation failed'
[ -s "$bundle" ] || fail 'postrun review bundle is empty'
printf 'FI POSTRUN SQL INDEX REVIEW PASS rows=%s package=%s\n' \
    "$(wc -l < "$report/RELATION_MAINTENANCE.jsonl" | tr -d ' ')" "$bundle"
)
 ORDER BY t.relname, pg_relation_size(i.oid) DESC,i.relname
) q;
SQL
run_sql > "$report/TARGET_CONSTRAINTS.jsonl" <<'SQL'
SELECT row_to_json(q)::text FROM (
 SELECT n.nspname AS schema_name, t.relname AS table_name,
        c.conname, c.contype,c.convalidated,
        pg_get_constraintdef(c.oid,true) AS definition,
        CASE WHEN c.confrelid<>0 THEN c.confrelid::regclass::text END AS referenced_relation
 FROM pg_constraint c
 JOIN pg_class t ON t.oid=c.conrelid
 JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE n.nspname='fi_recovery_projection'
 AND (t.relname IN ('content_hash_observation','file_observation',
      'windows_security_event','windows_security_event_field')
 OR t.relname ~ '^windows_security_event_field_w[0-9]{6} <<'SQL'
SELECT json_build_object(
    'pg_stat_database', (SELECT row_to_json(d) FROM pg_stat_database d WHERE d.datname=current_database()),
    'pg_stat_wal', (SELECT row_to_json(w) FROM pg_stat_wal w),
    'pg_stat_checkpointer', (SELECT row_to_json(c) FROM pg_stat_checkpointer c),
    'pg_stat_io', (SELECT json_agg(row_to_json(i)) FROM pg_stat_io i)
)::text;
SQL

run_sql > "$report/TOP_MAINTENANCE.csv" <<'SQL'
COPY (
    SELECT s.schemaname, s.relname,
           coalesce(ns.nspname || '.' || owner.relname,'') AS toast_owner,
           s.autovacuum_count,
           s.total_autovacuum_time AS autovacuum_ms,
           s.autoanalyze_count,
           s.total_autoanalyze_time AS autoanalyze_ms,
           s.n_tup_ins, s.n_dead_tup,
           pg_relation_size(s.relid) AS heap_bytes
    FROM pg_stat_all_tables s
    LEFT JOIN pg_class owner ON owner.reltoastrelid=s.relid
    LEFT JOIN pg_namespace ns ON ns.oid=owner.relnamespace
    WHERE s.schemaname LIKE 'fi%'
       OR (s.schemaname='pg_toast' AND ns.nspname LIKE 'fi%')
    ORDER BY s.total_autovacuum_time DESC NULLS LAST,
             s.total_autoanalyze_time DESC NULLS LAST
    LIMIT 75
) TO STDOUT WITH (FORMAT csv, HEADER true);
SQL

[ -s "$report/STATISTICS_IDENTITY.jsonl" ] &&
[ -s "$report/RELATION_MAINTENANCE.jsonl" ] &&
[ -s "$report/FI_INDEXES.jsonl" ] &&
[ -s "$report/PG_AFTER_RESTART.jsonl" ] &&
[ -s "$report/TOP_MAINTENANCE.csv" ] ||
    fail 'postrun metrics collection incomplete'

cat > "$report/README.txt" <<'README'
FI W128 private replay post-run relation-level statistics, PostgreSQL 18.
The original W3-W22 signed replay and postrun acceptance completed.
A pinned clone was restarted with autovacuum=off and default_transaction_read_only=on.
This is SQL read-only inspection; PostgreSQL startup/shutdown can alter on-disk
metadata and tiny amounts of cumulative activity. No original SoR was touched.
Relations include fi_* schemas, child partitions and FI-owned pg_toast tables.
Relational and TOAST sizes can overlap: do not sum total relation size blindly.
Vacuum and analyze counters are CUMULATIVE since each statistic reset, possibly
including the original seed import and PostgreSQL restart.
No per-window vacuum timing or actual I/O wait time can be recreated now.
This review complements the already captured pre/post pg_stat_io/WAL deltas.
README

bundle="$report/fi-postrun-sql-index-review-$stamp.tar.gz"
(
    cd "$report" || exit 1
    tar -czf "$bundle" README.txt VERIFICATION.txt \
        STATISTICS_IDENTITY.jsonl RELATION_MAINTENANCE.jsonl \
        FI_INDEXES.jsonl PG_AFTER_RESTART.jsonl TOP_MAINTENANCE.csv
) || fail 'postrun review bundle creation failed'
[ -s "$bundle" ] || fail 'postrun review bundle is empty'
printf 'FI POSTRUN SQL INDEX REVIEW PASS rows=%s package=%s\n' \
    "$(wc -l < "$report/RELATION_MAINTENANCE.jsonl" | tr -d ' ')" "$bundle"
)
 ORDER BY t.relname,c.conname
) q;
SQL
run_sql > "$report/TARGET_RELATION_SIZES.jsonl" <<'SQL'
SELECT row_to_json(q)::text FROM (
 SELECT n.nspname AS schema_name,t.relname AS table_name,
        t.reltuples::bigint AS planner_estimated_tuples,t.relpages,
        pg_relation_size(t.oid) AS heap_bytes,
        pg_indexes_size(t.oid) AS index_bytes,
        pg_total_relation_size(t.oid) AS total_bytes,
        s.n_tup_ins,s.n_live_tup,s.n_dead_tup,
        s.autovacuum_count,s.autoanalyze_count,
        s.total_autovacuum_time,s.total_autoanalyze_time
 FROM pg_class t
 JOIN pg_namespace n ON n.oid=t.relnamespace
 LEFT JOIN pg_stat_all_tables s ON s.relid=t.oid
 WHERE n.nspname='fi_recovery_projection'
 AND (t.relname IN ('content_hash_observation','file_observation',
     'file_metadata_observation','windows_security_event',
     'windows_security_event_field')
 OR t.relname ~ '^windows_security_event_field_w[0-9]{6} <<'SQL'
SELECT json_build_object(
    'pg_stat_database', (SELECT row_to_json(d) FROM pg_stat_database d WHERE d.datname=current_database()),
    'pg_stat_wal', (SELECT row_to_json(w) FROM pg_stat_wal w),
    'pg_stat_checkpointer', (SELECT row_to_json(c) FROM pg_stat_checkpointer c),
    'pg_stat_io', (SELECT json_agg(row_to_json(i)) FROM pg_stat_io i)
)::text;
SQL

run_sql > "$report/TOP_MAINTENANCE.csv" <<'SQL'
COPY (
    SELECT s.schemaname, s.relname,
           coalesce(ns.nspname || '.' || owner.relname,'') AS toast_owner,
           s.autovacuum_count,
           s.total_autovacuum_time AS autovacuum_ms,
           s.autoanalyze_count,
           s.total_autoanalyze_time AS autoanalyze_ms,
           s.n_tup_ins, s.n_dead_tup,
           pg_relation_size(s.relid) AS heap_bytes
    FROM pg_stat_all_tables s
    LEFT JOIN pg_class owner ON owner.reltoastrelid=s.relid
    LEFT JOIN pg_namespace ns ON ns.oid=owner.relnamespace
    WHERE s.schemaname LIKE 'fi%'
       OR (s.schemaname='pg_toast' AND ns.nspname LIKE 'fi%')
    ORDER BY s.total_autovacuum_time DESC NULLS LAST,
             s.total_autoanalyze_time DESC NULLS LAST
    LIMIT 75
) TO STDOUT WITH (FORMAT csv, HEADER true);
SQL

[ -s "$report/STATISTICS_IDENTITY.jsonl" ] &&
[ -s "$report/RELATION_MAINTENANCE.jsonl" ] &&
[ -s "$report/FI_INDEXES.jsonl" ] &&
[ -s "$report/PG_AFTER_RESTART.jsonl" ] &&
[ -s "$report/TOP_MAINTENANCE.csv" ] ||
    fail 'postrun metrics collection incomplete'

cat > "$report/README.txt" <<'README'
FI W128 private replay post-run relation-level statistics, PostgreSQL 18.
The original W3-W22 signed replay and postrun acceptance completed.
A pinned clone was restarted with autovacuum=off and default_transaction_read_only=on.
This is SQL read-only inspection; PostgreSQL startup/shutdown can alter on-disk
metadata and tiny amounts of cumulative activity. No original SoR was touched.
Relations include fi_* schemas, child partitions and FI-owned pg_toast tables.
Relational and TOAST sizes can overlap: do not sum total relation size blindly.
Vacuum and analyze counters are CUMULATIVE since each statistic reset, possibly
including the original seed import and PostgreSQL restart.
No per-window vacuum timing or actual I/O wait time can be recreated now.
This review complements the already captured pre/post pg_stat_io/WAL deltas.
README

bundle="$report/fi-postrun-sql-index-review-$stamp.tar.gz"
(
    cd "$report" || exit 1
    tar -czf "$bundle" README.txt VERIFICATION.txt \
        STATISTICS_IDENTITY.jsonl RELATION_MAINTENANCE.jsonl \
        FI_INDEXES.jsonl PG_AFTER_RESTART.jsonl TOP_MAINTENANCE.csv
) || fail 'postrun review bundle creation failed'
[ -s "$bundle" ] || fail 'postrun review bundle is empty'
printf 'FI POSTRUN SQL INDEX REVIEW PASS rows=%s package=%s\n' \
    "$(wc -l < "$report/RELATION_MAINTENANCE.jsonl" | tr -d ' ')" "$bundle"
)
 ORDER BY pg_total_relation_size(t.oid) DESC,t.relname
) q;
SQL

run_sql > "$report/PG_AFTER_RESTART.jsonl" <<'SQL'
SELECT json_build_object(
    'pg_stat_database', (SELECT row_to_json(d) FROM pg_stat_database d WHERE d.datname=current_database()),
    'pg_stat_wal', (SELECT row_to_json(w) FROM pg_stat_wal w),
    'pg_stat_checkpointer', (SELECT row_to_json(c) FROM pg_stat_checkpointer c),
    'pg_stat_io', (SELECT json_agg(row_to_json(i)) FROM pg_stat_io i)
)::text;
SQL

run_sql > "$report/TOP_MAINTENANCE.csv" <<'SQL'
COPY (
    SELECT s.schemaname, s.relname,
           coalesce(ns.nspname || '.' || owner.relname,'') AS toast_owner,
           s.autovacuum_count,
           s.total_autovacuum_time AS autovacuum_ms,
           s.autoanalyze_count,
           s.total_autoanalyze_time AS autoanalyze_ms,
           s.n_tup_ins, s.n_dead_tup,
           pg_relation_size(s.relid) AS heap_bytes
    FROM pg_stat_all_tables s
    LEFT JOIN pg_class owner ON owner.reltoastrelid=s.relid
    LEFT JOIN pg_namespace ns ON ns.oid=owner.relnamespace
    WHERE s.schemaname LIKE 'fi%'
       OR (s.schemaname='pg_toast' AND ns.nspname LIKE 'fi%')
    ORDER BY s.total_autovacuum_time DESC NULLS LAST,
             s.total_autoanalyze_time DESC NULLS LAST
    LIMIT 75
) TO STDOUT WITH (FORMAT csv, HEADER true);
SQL

[ -s "$report/STATISTICS_IDENTITY.jsonl" ] &&
[ -s "$report/RELATION_MAINTENANCE.jsonl" ] &&
[ -s "$report/FI_INDEXES.jsonl" ] &&
[ -s "$report/PG_AFTER_RESTART.jsonl" ] &&
[ -s "$report/TOP_MAINTENANCE.csv" ] ||
    fail 'postrun metrics collection incomplete'

cat > "$report/README.txt" <<'README'
FI W128 private replay post-run relation-level statistics, PostgreSQL 18.
The original W3-W22 signed replay and postrun acceptance completed.
A pinned clone was restarted with autovacuum=off and default_transaction_read_only=on.
This is SQL read-only inspection; PostgreSQL startup/shutdown can alter on-disk
metadata and tiny amounts of cumulative activity. No original SoR was touched.
Relations include fi_* schemas, child partitions and FI-owned pg_toast tables.
Relational and TOAST sizes can overlap: do not sum total relation size blindly.
Vacuum and analyze counters are CUMULATIVE since each statistic reset, possibly
including the original seed import and PostgreSQL restart.
No per-window vacuum timing or actual I/O wait time can be recreated now.
This review complements the already captured pre/post pg_stat_io/WAL deltas.
README

bundle="$report/fi-postrun-sql-index-review-$stamp.tar.gz"
(
    cd "$report" || exit 1
    tar -czf "$bundle" README.txt VERIFICATION.txt \
        STATISTICS_IDENTITY.jsonl RELATION_MAINTENANCE.jsonl \
        FI_INDEXES.jsonl PG_AFTER_RESTART.jsonl TOP_MAINTENANCE.csv
) || fail 'postrun review bundle creation failed'
[ -s "$bundle" ] || fail 'postrun review bundle is empty'
printf 'FI POSTRUN SQL INDEX REVIEW PASS rows=%s package=%s\n' \
    "$(wc -l < "$report/RELATION_MAINTENANCE.jsonl" | tr -d ' ')" "$bundle"
