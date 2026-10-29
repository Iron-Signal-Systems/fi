-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, in the repository root.
--
-- FI development SoR: metadata-only PostgreSQL COPY latency diagnostic.
--
-- Purpose: capture index/table footprint, cumulative cache and I/O counters,
-- checkpoint/WAL state, and current backend waits before attributing slow
-- COPY calls to a PostgreSQL or storage component.
--
-- Intended execution: fi-backend-b -> fi-sor-db (PostgreSQL 18, database fi).
-- Read-only transaction. No COUNT(*) on FI data, full-table scan, EXPLAIN
-- ANALYZE, DDL, VACUUM, ANALYZE, statistics reset, or configuration changes.
-- This is a *snapshot*, not a reproduction of the earlier 11.066s slow COPY.
-- PostgreSQL cumulative counters must be read with stats_reset timestamps.

\set ON_ERROR_STOP on
\pset pager off
\echo '===== FI COPY DIAGNOSTIC: IDENTITY / SETTINGS ====='

BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '1s';
SET LOCAL idle_in_transaction_session_timeout = '10s';

SELECT
    clock_timestamp() AS captured_at_utc,
    current_database() AS database_name,
    current_user AS database_user,
    current_setting('server_version') AS postgresql_version,
    pg_postmaster_start_time() AS server_started_at,
    pg_database_size(current_database()) AS database_bytes;

SELECT name, setting, unit
FROM pg_settings
WHERE name IN (
    'track_io_timing',
    'track_wal_io_timing',
    'shared_buffers',
    'checkpoint_timeout',
    'max_wal_size',
    'wal_buffers'
)
ORDER BY name;

\echo '===== FI COPY DIAGNOSTIC: LARGE RELATIONS (CATALOG ESTIMATES) ====='

SELECT
    c.relname AS table_name,
    c.reltuples::bigint AS estimated_rows,
    s.n_dead_tup AS estimated_dead_rows,
    pg_size_pretty(pg_table_size(c.oid)) AS table_size,
    pg_size_pretty(pg_indexes_size(c.oid)) AS index_size,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
    s.last_autovacuum,
    s.last_autoanalyze
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables AS s ON s.relid = c.oid
WHERE n.nspname = 'fi'
  AND c.relkind = 'r'
ORDER BY pg_total_relation_size(c.oid) DESC
LIMIT 15;

\echo '===== FI COPY DIAGNOSTIC: LARGE FI INDEXES / ACCESS COUNTERS ====='

SELECT
    t.relname AS table_name,
    x.relname AS index_name,
    pg_size_pretty(pg_relation_size(x.oid)) AS index_size,
    i.indisvalid AS valid,
    i.indisready AS ready,
    s.idx_scan,
    s.idx_tup_read,
    s.idx_tup_fetch,
    io.idx_blks_read,
    io.idx_blks_hit
FROM pg_index AS i
JOIN pg_class AS x ON x.oid = i.indexrelid
JOIN pg_class AS t ON t.oid = i.indrelid
JOIN pg_namespace AS n ON n.oid = t.relnamespace
LEFT JOIN pg_stat_user_indexes AS s ON s.indexrelid = x.oid
LEFT JOIN pg_statio_user_indexes AS io ON io.indexrelid = x.oid
WHERE n.nspname = 'fi'
ORDER BY pg_relation_size(x.oid) DESC
LIMIT 20;

\echo '===== FI COPY DIAGNOSTIC: SECURITY-FIELD INDEX CONTRACT ====='

SELECT
    count(*) FILTER (WHERE indexname = 'windows_security_event_field_pkey')
      AS field_primary_key_present,
    count(*) FILTER (WHERE indexname = 'windows_security_event_field_name_idx')
      AS removed_field_name_index_present
FROM pg_indexes
WHERE schemaname = 'fi'
  AND tablename = 'windows_security_event_field';

\echo '===== FI COPY DIAGNOSTIC: DATABASE-LEVEL CUMULATIVE I/O ====='

SELECT
    datname,
    stats_reset,
    blks_read,
    blks_hit,
    round(100.0 * blks_hit / nullif(blks_read + blks_hit, 0), 2)
      AS shared_buffer_hit_percent,
    round(blk_read_time::numeric, 2) AS read_time_ms,
    round(blk_write_time::numeric, 2) AS write_time_ms,
    temp_bytes,
    deadlocks
FROM pg_stat_database
WHERE datname = 'fi';

\echo '===== FI COPY DIAGNOSTIC: PG18 I/O BY BACKEND / CONTEXT ====='

SELECT
    backend_type,
    object,
    context,
    reads,
    round(read_time::numeric, 1) AS read_time_ms,
    writes,
    round(write_time::numeric, 1) AS write_time_ms,
    hits,
    evictions,
    fsyncs,
    round(fsync_time::numeric, 1) AS fsync_time_ms,
    stats_reset
FROM pg_stat_io
WHERE (coalesce(reads, 0) + coalesce(writes, 0)
       + coalesce(evictions, 0) + coalesce(fsyncs, 0)) > 0
ORDER BY backend_type, object, context;

\echo '===== FI COPY DIAGNOSTIC: WAL / CHECKPOINTER ====='

SELECT
    stats_reset,
    wal_records,
    wal_fpi,
    wal_bytes,
    wal_buffers_full
FROM pg_stat_wal;

SELECT
    stats_reset,
    num_timed,
    num_requested,
    num_done,
    buffers_written,
    round(write_time::numeric, 1) AS write_time_ms,
    round(sync_time::numeric, 1) AS sync_time_ms
FROM pg_stat_checkpointer;

\echo '===== FI COPY DIAGNOSTIC: CURRENT CLIENT WAITS (NO QUERY TEXT) ====='

SELECT
    pid,
    application_name,
    state,
    wait_event_type,
    wait_event,
    clock_timestamp() - query_start AS query_age,
    pg_blocking_pids(pid) AS blocking_pids
FROM pg_stat_activity
WHERE datname = 'fi'
  AND pid <> pg_backend_pid()
  AND state IS DISTINCT FROM 'idle'
ORDER BY query_start NULLS LAST
LIMIT 20;

COMMIT;

\echo '===== FI COPY DIAGNOSTIC COMPLETE (READ ONLY) ====='
