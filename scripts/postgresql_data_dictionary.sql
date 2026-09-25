\set ON_ERROR_STOP on
\pset pager off
\pset null 'NULL'

\echo '===== FI POSTGRESQL LIVE CATALOG REPORT ====='
SELECT
    current_database() AS database_name,
    current_user AS runtime_user,
    version() AS postgresql_version,
    clock_timestamp() AS report_time;

\echo '===== FI TABLE SUMMARY ====='
SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    c.reltuples::bigint AS estimated_rows,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'fi'
  AND c.relkind = 'r'
ORDER BY c.relname;

\echo '===== FI COLUMNS ====='
SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    a.attnum AS ordinal_position,
    a.attname AS column_name,
    pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
    NOT a.attnotnull AS nullable,
    CASE a.attidentity
        WHEN 'a' THEN 'ALWAYS'
        WHEN 'd' THEN 'BY DEFAULT'
        ELSE NULL
    END AS identity_generation,
    pg_get_expr(ad.adbin, ad.adrelid) AS column_default
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_attrdef ad
  ON ad.adrelid = a.attrelid
 AND ad.adnum = a.attnum
WHERE n.nspname = 'fi'
  AND c.relkind = 'r'
  AND a.attnum > 0
  AND NOT a.attisdropped
ORDER BY c.relname, a.attnum;

\echo '===== FI CONSTRAINTS ====='
SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    con.conname AS constraint_name,
    CASE con.contype
        WHEN 'p' THEN 'PRIMARY KEY'
        WHEN 'u' THEN 'UNIQUE'
        WHEN 'f' THEN 'FOREIGN KEY'
        WHEN 'c' THEN 'CHECK'
        WHEN 'x' THEN 'EXCLUSION'
        ELSE con.contype::text
    END AS constraint_type,
    pg_get_constraintdef(con.oid, true) AS definition
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'fi'
ORDER BY c.relname, constraint_type, con.conname;

\echo '===== FI FOREIGN-KEY COLUMN MAP ====='
SELECT
    src_ns.nspname AS source_schema,
    src.relname AS source_table,
    con.conname AS constraint_name,
    src_att.attname AS source_column,
    dst_ns.nspname AS target_schema,
    dst.relname AS target_table,
    dst_att.attname AS target_column,
    ord.ordinality AS column_ordinal,
    pg_get_constraintdef(con.oid, true) AS definition
FROM pg_constraint con
JOIN pg_class src ON src.oid = con.conrelid
JOIN pg_namespace src_ns ON src_ns.oid = src.relnamespace
JOIN pg_class dst ON dst.oid = con.confrelid
JOIN pg_namespace dst_ns ON dst_ns.oid = dst.relnamespace
JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS ord(attnum, ordinality) ON true
JOIN LATERAL unnest(con.confkey) WITH ORDINALITY AS ford(attnum, ordinality)
  ON ford.ordinality = ord.ordinality
JOIN pg_attribute src_att
  ON src_att.attrelid = src.oid
 AND src_att.attnum = ord.attnum
JOIN pg_attribute dst_att
  ON dst_att.attrelid = dst.oid
 AND dst_att.attnum = ford.attnum
WHERE con.contype = 'f'
  AND src_ns.nspname = 'fi'
ORDER BY src.relname, con.conname, ord.ordinality;

\echo '===== FI INDEXES ====='
SELECT
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE schemaname = 'fi'
ORDER BY tablename, indexname;

\echo '===== FI TABLE PRIVILEGES ====='
SELECT
    grantee,
    table_schema,
    table_name,
    privilege_type,
    is_grantable
FROM information_schema.role_table_grants
WHERE table_schema = 'fi'
ORDER BY table_name, grantee, privilege_type;

\echo '===== FI SEQUENCE PRIVILEGES ====='
SELECT
    grantee,
    object_schema AS sequence_schema,
    object_name AS sequence_name,
    privilege_type,
    is_grantable
FROM information_schema.role_usage_grants
WHERE object_schema = 'fi'
  AND object_type = 'SEQUENCE'
ORDER BY object_name, grantee, privilege_type;

\echo '===== FI_INGEST EFFECTIVE TABLE RIGHTS ====='
SELECT
    c.relname AS table_name,
    has_table_privilege('fi_ingest', c.oid, 'SELECT') AS can_select,
    has_table_privilege('fi_ingest', c.oid, 'INSERT') AS can_insert,
    has_table_privilege('fi_ingest', c.oid, 'UPDATE') AS can_update,
    has_table_privilege('fi_ingest', c.oid, 'DELETE') AS can_delete,
    has_table_privilege('fi_ingest', c.oid, 'TRUNCATE') AS can_truncate
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'fi'
  AND c.relkind = 'r'
ORDER BY c.relname;

\echo '===== FI OBJECT COUNTS ====='
SELECT 'tables' AS object_type, count(*)::bigint AS object_count
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'fi' AND c.relkind = 'r'
UNION ALL
SELECT 'columns', count(*)::bigint
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'fi' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
UNION ALL
SELECT 'constraints', count(*)::bigint
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'fi'
UNION ALL
SELECT 'foreign_keys', count(*)::bigint
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'fi' AND con.contype = 'f'
UNION ALL
SELECT 'indexes', count(*)::bigint
FROM pg_index i
JOIN pg_class c ON c.oid = i.indrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'fi'
ORDER BY object_type;
