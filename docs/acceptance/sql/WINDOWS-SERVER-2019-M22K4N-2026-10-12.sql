-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the FI repository LICENSE.
--
-- Historical, READ-ONLY verification for the exact 2026-10-12 lab run.
-- Must be executed against the FI System of Record on fi-backend-b.
-- PostgreSQL system-of-record object IDs 608/634 are lab-specific, NOT portable
-- NTFS identifiers. No DDL, DML, privileges, or installer changes are made.
--
-- From the FreeBSD HOST in the FI repository working directory:
-- cat docs/acceptance/sql/WINDOWS-SERVER-2019-M22K4N-2026-10-12.sql | \
--   jexec -U postgres fi-sor-db /usr/local/bin/psql \
--      -X -w -h /tmp -p 5432 -d fi -v ON_ERROR_STOP=1 -P pager=off

\set ON_ERROR_STOP on
\pset null '(NULL)'
BEGIN TRANSACTION READ ONLY;

\echo '===== ACCEPTED FILE-HISTORY GENERATION ====='
SELECT g.source_id, g.generation_id, g.ingested_at, g.record_count,
       j.outcome, j.records_seen, j.records_committed,
       (g.record_count = 50 AND j.outcome = 'Accepted'
        AND j.records_seen = 50 AND j.records_committed = 50) AS meets_expected
FROM fi.recorded_generation g
JOIN fi.ingest_journal j
  ON j.source_id = g.source_id AND j.generation_id = g.generation_id
 AND j.outcome = 'Accepted'
WHERE g.source_id = 'iss-fs-2019.iss.local'
  AND g.generation_id = '20261012T171950.364607700Z-181735f086990e45';

\echo '===== VOLUME-QUALIFIED OBJECT IDENTITY ====='
SELECT o.ntfs_object_id, v.source_id, v.volume_guid, v.volume_serial,
       o.file_reference_number, o.sequence_number
FROM fi.ntfs_object o
JOIN fi.ntfs_volume v ON v.ntfs_volume_id = o.ntfs_volume_id
WHERE v.source_id = 'iss-fs-2019.iss.local'
  AND o.ntfs_object_id IN (608, 634)
ORDER BY o.ntfs_object_id;

\echo '===== OBJECT REOBSERVATION, INCLUDING DELETED COPY ====='
SELECT u.source_record_id, u.ntfs_object_id, u.status, u.scope_basis,
       u.reason_code, u.error_text, u.has_ntfs_observation,
       u.has_content_hashes
FROM fi.usn_object_observation u
WHERE u.ntfs_object_id IN (608, 634)
ORDER BY u.ntfs_object_id, u.source_record_id;

\echo '===== FILE METADATA / SHA-256 CHECK ====='
SELECT f.ntfs_object_id, f.source_record_id, f.observed_at,
       f.collection_entry_method, f.collection_method, f.observation_status,
       m.logical_size, m.allocated_size, m.creation_time, m.last_write_time,
       m.change_time, m.last_access_time, m.raw_attributes, m.link_count,
       h.state AS hash_state, h.bytes_hashed,
       encode(h.md5, 'hex') AS md5,
       encode(h.sha1, 'hex') AS sha1,
       encode(h.sha256, 'hex') AS sha256,
       (f.ntfs_object_id = 608 AND m.logical_size = 49
        AND h.state = 'Present' AND h.bytes_hashed = 49
        AND encode(h.sha256, 'hex') =
        'e271bbbead08fb44ab23cacfd2b8efd902e6bdafca64a3234c6611313b752df6') AS matches_test_file
FROM fi.file_observation f
LEFT JOIN fi.file_metadata_observation m
  ON m.source_record_id = f.source_record_id
LEFT JOIN fi.content_hash_observation h
  ON h.source_record_id = f.source_record_id
WHERE f.ntfs_object_id IN (608, 634)
ORDER BY f.ntfs_object_id, f.observed_at;

\echo '===== OWNER, DACL AND SACL COUNTS ====='
SELECT f.ntfs_object_id, s.owner_sid, s.primary_group_sid,
       s.state AS security_state, sa.state AS sacl_state,
       (SELECT COUNT(*) FROM fi.security_ace a
        WHERE a.source_record_id = f.source_record_id) AS dacl_entries,
       (SELECT COUNT(*) FROM fi.sacl_ace a
        WHERE a.source_record_id = f.source_record_id) AS sacl_entries
FROM fi.file_observation f
LEFT JOIN fi.security_observation s
  ON s.source_record_id = f.source_record_id
LEFT JOIN fi.sacl_observation sa
  ON sa.source_record_id = f.source_record_id
WHERE f.ntfs_object_id IN (608, 634)
ORDER BY f.ntfs_object_id, f.observed_at;

\echo '===== INDIVIDUAL ACCESS-CONTROL ENTRIES ====='
SELECT f.ntfs_object_id, 'DACL' AS acl_type, a.ace_ordinal, a.type_name,
       a.flags, a.sid, a.access_mask
FROM fi.file_observation f
JOIN fi.security_ace a ON a.source_record_id = f.source_record_id
WHERE f.ntfs_object_id IN (608, 634)
UNION ALL
SELECT f.ntfs_object_id, 'SACL', a.ace_ordinal, a.type_name,
       a.flags, a.sid, a.access_mask
FROM fi.file_observation f
JOIN fi.sacl_ace a ON a.source_record_id = f.source_record_id
WHERE f.ntfs_object_id IN (608, 634)
ORDER BY ntfs_object_id, acl_type, ace_ordinal;

\echo '===== STREAM AND REPARSE STATE ====='
SELECT f.ntfs_object_id, i.state AS stream_inventory_state,
       so.stream_ordinal, so.kind, so.stream_type, so.logical_size,
       so.allocated_size, rp.state AS reparse_state
FROM fi.file_observation f
LEFT JOIN fi.stream_inventory i ON i.source_record_id = f.source_record_id
LEFT JOIN fi.stream_observation so ON so.source_record_id = f.source_record_id
LEFT JOIN fi.reparse_observation rp ON rp.source_record_id = f.source_record_id
WHERE f.ntfs_object_id IN (608, 634)
ORDER BY f.ntfs_object_id, so.stream_ordinal;

\echo '===== USN OBJECT CONTINUITY / PARENT CHANGES ====='
SELECT c.file_ntfs_object_id AS object_id,
       c.parent_ntfs_object_id AS parent_id, c.usn, c.event_timestamp,
       CASE c.file_name_utf16le
         WHEN decode('730061006d0070006c0065002e00740078007400', 'hex') THEN 'sample.txt'
         WHEN decode('720065006e0061006d00650064002e00740078007400', 'hex') THEN 'renamed.txt'
         WHEN decode('63006f00700079002e00740078007400', 'hex') THEN 'copy.txt'
         ELSE encode(c.file_name_utf16le, 'hex')
       END AS filename,
       string_agg(reason.reason_name, ', ' ORDER BY reason.reason_ordinal) AS reasons
FROM fi.usn_object_change c
JOIN fi.usn_object_observation u ON u.source_record_id = c.source_record_id
JOIN fi.source_record r ON r.source_record_id = u.source_record_id
JOIN fi.source_batch b ON b.source_batch_id = r.source_batch_id
JOIN fi.recorded_generation g ON g.recorded_generation_id = b.recorded_generation_id
LEFT JOIN fi.usn_object_change_reason reason
  ON reason.source_record_id = c.source_record_id
 AND reason.change_ordinal = c.change_ordinal
WHERE g.source_id = 'iss-fs-2019.iss.local'
  AND g.generation_id = '20261012T171950.364607700Z-181735f086990e45'
  AND c.file_ntfs_object_id IN (608, 634)
GROUP BY c.source_record_id, c.change_ordinal, c.file_ntfs_object_id,
         c.parent_ntfs_object_id, c.usn, c.event_timestamp, c.file_name_utf16le
ORDER BY object_id, c.usn;

\echo '===== WINDOWS SECURITY EVENTS ATTRIBUTION ====='
SELECT e.event_id, e.subject_domain_name, e.subject_user_name,
       e.process_name, COUNT(*) AS event_count
FROM fi.windows_security_event e
JOIN fi.source_record r ON r.source_record_id = e.source_record_id
JOIN fi.source_batch b ON b.source_batch_id = r.source_batch_id
JOIN fi.recorded_generation g ON g.recorded_generation_id = b.recorded_generation_id
WHERE g.source_id = 'iss-fs-2019.iss.local'
  AND (e.object_name ILIKE '%FI-TEST-20261012-101110%'
       OR e.file_name ILIKE '%FI-TEST-20261012-101110%')
GROUP BY e.event_id, e.subject_domain_name, e.subject_user_name, e.process_name
ORDER BY e.subject_user_name, e.event_id;

\echo '===== SOURCE RECORD PROVENANCE ====='
SELECT u.source_record_id, r.record_kind, r.scope_id,
       encode(r.record_sha256, 'hex') AS source_record_sha256,
       b.batch_id, g.generation_id, g.ingested_at
FROM fi.usn_object_observation u
JOIN fi.source_record r ON r.source_record_id = u.source_record_id
JOIN fi.source_batch b ON b.source_batch_id = r.source_batch_id
JOIN fi.recorded_generation g ON g.recorded_generation_id = b.recorded_generation_id
WHERE g.source_id = 'iss-fs-2019.iss.local'
  AND u.ntfs_object_id IN (608, 634)
ORDER BY u.ntfs_object_id, r.written_at;

\echo '===== REBOOT PERSISTENCE - SUBSEQUENT ACCEPTED GENERATION ====='
SELECT g.generation_id, g.ingested_at, g.record_count,
       j.outcome, j.records_seen, j.records_committed,
       (g.ingested_at >= TIMESTAMPTZ '2026-10-12 17:28:13+00'
        AND j.outcome = 'Accepted'
        AND j.records_seen = j.records_committed
        AND g.record_count = j.records_committed) AS post_reboot_commit_consistent
FROM fi.recorded_generation g
JOIN fi.ingest_journal j ON j.source_id = g.source_id
  AND j.generation_id = g.generation_id AND j.outcome = 'Accepted'
WHERE g.source_id = 'iss-fs-2019.iss.local'
  AND g.generation_id = '20261012T172827.518061300Z-d2db9b44af3ae92e';

COMMIT;
\echo '===== READ-ONLY ACCEPTANCE QUERY COMPLETE ====='
