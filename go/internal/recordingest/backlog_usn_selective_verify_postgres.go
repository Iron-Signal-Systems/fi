// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Independent verifier B reads only relationally committed evidence, never
// trusts the collector's claim that a source-bound observation was complete.
package recordingest

import (
    "context"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
)

// verifyUSNSelectiveObservationsComplete rejects missing, duplicated,
// misbound, non-original or fabricated File-ID evidence in the signed
// generation. It never turns a current outside/missing file into proof
// that an earlier USN event was outside the governed root.
func verifyUSNSelectiveObservationsComplete(
    ctx context.Context,tx pgx.Tx,generationID int64,
)error{
    if ctx==nil||tx==nil||generationID<=0{
        return errors.New("FI verifier B: source-bound observation SQL context required")
    }
    var id int64
    err:=tx.QueryRow(ctx,`
SELECT o.source_record_id
FROM fi.usn_selective_observation o
JOIN fi.source_record sr ON sr.source_record_id=o.source_record_id
JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id
JOIN fi.usn_scoped_capture cap ON cap.source_record_id=o.original_capture_source_record_id
JOIN fi.source_record original_sr ON original_sr.source_record_id=cap.source_record_id
JOIN fi.source_batch original_sb ON original_sb.source_batch_id=original_sr.source_batch_id
JOIN fi.recorded_generation original_rg ON original_rg.recorded_generation_id=original_sb.recorded_generation_id
LEFT JOIN fi.file_observation ntfs ON ntfs.source_record_id=o.source_record_id
WHERE sb.recorded_generation_id=$1 AND (
    sr.record_kind<>'USNSelectiveObservation'
 OR sr.scope_id<>o.governed_scope_id
 OR original_rg.source_id<>rg.source_id
 OR original_sr.scope_id<>o.governed_scope_id
 OR cap.capture_scope_id<>o.capture_scope_id
 OR cap.governed_scope_id<>o.governed_scope_id
 OR cap.ntfs_volume_id<>o.ntfs_volume_id
 OR cap.root_ntfs_object_id<>o.root_ntfs_object_id
 OR cap.journal_id<>o.journal_id
 OR cap.start_usn<>o.start_usn
 OR cap.next_usn<>o.next_usn
 OR cap.source_batch_sha256<>o.source_batch_sha256
 OR (o.observation_status='Observed' AND ntfs.source_record_id IS NULL)
 OR (o.observation_status<>'Observed' AND ntfs.source_record_id IS NOT NULL)
 OR o.has_ntfs_observation IS DISTINCT FROM (o.observation_status='Observed')
 OR o.has_content_hashes IS DISTINCT FROM (o.observation_status='Observed')
)
LIMIT 1
`,generationID).Scan(&id)
    if err==nil{return fmt.Errorf("FI verifier B: source-bound NTFS observation %d lacks original identity/real file evidence",id)}
    if !errors.Is(err,pgx.ErrNoRows){return err}

    // Missing or repeated original trigger events cannot be disguised by a
    // matching trigger_count alone, or by changing the child ordinal values.
    var expected,got int64
    err=tx.QueryRow(ctx,`
SELECT o.source_record_id,o.trigger_count,count(t.trigger_ordinal)
FROM fi.usn_selective_observation o
JOIN fi.source_record sr ON sr.source_record_id=o.source_record_id
JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
LEFT JOIN fi.usn_selective_observation_trigger t ON t.source_record_id=o.source_record_id
WHERE sb.recorded_generation_id=$1
GROUP BY o.source_record_id,o.trigger_count
HAVING count(t.trigger_ordinal)<>o.trigger_count
   OR min(t.trigger_ordinal)<>1
   OR max(t.trigger_ordinal)<>o.trigger_count
LIMIT 1
`,generationID).Scan(&id,&expected,&got)
    if err==nil{return fmt.Errorf("FI verifier B: incomplete selective observation %d triggers=%d/%d",id,got,expected)}
    if !errors.Is(err,pgx.ErrNoRows){return err}

    // Every observation trigger must correspond to a REAL original USN
    // child of the SAME File-ID and parent capture. The original source
    // digest already verified by A is not inferred from these counters.
    err=tx.QueryRow(ctx,`
SELECT o.source_record_id
FROM fi.usn_selective_observation o
JOIN fi.source_record sr ON sr.source_record_id=o.source_record_id
JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
JOIN fi.usn_selective_observation_trigger t ON t.source_record_id=o.source_record_id
WHERE sb.recorded_generation_id=$1 AND NOT EXISTS (
 SELECT 1 FROM fi.usn_scoped_change c
 WHERE c.source_record_id=o.original_capture_source_record_id
   AND c.file_ntfs_object_id=o.file_ntfs_object_id
   AND c.usn=t.usn
)
LIMIT 1
`,generationID).Scan(&id)
    if err==nil{return fmt.Errorf("FI verifier B: observation %d cites an event absent from original USN source",id)}
    if !errors.Is(err,pgx.ErrNoRows){return err}

    // A second signed generation may legitimately observe the SAME file
    // in a DIFFERENT original source interval; it may not publish another
    // observation for an identical original interval, root and File-ID.
    err=tx.QueryRow(ctx,`
SELECT newer.source_record_id
FROM fi.usn_selective_observation newer
JOIN fi.source_record nsr ON nsr.source_record_id=newer.source_record_id
JOIN fi.source_batch nsb ON nsb.source_batch_id=nsr.source_batch_id
JOIN fi.recorded_generation ng ON ng.recorded_generation_id=nsb.recorded_generation_id
JOIN fi.usn_selective_observation older
  ON older.original_capture_source_record_id=newer.original_capture_source_record_id
 AND older.governed_scope_id=newer.governed_scope_id
 AND older.file_ntfs_object_id=newer.file_ntfs_object_id
 AND older.source_record_id<>newer.source_record_id
JOIN fi.source_record osr ON osr.source_record_id=older.source_record_id
JOIN fi.source_batch osb ON osb.source_batch_id=osr.source_batch_id
JOIN fi.recorded_generation og ON og.recorded_generation_id=osb.recorded_generation_id
WHERE nsb.recorded_generation_id=$1
  AND og.source_id=ng.source_id
LIMIT 1
`,generationID).Scan(&id)
    if err==nil{return fmt.Errorf("FI verifier B: duplicate observed source interval/file identity %d",id)}
    if !errors.Is(err,pgx.ErrNoRows){return err}
    return nil
}
