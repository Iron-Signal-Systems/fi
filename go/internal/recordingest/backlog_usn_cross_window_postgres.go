// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

// The opt-in backlog projector reconstructs cross-window M6.1 state from its
// already-durable private relational rows. No counter is trusted solely from
// process memory, and no schema or authority is added to the canonical SoR.
type backlogUSNCrossWindowContextKey struct{}

// Called only after the in-window map has no matching key. SQL reads are made
// through the privateProjectionTx, and require this generation, source, scope,
// digest, and a preceding boundary. Counts include all committed earlier
// windows, so the remaining allowance survives crashes/restarts.
func restoreBacklogUSNCapture(ctx context.Context, tx pgx.Tx, state *usnCaptureState, sourceID, scopeID, digest string, objectRecordID int64) error {
	if state == nil || state.sourceID != sourceID || state.generationID == "" || scopeID == "" || objectRecordID <= 0 {
		return errors.New("FI backlog USN: invalid restoration context")
	}
	raw, err := decodeHex(digest, 32, true, "usn_object_observation.source_batch_sha256")
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `
SELECT b.source_record_id,b.ntfs_volume_id,
       root.identity_method_version,root.file_reference_number::text,root.sequence_number::text,
       b.source_distinct_object_count,b.source_record_count
FROM fi.usn_read_boundary AS b
JOIN fi.source_record AS sr ON sr.source_record_id=b.source_record_id
JOIN fi.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
JOIN fi.recorded_generation AS rg ON rg.recorded_generation_id=sb.recorded_generation_id
JOIN fi.ntfs_object AS root ON root.ntfs_object_id=b.root_ntfs_object_id
WHERE rg.source_id=$1 AND rg.generation_id=$2 AND sr.scope_id=$3
  AND b.source_batch_sha256=$4
ORDER BY b.source_record_id
LIMIT 2
`, sourceID, state.generationID, scopeID, raw)
	if err != nil {
		return fmt.Errorf("FI backlog USN: find preceding durable capture: %w", err)
	}
	var boundary usnCaptureBoundary
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			break
		}
		if err := rows.Scan(&boundary.recordID, &boundary.volumeID,
			&boundary.root.MethodVersion, &boundary.root.FileReferenceNumber, &boundary.root.SequenceNumber,
			&boundary.expectedObjects, &boundary.expectedChanges); err != nil {
			rows.Close()
			return fmt.Errorf("FI backlog USN: scan durable capture: %w", err)
		}
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return readErr
	}
	if count != 1 || boundary.recordID >= objectRecordID {
		return errors.New("FI backlog USN: no unique preceding source-bound capture in this generation")
	}
	if err := records.ValidateNTFSObjectIdentity(boundary.root); err != nil {
		return fmt.Errorf("FI backlog USN: invalid restored root: %w", err)
	}
	var objects, changes int64
	err = tx.QueryRow(ctx, `
SELECT
  (SELECT count(*) FROM fi.usn_object_observation
   WHERE usn_read_boundary_source_record_id=$1),
  (SELECT count(*) FROM fi.usn_object_change AS ch
   JOIN fi.usn_object_observation AS ob ON ob.source_record_id=ch.source_record_id
   WHERE ob.usn_read_boundary_source_record_id=$1)
`, boundary.recordID).Scan(&objects, &changes)
	if err != nil {
		return fmt.Errorf("FI backlog USN: restore durable capture counts: %w", err)
	}
	if objects > int64(boundary.expectedObjects) || changes > int64(boundary.expectedChanges) ||
		objects < 0 || changes < 0 {
		return errors.New("FI backlog USN: durable capture counts exceed boundary")
	}
	boundary.observedObjects = int(objects)
	boundary.observedChanges = int(changes)
	if err := state.remember(sourceID, scopeID, digest, boundary); err != nil {
		return err
	}
	return nil
}

// This is a completion check, not a per-window requirement. A source-bound
// capture may be incomplete at an intermediate checkpoint, but cannot remain
// incomplete at the final private typed-window commit. Both checks are made
// against durable SQL, not only the current process's in-memory capture map.
func verifyBacklogUSNCapturesComplete(ctx context.Context, tx pgx.Tx, shadowGenerationID int64) error {
	if shadowGenerationID <= 0 {
		return errors.New("FI backlog USN: invalid shadow generation")
	}
	var scope, digest string
	var duplicates int64
	err := tx.QueryRow(ctx, `
SELECT sr.scope_id,encode(b.source_batch_sha256,'hex'),count(*)
FROM fi.usn_read_boundary AS b
JOIN fi.source_record AS sr ON sr.source_record_id=b.source_record_id
JOIN fi.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
WHERE sb.recorded_generation_id=$1 AND b.source_batch_sha256 IS NOT NULL
GROUP BY sr.scope_id,b.source_batch_sha256
HAVING count(*)<>1 LIMIT 1
`, shadowGenerationID).Scan(&scope, &digest, &duplicates)
	if err == nil {
		return fmt.Errorf("FI backlog USN: duplicate durable capture scope=%s digest=%s count=%d", scope, digest, duplicates)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	var boundaryID int64
	var expectedObjects, expectedChanges int
	var gotObjects, gotChanges int64
	err = tx.QueryRow(ctx, `
SELECT b.source_record_id,b.source_distinct_object_count,b.source_record_count,
  (SELECT count(*) FROM fi.usn_object_observation AS ob
   WHERE ob.usn_read_boundary_source_record_id=b.source_record_id) AS objects,
  (SELECT count(*) FROM fi.usn_object_change AS ch
   JOIN fi.usn_object_observation AS ob ON ob.source_record_id=ch.source_record_id
   WHERE ob.usn_read_boundary_source_record_id=b.source_record_id) AS changes
FROM fi.usn_read_boundary AS b
JOIN fi.source_record AS sr ON sr.source_record_id=b.source_record_id
JOIN fi.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
WHERE sb.recorded_generation_id=$1 AND b.source_batch_sha256 IS NOT NULL
AND (
  b.source_distinct_object_count <> (
    SELECT count(*) FROM fi.usn_object_observation AS ob
    WHERE ob.usn_read_boundary_source_record_id=b.source_record_id)
  OR b.source_record_count <> (
    SELECT count(*) FROM fi.usn_object_change AS ch
    JOIN fi.usn_object_observation AS ob ON ob.source_record_id=ch.source_record_id
    WHERE ob.usn_read_boundary_source_record_id=b.source_record_id)
)
LIMIT 1
`, shadowGenerationID).Scan(&boundaryID, &expectedObjects, &expectedChanges, &gotObjects, &gotChanges)
	if err == nil {
		return fmt.Errorf("FI backlog USN: incomplete durable capture boundary=%d objects=%d/%d changes=%d/%d",
			boundaryID, gotObjects, expectedObjects, gotChanges, expectedChanges)
	}
	if errors.Is(err, pgx.ErrNoRows) {
        return verifyScopedUSNCapturesComplete(ctx,tx,shadowGenerationID)
    }
    return err
}

// verifyScopedUSNCapturesComplete independently checks the new source-fact
// family in durable SQL, not the Windows publisher's in-memory counters.
// C1 B invokes this through the same read-only snapshot as the old USN proof.
func verifyScopedUSNCapturesComplete(ctx context.Context, tx pgx.Tx, generationID int64) error {
    if ctx==nil || tx==nil || generationID<=0 {
        return errors.New("FI scoped USN: invalid independent SQL verification context")
    }
    var duplicateScope,digest string
    var duplicates int64
    err:=tx.QueryRow(ctx,`
SELECT sr.scope_id,encode(c.source_batch_sha256,'hex'),count(*)
FROM fi.usn_scoped_capture c
JOIN fi.source_record sr ON sr.source_record_id=c.source_record_id
JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
WHERE sb.recorded_generation_id=$1
GROUP BY sr.scope_id,c.source_batch_sha256
HAVING count(*)<>1
LIMIT 1`,generationID).Scan(&duplicateScope,&digest,&duplicates)
    if err==nil{
        return fmt.Errorf("FI scoped USN: duplicate source batch scope=%s SHA=%s count=%d",duplicateScope,digest,duplicates)
    }
    if !errors.Is(err,pgx.ErrNoRows){return err}
    // B compares historical interval boundaries using PostgreSQL itself,
    // independently of the Windows uploader and the A projector. Repeated
    // event ranges with different SHA-256 values are still contradictions.
    // Multiple governed roots may share a volume-wide raw source interval;
    // each root is intentionally verified in its own partition.
    var overlapID,priorID int64
    var overlapStart,priorEnd string
    err=tx.QueryRow(ctx,`
WITH ordered AS (
 SELECT c.source_record_id,c.start_usn,c.next_usn,
        lag(c.source_record_id) OVER w AS prior_id,
        lag(c.next_usn) OVER w AS prior_end
 FROM fi.usn_scoped_capture c
 JOIN fi.source_record sr ON sr.source_record_id=c.source_record_id
 JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
 JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id
 WHERE sb.recorded_generation_id=$1
 WINDOW w AS (
  PARTITION BY rg.source_id,c.ntfs_volume_id,c.governed_scope_id,c.journal_id
  ORDER BY c.start_usn,c.next_usn,c.source_record_id
 )
)
SELECT source_record_id,prior_id,start_usn::text,prior_end::text
FROM ordered
WHERE prior_end>start_usn
LIMIT 1`,generationID).Scan(&overlapID,&priorID,&overlapStart,&priorEnd)
    if err==nil{
        return fmt.Errorf("FI scoped USN: overlapping source intervals record=%d start=%s previous_record=%d previous_end=%s",
            overlapID,overlapStart,priorID,priorEnd)
    }
    if !errors.Is(err,pgx.ErrNoRows){return err}
    // B independently rejects re-signed or conflicting source history across
    // separate generations from the same source and exact NTFS volume. A
    // previous generation must not make an overlapping interval acceptable
    // merely because the new receipt, manifest and source SHA are different.
    var newRecordID,oldRecordID int64
    err=tx.QueryRow(ctx,`
SELECT newer.source_record_id,older.source_record_id
FROM fi.usn_scoped_capture newer
JOIN fi.source_record nsr ON nsr.source_record_id=newer.source_record_id
JOIN fi.source_batch nsb ON nsb.source_batch_id=nsr.source_batch_id
JOIN fi.recorded_generation ng ON ng.recorded_generation_id=nsb.recorded_generation_id
JOIN fi.usn_scoped_capture older
  ON older.ntfs_volume_id=newer.ntfs_volume_id
 AND older.governed_scope_id=newer.governed_scope_id
 AND older.journal_id=newer.journal_id
 AND older.start_usn<newer.next_usn
 AND newer.start_usn<older.next_usn
JOIN fi.source_record osr ON osr.source_record_id=older.source_record_id
JOIN fi.source_batch osb ON osb.source_batch_id=osr.source_batch_id
JOIN fi.recorded_generation og ON og.recorded_generation_id=osb.recorded_generation_id
WHERE nsb.recorded_generation_id=$1
 AND osb.recorded_generation_id<>nsb.recorded_generation_id
 AND og.source_id=ng.source_id
LIMIT 1`,generationID).Scan(&newRecordID,&oldRecordID)
    if err==nil{
        return fmt.Errorf("FI scoped USN: source interval conflicts across signed generations new=%d prior=%d",
            newRecordID,oldRecordID)
    }
    if !errors.Is(err,pgx.ErrNoRows){return err}

    var id int64
    var expected,got,governed,unresolved int64
    err=tx.QueryRow(ctx,`
SELECT c.source_record_id,c.included_record_count,count(ch.change_ordinal),
       count(ch.change_ordinal) FILTER (WHERE ch.scope_class='Governed'),
       count(ch.change_ordinal) FILTER (WHERE ch.scope_class='Unresolved')
FROM fi.usn_scoped_capture c
JOIN fi.source_record sr ON sr.source_record_id=c.source_record_id
JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
LEFT JOIN fi.usn_scoped_change ch ON ch.source_record_id=c.source_record_id
WHERE sb.recorded_generation_id=$1
GROUP BY c.source_record_id,c.included_record_count,c.governed_record_count,
         c.unresolved_record_count,sr.scope_id,c.governed_scope_id
HAVING count(ch.change_ordinal)<>c.included_record_count
   OR (count(ch.change_ordinal)>0 AND
       (min(ch.change_ordinal)<>1 OR max(ch.change_ordinal)<>c.included_record_count))
   OR count(ch.change_ordinal) FILTER (WHERE ch.scope_class='Governed')<>c.governed_record_count
   OR count(ch.change_ordinal) FILTER (WHERE ch.scope_class='Unresolved')<>c.unresolved_record_count
   OR sr.scope_id<>c.governed_scope_id
LIMIT 1`,generationID).Scan(&id,&expected,&got,&governed,&unresolved)
    if err==nil {
        return fmt.Errorf("FI scoped USN: incomplete source capture record=%d events=%d/%d governed=%d unresolved=%d",id,got,expected,governed,unresolved)
    }
    if errors.Is(err,pgx.ErrNoRows){
        return verifyUSNSelectiveObservationsComplete(ctx,tx,generationID)
    }
    return err
}
