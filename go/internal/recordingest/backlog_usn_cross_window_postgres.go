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

func checkBacklogUSNCaptureUnique(ctx context.Context, tx pgx.Tx, state *usnCaptureState, sourceID, scopeID, digest string) error {
    if state == nil || state.sourceID != sourceID || state.generationID == "" || scopeID == "" {
        return errors.New("FI backlog USN: invalid capture generation context")
    }
    raw, err := decodeHex(digest, 32, true, "usn_read_boundary.source_batch_sha256")
    if err != nil { return err }
    var exists bool
    err = tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM fi.usn_read_boundary AS b
    JOIN fi.source_record AS sr ON sr.source_record_id=b.source_record_id
    JOIN fi.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
    JOIN fi.recorded_generation AS rg ON rg.recorded_generation_id=sb.recorded_generation_id
    WHERE rg.source_id=$1 AND rg.generation_id=$2 AND sr.scope_id=$3
      AND b.source_batch_sha256=$4
)`, sourceID, state.generationID, scopeID, raw).Scan(&exists)
    if err != nil { return fmt.Errorf("FI backlog USN: check durable duplicate capture: %w", err) }
    if exists { return errors.New("FI backlog USN: duplicate source-bound capture across windows") }
    return nil
}

// Called only after the in-window map has no matching key. SQL reads are made
// through the privateProjectionTx, and require this generation, source, scope,
// digest, and a preceding boundary. Counts include all committed earlier
// windows, so the remaining allowance survives crashes/restarts.
func restoreBacklogUSNCapture(ctx context.Context, tx pgx.Tx, state *usnCaptureState, sourceID, scopeID, digest string, objectRecordID int64) error {
    if state == nil || state.sourceID != sourceID || state.generationID == "" || scopeID == "" || objectRecordID <= 0 {
        return errors.New("FI backlog USN: invalid restoration context")
    }
    raw, err := decodeHex(digest, 32, true, "usn_object_observation.source_batch_sha256")
    if err != nil { return err }
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
`,sourceID,state.generationID,scopeID,raw)
    if err != nil { return fmt.Errorf("FI backlog USN: find preceding durable capture: %w", err) }
    var boundary usnCaptureBoundary
    count := 0
    for rows.Next() {
        count++
        if count > 1 { break }
        if err := rows.Scan(&boundary.recordID,&boundary.volumeID,
            &boundary.root.MethodVersion,&boundary.root.FileReferenceNumber,&boundary.root.SequenceNumber,
            &boundary.expectedObjects,&boundary.expectedChanges); err != nil {
            rows.Close()
            return fmt.Errorf("FI backlog USN: scan durable capture: %w",err)
        }
    }
    readErr := rows.Err()
    rows.Close()
    if readErr != nil { return readErr }
    if count != 1 || boundary.recordID >= objectRecordID {
        return errors.New("FI backlog USN: no unique preceding source-bound capture in this generation")
    }
    if err := records.ValidateNTFSObjectIdentity(boundary.root); err != nil {
        return fmt.Errorf("FI backlog USN: invalid restored root: %w",err)
    }
    var objects,changes int64
    err = tx.QueryRow(ctx, `
SELECT
  (SELECT count(*) FROM fi.usn_object_observation
   WHERE usn_read_boundary_source_record_id=$1),
  (SELECT count(*) FROM fi.usn_object_change AS ch
   JOIN fi.usn_object_observation AS ob ON ob.source_record_id=ch.source_record_id
   WHERE ob.usn_read_boundary_source_record_id=$1)
`,boundary.recordID).Scan(&objects,&changes)
    if err != nil { return fmt.Errorf("FI backlog USN: restore durable capture counts: %w",err) }
    if objects > int64(boundary.expectedObjects) || changes > int64(boundary.expectedChanges) ||
        objects < 0 || changes < 0 {
        return errors.New("FI backlog USN: durable capture counts exceed boundary")
    }
    boundary.observedObjects = int(objects)
    boundary.observedChanges = int(changes)
    if err := state.remember(sourceID,scopeID,digest,boundary); err != nil { return err }
    return nil
}

// This is a completion check, not a per-window requirement. A source-bound
// capture may be incomplete at an intermediate checkpoint, but cannot remain
// incomplete at the final private typed-window commit. Both checks are made
// against durable SQL, not only the current process's in-memory capture map.
func verifyBacklogUSNCapturesComplete(ctx context.Context, tx pgx.Tx, shadowGenerationID int64) error {
    if shadowGenerationID <= 0 { return errors.New("FI backlog USN: invalid shadow generation") }
    var scope,digest string
    var duplicates int64
    err := tx.QueryRow(ctx, `
SELECT sr.scope_id,encode(b.source_batch_sha256,'hex'),count(*)
FROM fi.usn_read_boundary AS b
JOIN fi.source_record AS sr ON sr.source_record_id=b.source_record_id
JOIN fi.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
WHERE sb.recorded_generation_id=$1 AND b.source_batch_sha256 IS NOT NULL
GROUP BY sr.scope_id,b.source_batch_sha256
HAVING count(*)<>1 LIMIT 1
`,shadowGenerationID).Scan(&scope,&digest,&duplicates)
    if err == nil { return fmt.Errorf("FI backlog USN: duplicate durable capture scope=%s digest=%s count=%d",scope,digest,duplicates) }
    if !errors.Is(err,pgx.ErrNoRows) { return err }

    var boundaryID int64
    var expectedObjects,expectedChanges int
    var gotObjects,gotChanges int64
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
`,shadowGenerationID).Scan(&boundaryID,&expectedObjects,&expectedChanges,&gotObjects,&gotChanges)
    if err == nil {
        return fmt.Errorf("FI backlog USN: incomplete durable capture boundary=%d objects=%d/%d changes=%d/%d",
            boundaryID,gotObjects,expectedObjects,gotChanges,expectedChanges)
    }
    if errors.Is(err,pgx.ErrNoRows) { return nil }
    return err
}
