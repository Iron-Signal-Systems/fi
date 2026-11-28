//go:build fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

// A disposable-only PostgreSQL 18 test: prove consecutive source-first USN
// batches are real relational projections, not compiler-admitted kind strings.
// Every inserted row is rolled back; no signed custody is fabricated here.
func proveScopedUSNPostgres18Projection(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	first := testUSNScopedCapturePayload()
	second := testUSNScopedCapturePayload()
	second.StartUSN = first.NextUSN
	second.NextUSN = "300"
	second.Included[0].Source.USN = "204"
	second.Included[0].Source.FileIdentity.FileReferenceNumber = "103"

	rawSecond := records.USNReadBatch{
		ObservedAt: second.CapturedAt,
		CollectionMethod: second.CollectionMethod,
		ScopeID: second.CaptureScopeID,
		VolumeIdentity: second.VolumeIdentity,
		JournalID: second.JournalID,
		StartUSN: second.StartUSN,
		NextUSN: second.NextUSN,
		Records: []records.USNChangeObservation{second.Included[0].Source},
	}
	encoded, err := json.Marshal(rawSecond)
	if err != nil { t.Fatal(err) }
	sum := sha256.Sum256(encoded)
	second.SourceBatchSHA256 = hex.EncodeToString(sum[:])
	fixtures := []usnScopedCapturePayload{first, second}

	tx, err := admin.Begin(ctx)
	if err != nil { t.Fatal(err) }
	defer tx.Rollback(context.Background())

	source := "ci-disposable-usn-source"
	generation := "ci-disposable-usn-generation"
	hash := sha256.Sum256([]byte("fi scoped usn ephemeral sql fixture"))
	var genID int64
	err = tx.QueryRow(ctx, `
INSERT INTO fi.recorded_generation (
 receipt_version,descriptor_version,source_id,generation_id,
 canonical_version,data_encoding,artifact_count,source_bytes,
 canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,
 metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
 batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version)
VALUES ('ci/1','ci/1',$1,$2,'fi-canonical/0.1','none',4,256,
 256,$3,128,$3,64,$3,232,$3,2,128,2,120,$3,'ci-only')
RETURNING recorded_generation_id`, source, generation, hash[:]).Scan(&genID)
	if err != nil { t.Fatalf("disposable source-fixture generation: %v", err) }

	recordIDs := make([]int64, 0, len(fixtures))
	for i, v := range fixtures {
		// A genuine boundary between source batches: a distinct manifest,
		// batch identifier and source record for every contiguous interval.
		label := "ci-usn-first"
		if i == 1 { label = "ci-usn-second" }
		var batchID int64
		err = tx.QueryRow(ctx, `
INSERT INTO fi.source_batch (
 recorded_generation_id,manifest_artifact_name,data_artifact_name,manifest_version,
 batch_id,target_batch_size,record_count,data_bytes,data_sha256,data_file,
 collector_executable_path,collector_executable_sha256,created_at,completed_at,
 manifest_bytes,manifest_sha256)
VALUES ($1,$2,$3,'fi-spool-manifest/0.1',
 $4,512,1,64,$5,$3,
 'CI-FICollector.exe',$5,$6,$6,120,$5)
RETURNING source_batch_id`,
			genID, label+".manifest.json", label+".jsonl", label,
			hash[:], time.Now().UTC()).Scan(&batchID)
		if err != nil { t.Fatalf("disposable USN batch %d: %v", i, err) }

		var sourceRecordID int64
		err = tx.QueryRow(ctx, `
INSERT INTO fi.source_record (
 source_batch_id,record_ordinal,version,record_kind,scope_id,written_at,
 record_bytes,record_sha256,ingest_version)
VALUES ($1,1,$2,'USNScopedCapture',$3,$4,512,$5,$6)
RETURNING source_record_id`,
			batchID, SpoolRecordVersion, v.GovernedScopeID,
			time.Now().UTC(), hash[:], IngestVersion).Scan(&sourceRecordID)
		if err != nil { t.Fatalf("disposable USN source record %d: %v", i, err) }
		if err := projectUSNScopedCapture(ctx, tx, source, sourceRecordID,
			v.GovernedScopeID, v); err != nil {
			t.Fatalf("real PostgreSQL18 USN batch %d projection rejected: %v", i, err)
		}
		recordIDs = append(recordIDs, sourceRecordID)
	}

	// Read back both source batches independently, including their exact
	// child event ordinals. No earlier batch may hide a missing later event.
	for i, recordID := range recordIDs {
		var captures, changes, governed, unresolved int64
		err = tx.QueryRow(ctx, `
SELECT (SELECT count(*) FROM fi.usn_scoped_capture WHERE source_record_id=$1),
       (SELECT count(*) FROM fi.usn_scoped_change WHERE source_record_id=$1),
       (SELECT count(*) FROM fi.usn_scoped_change WHERE source_record_id=$1 AND scope_class='Governed'),
       (SELECT count(*) FROM fi.usn_scoped_change WHERE source_record_id=$1 AND scope_class='Unresolved')`,
			recordID).Scan(&captures, &changes, &governed, &unresolved)
		if err != nil || captures != 1 || changes != 1 || governed != 1 || unresolved != 0 {
			t.Fatalf("USN batch %d source rows incomplete: capture=%d child=%d governed=%d unresolved=%d err=%v",
				i, captures, changes, governed, unresolved, err)
		}
	}
	if err := verifyGenerationProjectionCoverage(ctx, tx, genID); err != nil {
		t.Fatalf("two USN batches excluded from canonical typed coverage: %v", err)
	}
	if err := verifyScopedUSNCapturesComplete(ctx, tx, genID); err != nil {
		t.Fatalf("independent B relational USN proof failed for two batches: %v", err)
	}
    // The same disposable SQL transaction proves asynchronous File-ID
    // source binding and verifier-B failure injections without leaving
    // any additional canonical source rows in the surrounding fixture.
    proveSelectiveUSNPostgres18Outcome(t,ctx,tx,genID,recordIDs[0])


	// B must reject an overlap even though both source digests are
	// different and their original event checksums remain plausible.
	if _, err := tx.Exec(ctx, "SAVEPOINT ci_usn_overlap"); err != nil { t.Fatal(err) }
	if _, err := tx.Exec(ctx,
		"UPDATE fi.usn_scoped_capture SET start_usn=150 WHERE source_record_id=$1",
		recordIDs[1]); err != nil { t.Fatal(err) }
	if err := verifyScopedUSNCapturesComplete(ctx, tx, genID); err == nil {
		t.Fatal("independent B accepted overlapping scoped USN source intervals")
	}
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT ci_usn_overlap"); err != nil { t.Fatal(err) }

	// Exactly matching totals are insufficient when source child ordinals
	// contain a hole. Detect it without rebuilding or replaying the source.
	if _, err := tx.Exec(ctx, "SAVEPOINT ci_usn_ordinal_gap"); err != nil { t.Fatal(err) }
	if _, err := tx.Exec(ctx,
		"UPDATE fi.usn_scoped_change SET change_ordinal=2 WHERE source_record_id=$1",
		recordIDs[1]); err != nil { t.Fatal(err) }
	if err := verifyScopedUSNCapturesComplete(ctx, tx, genID); err == nil {
		t.Fatal("independent B accepted a missing source change ordinal")
	}
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT ci_usn_ordinal_gap"); err != nil { t.Fatal(err) }

	// Prove B rejects an event missing from the SECOND batch even though the
	// first remains perfectly valid. Roll back the fault before completion.
	if _, err := tx.Exec(ctx, "SAVEPOINT ci_usn_missing_child"); err != nil { t.Fatal(err) }
	if _, err := tx.Exec(ctx, "DELETE FROM fi.usn_scoped_change WHERE source_record_id=$1", recordIDs[1]); err != nil {
		t.Fatal(err)
	}
	if err := verifyScopedUSNCapturesComplete(ctx, tx, genID); err == nil {
		t.Fatal("independent USN B proof accepted a missing event from the second batch")
	}
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT ci_usn_missing_child"); err != nil { t.Fatal(err) }
	if err := verifyScopedUSNCapturesComplete(ctx, tx, genID); err != nil {
		t.Fatalf("independent B proof did not recover after restoring the second batch: %v", err)
	}

    // Generate a DISTINCT signed-looking generation that reuses an original
    // volume/journal/root interval. No source reread, raw record replay or
    // canonical mutation is necessary for independent relational B detection.
    if _,err:=tx.Exec(ctx,"SAVEPOINT ci_cross_generation_replay");err!=nil{t.Fatal(err)}
    replayHash:=sha256.Sum256([]byte("distinct second signed USN generation transfer fixture"))
    var replayGen int64
    err=tx.QueryRow(ctx,`
INSERT INTO fi.recorded_generation (
 receipt_version,descriptor_version,source_id,generation_id,
 canonical_version,data_encoding,artifact_count,source_bytes,
 canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,
 metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
 batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version)
VALUES ('ci/1','ci/1',$1,$2,'fi-canonical/0.1','none',2,128,
 128,$3,64,$3,32,$3,116,$3,1,64,1,120,$3,'ci-only')
RETURNING recorded_generation_id`,source,generation+"-replay",replayHash[:]).Scan(&replayGen)
    if err!=nil{t.Fatalf("second isolated signed-generation fixture: %v",err)}
    var replayBatch int64
    err=tx.QueryRow(ctx,`
INSERT INTO fi.source_batch (
 recorded_generation_id,manifest_artifact_name,data_artifact_name,manifest_version,
 batch_id,target_batch_size,record_count,data_bytes,data_sha256,data_file,
 collector_executable_path,collector_executable_sha256,created_at,completed_at,
 manifest_bytes,manifest_sha256)
VALUES ($1,'ci-usn-replay.manifest.json','ci-usn-replay.jsonl','fi-spool-manifest/0.1',
 'ci-usn-replay',512,1,64,$2,'ci-usn-replay.jsonl',
 'CI-FICollector.exe',$2,$3,$3,120,$2)
RETURNING source_batch_id`,replayGen,replayHash[:],time.Now().UTC()).Scan(&replayBatch)
    if err!=nil{t.Fatalf("re-signed replay batch: %v",err)}
    var replayRecord int64
    err=tx.QueryRow(ctx,`
INSERT INTO fi.source_record (
 source_batch_id,record_ordinal,version,record_kind,scope_id,written_at,
 record_bytes,record_sha256,ingest_version)
VALUES ($1,1,$2,'USNScopedCapture',$3,$4,512,$5,$6)
RETURNING source_record_id`,
        replayBatch,SpoolRecordVersion,first.GovernedScopeID,
        time.Now().UTC(),replayHash[:],IngestVersion).Scan(&replayRecord)
    if err!=nil{t.Fatalf("re-signed replay source record: %v",err)}
    if err:=projectUSNScopedCapture(ctx,tx,source,replayRecord,
        first.GovernedScopeID,first);err!=nil{
        t.Fatalf("re-signed conflicting source setup: %v",err)
    }
    if err:=verifyScopedUSNCapturesComplete(ctx,tx,replayGen);err==nil{
        t.Fatal("independent B accepted overlapping original USN under another signed generation")
    }
    if err:=verifyScopedUSNCapturesComplete(ctx,tx,genID);err==nil{
        t.Fatal("independent B did not detect historical cross-generation conflict")
    }
    if _,err:=tx.Exec(ctx,"ROLLBACK TO SAVEPOINT ci_cross_generation_replay");err!=nil{t.Fatal(err)}
    if err:=verifyScopedUSNCapturesComplete(ctx,tx,genID);err!=nil{
        t.Fatalf("independent B failed after discarded conflicting generation: %v",err)
    }

	if err := tx.Rollback(ctx); err != nil { t.Fatal(err) }
	var remainingCaptures, remainingChanges int64
	if err := admin.QueryRow(ctx, `
SELECT (SELECT count(*) FROM fi.usn_scoped_capture),
       (SELECT count(*) FROM fi.usn_scoped_change)`).Scan(
		&remainingCaptures, &remainingChanges); err != nil {
		t.Fatal(err)
	}
	if remainingCaptures != 0 || remainingChanges != 0 {
		t.Fatalf("disposable test left authoritative USN rows: captures=%d changes=%d",
			remainingCaptures, remainingChanges)
	}
	if len(hash[:]) != 32 || bytes.Equal(hash[:], make([]byte, 32)) {
		t.Fatal("invalid disposable fixture digest")
	}
}
