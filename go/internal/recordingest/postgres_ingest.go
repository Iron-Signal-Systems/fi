// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5"
)

var (
	ErrGenerationConflict   = errors.New("FI relational generation identity conflict")
	ErrSourceRecordRejected = errors.New("FI relational source record rejected")
)

type IngestResult struct {
	AttemptID            string
	SourceID             string
	GenerationID         string
	TransferSHA256       string
	ReceiptSHA256        string
	Batches              int
	DataBytes            uint64
	RecordsSeen          int64
	RecordsCommitted     int64
	RecordedGenerationID int64
	Outcome              string
}

func IngestPreparedGeneration(ctx context.Context, connection *pgx.Conn, attemptID string, generation *PreparedGeneration) (IngestResult, error) {
	if ctx == nil || connection == nil || generation == nil || attemptID == "" {
		return IngestResult{}, errors.New("FI relational generation ingest input is incomplete")
	}
	descriptor := generation.Receipt.Descriptor
	result := IngestResult{
		AttemptID: attemptID, SourceID: descriptor.SourceID, GenerationID: descriptor.GenerationID,
		TransferSHA256: generation.Receipt.TransferSHA256, ReceiptSHA256: generation.ReceiptSHA256,
		Batches: len(generation.Batches), DataBytes: generation.Receipt.DataBytes,
	}

	tx, err := connection.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("begin FI relational generation transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()

	existingID, found, err := lookupRecordedGeneration(ctx, tx, descriptor.SourceID, descriptor.GenerationID, generation.Receipt.TransferSHA256, generation.ReceiptSHA256)
	if err != nil {
		return result, failIngestAttempt(ctx, connection, tx, result, "IdentityCheck", "DATABASE_IDENTITY_CHECK_FAILED", err)
	}
	if found {
		result.RecordedGenerationID = existingID
		result.RecordsSeen = int64(generation.Receipt.RecordCount)
		result.Outcome = "AlreadyAccepted"
		if err := tx.Rollback(ctx); err != nil {
			return result, fmt.Errorf("rollback FI already-accepted check: %w", err)
		}
		committed = true
		zero := int64(0)
		seen := result.RecordsSeen
		if err := WriteAttemptTerminal(ctx, connection, JournalEvent{
			AttemptID: attemptID, SourceID: result.SourceID, GenerationID: result.GenerationID, TransferSHA256: result.TransferSHA256,
			Outcome: "AlreadyAccepted", Stage: "IdentityCheck", RecordsSeen: &seen, RecordsCommitted: &zero,
		}); err != nil {
			return result, err
		}
		return result, nil
	}

	recordedGenerationID, err := insertRecordedGeneration(ctx, tx, generation)
	if err != nil {
		return result, failIngestAttempt(ctx, connection, tx, result, "AuthoritativeRecord", "GENERATION_INSERT_FAILED", err)
	}
	result.RecordedGenerationID = recordedGenerationID

	for _, batch := range generation.Batches {
		sourceBatchID, err := insertSourceBatch(ctx, tx, recordedGenerationID, batch)
		if err != nil {
			return result, failIngestAttempt(ctx, connection, tx, result, "AuthoritativeRecord", "SOURCE_BATCH_INSERT_FAILED", err)
		}
		seen, err := ingestSourceBatch(ctx, tx, descriptor.SourceID, sourceBatchID, batch)
		result.RecordsSeen += seen
		if err != nil {
			return result, rejectIngestAttempt(ctx, connection, tx, result, err)
		}
	}

	if result.RecordsSeen != int64(generation.Receipt.RecordCount) {
		return result, rejectIngestAttempt(ctx, connection, tx, result, fmt.Errorf("generation source-record count %d does not match recorder receipt %d", result.RecordsSeen, generation.Receipt.RecordCount))
	}
	if err := verifyGenerationProjectionCoverage(ctx, tx, recordedGenerationID); err != nil {
		return result, rejectIngestAttempt(ctx, connection, tx, result, err)
	}

	result.RecordsCommitted = result.RecordsSeen
	result.Outcome = "Accepted"
	seen := result.RecordsSeen
	committedCount := result.RecordsCommitted
	transfer, err := decodeHex(result.TransferSHA256, 32, true, "accepted.transfer_sha256")
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.ingest_journal (
 attempt_id,event_sequence,source_id,generation_id,transfer_sha256,outcome,stage,records_seen,records_committed,ingest_version
) VALUES ($1,2,$2,$3,$4,'Accepted','AuthoritativeRecord',$5,$6,$7)
`, attemptID, result.SourceID, result.GenerationID, transfer, seen, committedCount, IngestVersion)
	if err != nil {
		return result, fmt.Errorf("write FI accepted ingest journal event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("commit FI relational generation: %w", err)
	}
	committed = true
	return result, nil
}

func lookupRecordedGeneration(ctx context.Context, tx pgx.Tx, sourceID, generationID, transferSHA256, receiptSHA256 string) (int64, bool, error) {
	var id int64
	var storedTransfer []byte
	var storedReceipt []byte
	err := tx.QueryRow(ctx, `SELECT recorded_generation_id,transfer_sha256,receipt_sha256 FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`, sourceID, generationID).Scan(&id, &storedTransfer, &storedReceipt)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	wantTransfer, err := decodeHex(transferSHA256, 32, true, "generation.transfer_sha256")
	if err != nil {
		return 0, false, err
	}
	wantReceipt, err := decodeHex(receiptSHA256, 32, true, "generation.receipt_sha256")
	if err != nil {
		return 0, false, err
	}
	if !bytesEqual(storedTransfer, wantTransfer) || !bytesEqual(storedReceipt, wantReceipt) {
		return 0, false, ErrGenerationConflict
	}
	return id, true, nil
}

func insertRecordedGeneration(ctx context.Context, tx pgx.Tx, generation *PreparedGeneration) (int64, error) {
	receipt := generation.Receipt
	descriptor := receipt.Descriptor
	canonical, err := decodeHex(descriptor.CanonicalSHA256, 32, true, "generation.canonical_sha256")
	if err != nil {
		return 0, err
	}
	encoded, err := decodeHex(descriptor.EncodedDataSHA256, 32, true, "generation.encoded_data_sha256")
	if err != nil {
		return 0, err
	}
	metadata, err := decodeHex(receipt.MetadataSHA256, 32, true, "generation.metadata_sha256")
	if err != nil {
		return 0, err
	}
	transfer, err := decodeHex(receipt.TransferSHA256, 32, true, "generation.transfer_sha256")
	if err != nil {
		return 0, err
	}
	receiptSHA, err := decodeHex(generation.ReceiptSHA256, 32, true, "generation.receipt_sha256")
	if err != nil {
		return 0, err
	}
	var id int64
	err = tx.QueryRow(ctx, `
INSERT INTO fi.recorded_generation (
 receipt_version,descriptor_version,source_id,generation_id,canonical_version,data_encoding,artifact_count,source_bytes,
 canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
 batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
RETURNING recorded_generation_id
`, receipt.Version, descriptor.Version, descriptor.SourceID, descriptor.GenerationID, descriptor.CanonicalVersion, descriptor.DataEncoding,
		int64(descriptor.ArtifactCount), int64(descriptor.SourceBytes), int64(descriptor.CanonicalBytes), canonical, int64(descriptor.EncodedDataBytes), encoded,
		int64(receipt.MetadataBytes), metadata, int64(receipt.TransferBytes), transfer, int64(receipt.BatchCount), int64(receipt.DataBytes),
		int64(receipt.RecordCount), generation.ReceiptBytes, receiptSHA, IngestVersion).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert FI recorded generation: %w", err)
	}
	return id, nil
}

func insertSourceBatch(ctx context.Context, tx pgx.Tx, recordedGenerationID int64, batch PreparedBatch) (int64, error) {
	manifest := batch.Manifest
	dataSHA, err := decodeHex(manifest.DataSHA256, 32, true, "source_batch.data_sha256")
	if err != nil {
		return 0, err
	}
	collectorSHA, err := decodeHex(manifest.Collector.ExecutableSHA256, 32, true, "source_batch.collector_sha256")
	if err != nil {
		return 0, err
	}
	manifestSHA, err := decodeHex(batch.ManifestSHA256, 32, true, "source_batch.manifest_sha256")
	if err != nil {
		return 0, err
	}
	createdAt, err := parseRFC3339(manifest.CreatedAt, "source_batch.created_at")
	if err != nil {
		return 0, err
	}
	completedAt, err := parseRFC3339(manifest.CompletedAt, "source_batch.completed_at")
	if err != nil {
		return 0, err
	}
	var id int64
	err = tx.QueryRow(ctx, `
INSERT INTO fi.source_batch (
 recorded_generation_id,manifest_artifact_name,data_artifact_name,manifest_version,batch_id,target_batch_size,record_count,data_bytes,data_sha256,
 data_file,collector_executable_path,collector_executable_sha256,created_at,completed_at,manifest_bytes,manifest_sha256
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
RETURNING source_batch_id
`, recordedGenerationID, batch.ManifestArtifactName, batch.DataArtifactName, manifest.Version, manifest.BatchID, manifest.TargetBatchSize,
		int64(manifest.RecordCount), manifest.DataBytes, dataSHA, manifest.DataFile, manifest.Collector.ExecutablePath, collectorSHA, createdAt, completedAt,
		batch.ManifestBytes, manifestSHA).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert FI source batch: %w", err)
	}
	return id, nil
}

func ingestSourceBatch(ctx context.Context, tx pgx.Tx, sourceID string, sourceBatchID int64, batch PreparedBatch) (int64, error) {
	file, err := os.Open(batch.DataPath)
	if err != nil {
		return 0, fmt.Errorf("open FI staged source batch: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	hasher := sha256.New()
	var ordinal int64
	var byteCount int64
	for {
		raw, readErr := reader.ReadBytes('\n')
		if len(raw) == 0 && errors.Is(readErr, io.EOF) {
			break
		}
		if len(raw) == 0 && readErr != nil {
			return ordinal, fmt.Errorf("read FI source batch: %w", readErr)
		}
		if raw[len(raw)-1] != '\n' {
			return ordinal, fmt.Errorf("%w: batch %s record %d is missing final LF", ErrSourceRecordRejected, batch.BatchID, ordinal+1)
		}
		ordinal++
		byteCount += int64(len(raw))
		_, _ = hasher.Write(raw)

		prepared, err := PrepareSourceRecord(raw)
		if err != nil {
			return ordinal, fmt.Errorf("%w: batch %s record %d: %v", ErrSourceRecordRejected, batch.BatchID, ordinal, err)
		}
		digest, err := decodeHex(prepared.RecordSHA256, 32, true, "source_record.record_sha256")
		if err != nil {
			return ordinal, err
		}
		var sourceRecordID int64
		err = tx.QueryRow(ctx, `
INSERT INTO fi.source_record (
 source_batch_id,record_ordinal,version,record_kind,scope_id,written_at,record_bytes,record_sha256,ingest_version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING source_record_id
`, sourceBatchID, ordinal, prepared.Record.Version, prepared.Record.RecordKind, prepared.Record.ScopeID, prepared.WrittenAtUTC,
			prepared.RecordBytes, digest, IngestVersion).Scan(&sourceRecordID)
		if err != nil {
			return ordinal, fmt.Errorf("insert FI source record: %w", err)
		}
		if err := ProjectSourceRecord(ctx, tx, sourceID, sourceRecordID, prepared); err != nil {
			return ordinal, fmt.Errorf("%w: batch %s record %d (%s): %v", ErrSourceRecordRejected, batch.BatchID, ordinal, prepared.Record.RecordKind, err)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return ordinal, fmt.Errorf("%w: batch %s ended without final LF", ErrSourceRecordRejected, batch.BatchID)
			}
			return ordinal, fmt.Errorf("read FI source batch: %w", readErr)
		}
	}

	gotSHA := hex.EncodeToString(hasher.Sum(nil))
	if ordinal != int64(batch.Manifest.RecordCount) || byteCount != batch.Manifest.DataBytes || gotSHA != batch.Manifest.DataSHA256 {
		return ordinal, fmt.Errorf("%w: batch %s changed between custody validation and relational ingest", ErrSourceRecordRejected, batch.BatchID)
	}
	return ordinal, nil
}

func verifyGenerationProjectionCoverage(ctx context.Context, tx pgx.Tx, recordedGenerationID int64) error {
	var missing int64
	err := tx.QueryRow(ctx, `
SELECT count(*)
FROM fi.source_record sr
JOIN fi.source_batch sb ON sb.source_batch_id = sr.source_batch_id
WHERE sb.recorded_generation_id = $1
  AND CASE sr.record_kind
    WHEN 'CollectorIdentity' THEN NOT EXISTS (SELECT 1 FROM fi.collector_identity x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'DirectoryPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.directory_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'FileObservation' THEN NOT EXISTS (SELECT 1 FROM fi.file_observation x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'LocalPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.local_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'NTFSCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi.ntfs_collection_error x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'SMBShareSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.smb_share_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'SupportingSourceCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi.supporting_source_collection_error x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi.usn_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNObjectObservation' THEN NOT EXISTS (SELECT 1 FROM fi.usn_object_observation x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNReadBoundary' THEN NOT EXISTS (SELECT 1 FROM fi.usn_read_boundary x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityCoverage' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_coverage x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityEvent' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_event x WHERE x.source_record_id=sr.source_record_id)
    ELSE true
  END
`, recordedGenerationID).Scan(&missing)
	if err != nil {
		return fmt.Errorf("verify FI relational projection coverage: %w", err)
	}
	if missing != 0 {
		return fmt.Errorf("%w: %d source records lack their typed relational projection", ErrSourceRecordRejected, missing)
	}
	return nil
}

func rejectIngestAttempt(ctx context.Context, connection *pgx.Conn, tx pgx.Tx, result IngestResult, cause error) error {
	rollbackErr := tx.Rollback(ctx)
	seen := result.RecordsSeen
	zero := int64(0)
	journalErr := WriteAttemptTerminal(ctx, connection, JournalEvent{
		AttemptID: result.AttemptID, SourceID: result.SourceID, GenerationID: result.GenerationID, TransferSHA256: result.TransferSHA256,
		Outcome: "Rejected", Stage: "AuthoritativeRecord", ReasonCode: "SOURCE_RECORD_REJECTED", Detail: cause.Error(), RecordsSeen: &seen, RecordsCommitted: &zero,
	})
	return errors.Join(cause, rollbackErr, journalErr)
}

func failIngestAttempt(ctx context.Context, connection *pgx.Conn, tx pgx.Tx, result IngestResult, stage, reason string, cause error) error {
	rollbackErr := tx.Rollback(ctx)
	seen := result.RecordsSeen
	zero := int64(0)
	outcome := "Failed"
	if errors.Is(cause, ErrGenerationConflict) {
		outcome = "Conflict"
		reason = "GENERATION_IDENTITY_CONFLICT"
	}
	journalErr := WriteAttemptTerminal(ctx, connection, JournalEvent{
		AttemptID: result.AttemptID, SourceID: result.SourceID, GenerationID: result.GenerationID, TransferSHA256: result.TransferSHA256,
		Outcome: outcome, Stage: stage, ReasonCode: reason, Detail: cause.Error(), RecordsSeen: &seen, RecordsCommitted: &zero,
	})
	return errors.Join(cause, rollbackErr, journalErr)
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := range left {
		diff |= left[i] ^ right[i]
	}
	return diff == 0
}
