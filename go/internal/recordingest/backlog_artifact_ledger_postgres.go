// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
)

// RecordVerifiedBacklogArtifactWindow appends a private verified-FILE-COPY
// checkpoint to a separately isolated recovery schema. The caller must first
// have used FI's signed-custody loader to obtain a PreparedGeneration.
//
// In particular this is NOT a checkpoint for completed relational ingestion,
// NOT acceptance of a generation, and NOT authority for query publication.
// Only the isolated fixture currently installs fi_recovery. Production FI
// does not call this function or install the schema.
func RecordVerifiedBacklogArtifactWindow(
	ctx context.Context,
	connection *pgx.Conn,
	generation *PreparedGeneration,
	limits BacklogWindowLimits,
	index int,
	privateRoot string,
) error {
	if ctx == nil || connection == nil {
		return errors.New("FI recovery artifact ledger: context and connection required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	descriptors, err := DescribeBacklogWindows(generation, limits)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(descriptors) {
		return errors.New("FI recovery artifact ledger: window index outside validated receipt")
	}
	d := descriptors[index]
	if d.StartRecord > math.MaxInt64 || d.EndRecord > math.MaxInt64 ||
		d.DataBytes > math.MaxInt64 {
		return errors.New("FI recovery artifact ledger: source totals exceed SQL bigint")
	}

	// Full byte re-verification is required for every reuse; the presence
	// of a previously committed ledger row does not establish disk integrity.
	if err := VerifyMaterializedBacklogWindow(ctx, generation, limits, index, privateRoot); err != nil {
		return fmt.Errorf("FI recovery artifact ledger: private artifact verification failed: %w", err)
	}

	var currentUser, currentDatabase string
	if err := connection.QueryRow(ctx,
		"SELECT current_user, current_database()").Scan(&currentUser, &currentDatabase); err != nil {
		return err
	}
	if currentUser != "fi_ingest" || currentDatabase != "fi" {
		return fmt.Errorf("FI recovery artifact ledger: wrong runtime database identity %s/%s", currentUser, currentDatabase)
	}

	receipt, err := hex.DecodeString(d.ReceiptSHA256)
	if err != nil {
		return err
	}
	transfer, err := hex.DecodeString(d.TransferSHA256)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(d.DigestSHA256)
	if err != nil {
		return err
	}
	previous, err := hex.DecodeString(d.PreviousDigestSHA256)
	if err != nil {
		return err
	}

	tx, err := connection.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	// An advisory lock serializes writers for the same original signed
	// receipt. Hash collisions only over-serialize unrelated receipts.
	serial := int64(binary.BigEndian.Uint64(receipt[:8]))
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1::bigint)", serial); err != nil {
		return fmt.Errorf("FI recovery artifact ledger: acquire receipt lock: %w", err)
	}

	var accepted bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM fi.recorded_generation
    WHERE source_id=$1 AND generation_id=$2
)
`, d.SourceID, d.GenerationID).Scan(&accepted); err != nil {
		return err
	}
	if accepted {
		return errors.New("FI recovery artifact ledger: original generation is already accepted")
	}

	// If the requested window is already present, require exact identity.
	// Never repair, replace, or update an existing checkpoint silently.
	var existingDigest, existingPrevious, existingTransfer []byte
	var existingSource, existingGeneration string
	var existingStartBatch, existingEndBatch int64
	var existingStartRecord, existingEndRecord, existingBytes int64
	err = tx.QueryRow(ctx, `
SELECT descriptor_sha256, previous_digest_sha256, transfer_sha256,
       source_id, generation_id, start_batch, end_batch,
       start_record, end_record, data_bytes
FROM fi_recovery.verified_artifact_window
WHERE receipt_sha256=$1 AND window_index=$2
`, receipt, index).Scan(
		&existingDigest, &existingPrevious, &existingTransfer,
		&existingSource, &existingGeneration, &existingStartBatch, &existingEndBatch,
		&existingStartRecord, &existingEndRecord, &existingBytes,
	)
	if err == nil {
		if subtle.ConstantTimeCompare(existingDigest, digest) != 1 || subtle.ConstantTimeCompare(existingPrevious, previous) != 1 ||
			subtle.ConstantTimeCompare(existingTransfer, transfer) != 1 ||
			existingSource != d.SourceID || existingGeneration != d.GenerationID ||
			existingStartBatch != int64(d.StartBatch) || existingEndBatch != int64(d.EndBatch) ||
			existingStartRecord != int64(d.StartRecord) || existingEndRecord != int64(d.EndRecord) ||
			existingBytes != int64(d.DataBytes) {
			return errors.New("FI recovery artifact ledger: conflicting existing artifact checkpoint")
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	// Append strictly after the previous verified-artifact window. Even if
	// the next window's files exist, we never create holes in the ledger.
	var lastIndex int
	var lastDigest []byte
	var lastEndBatch, lastEndRecord int64
	err = tx.QueryRow(ctx, `
SELECT window_index, descriptor_sha256, end_batch, end_record
FROM fi_recovery.verified_artifact_window
WHERE receipt_sha256=$1
ORDER BY window_index DESC
LIMIT 1
`, receipt).Scan(&lastIndex, &lastDigest, &lastEndBatch, &lastEndRecord)
	if errors.Is(err, pgx.ErrNoRows) {
		if index != 0 || d.StartBatch != 0 || d.StartRecord != 0 {
			return errors.New("FI recovery artifact ledger: first checkpoint must begin at window zero")
		}
	} else if err != nil {
		return err
	} else if lastIndex+1 != index ||
		subtle.ConstantTimeCompare(lastDigest, previous) != 1 ||
		lastEndBatch != int64(d.StartBatch) ||
		lastEndRecord != int64(d.StartRecord) {
		return errors.New("FI recovery artifact ledger: skipped or conflicting window boundary")
	}

	_, err = tx.Exec(ctx, `
INSERT INTO fi_recovery.verified_artifact_window (
 receipt_sha256, window_index, source_id, generation_id,
 transfer_sha256, descriptor_sha256, previous_digest_sha256,
 start_batch, end_batch, start_record, end_record, data_bytes
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
`, receipt, index, d.SourceID, d.GenerationID,
		transfer, digest, previous, d.StartBatch, d.EndBatch,
		int64(d.StartRecord), int64(d.EndRecord), int64(d.DataBytes))
	if err != nil {
		return fmt.Errorf("FI recovery artifact ledger: append: %w", err)
	}
	return tx.Commit(ctx)
}
