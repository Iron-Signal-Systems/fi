//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Local fi-sor read-only verification of newly admitted signed metadata.
// This replaces the old development-schema START lookup in the active
// two-jail C1 service. It authorizes no replay and no canonical acceptance.
package recordingest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
	"github.com/jackc/pgx/v5"
)

func (s *C1SoRService) validateSignedPendingStage(ctx context.Context,
	f c1handoff.Frame, allowReconciledReplay ...bool) ([]int64, error) {
	if s == nil || ctx == nil || f.Kind != c1handoff.Start || f.StartBatchIndex != 0 {
		return nil, errors.New("C1 pending: unsupported replay or unsigned Start")
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(f.ReceiptSHA256)
	if err != nil || len(digest) != 32 {
		return nil, errors.New("C1 pending: invalid original signed receipt")
	}
	conn, _, err := openC1SoRLocalSQL(ctx, s.DSN, "")
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	var already bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fi.recorded_generation
		WHERE source_id=$1 AND generation_id=$2)`,
		f.SourceID, f.GenerationID).Scan(&already); err != nil {
		return nil, err
	}
	if already {
		return nil, errors.New("C1 pending: generation already exists in canonical SoR")
	}
	var controlCount int64
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM fi_c1_pending.generation_control").
		Scan(&controlCount); err != nil {
		return nil, err
	}
	if controlCount != 1 {
		return nil, errors.New("C1 pending: exactly one governed signed-generation control required")
	}
	var generationID, records, batches int64
	var state string
	var verifiedSHA []byte
	var verifierAt *string
	// The FK ties the control to immutable original signed generation
	// metadata, not an ingest-supplied proof or a shadow receipt cache.
	err = tx.QueryRow(ctx, `SELECT g.recorded_generation_id,g.record_count,g.batch_count,
		c.state,c.verifier_b_receipt_sha256,c.verifier_b_at::text
		FROM fi_c1_pending.recorded_generation g
		JOIN fi_c1_pending.generation_control c
		  ON c.source_id=g.source_id AND c.generation_id=g.generation_id
		 AND c.receipt_sha256=g.receipt_sha256
		 AND c.transfer_sha256=g.transfer_sha256
		 AND c.record_count=g.record_count AND c.batch_count=g.batch_count
		WHERE g.source_id=$1 AND g.generation_id=$2 AND g.receipt_sha256=$3`,
		f.SourceID, f.GenerationID, digest).
		Scan(&generationID, &records, &batches, &state, &verifiedSHA, &verifierAt)
	if err != nil {
		return nil, fmt.Errorf("C1 pending: exact signed admission control missing: %w", err)
	}
	if state != "Pending" || verifiedSHA != nil || verifierAt != nil ||
		generationID <= 0 || records != f.ExpectedRecords ||
		batches != int64(len(f.BatchIDs)) {
		return nil, errors.New("C1 pending: metadata, record count or verifier state differs from signed Start")
	}
	var actualBatches, declaredRecords int64
	err = tx.QueryRow(ctx, `SELECT count(*),coalesce(sum(record_count),0)::bigint
		FROM fi_c1_pending.source_batch WHERE recorded_generation_id=$1`,
		generationID).Scan(&actualBatches, &declaredRecords)
	if err != nil {
		return nil, err
	}
	if actualBatches != batches || declaredRecords != records {
		return nil, errors.New("C1 pending: incomplete original signed source batch ledger")
	}
	original := make([]PreparedBatch, len(f.BatchIDs))
	for i, name := range f.BatchIDs {
		original[i].BatchID = name
	}
	ids, err := lookupBacklogShadowBatchIDs(ctx,
		privateProjectionTx{Tx: tx, schema: c1GovernedPendingSchema},
		generationID, original)
	if err != nil {
		return nil, fmt.Errorf("C1 pending: exact source batch order/SQL identities: %w", err)
	}
	if len(ids) != len(f.BatchIDs) {
		return nil, errors.New("C1 pending: incomplete source batch SQL identity map")
	}
	var typed, journal int64
	err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM fi_c1_pending.source_record),
		(SELECT count(*) FROM fi_c1_pending.ingest_journal)`).
		Scan(&typed, &journal)
	if err != nil {
		return nil, err
	}
	if journal != 0 || typed<0 || typed>records {
        return nil, errors.New("C1 pending: invalid committed SourceParent count or staged journal")
    }
    if typed!=0&&(len(allowReconciledReplay)!=1||!allowReconciledReplay[0]){
        return nil,errors.New("C1 pending: dirty SourceParent stage requires separately audited replay")
    }
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return ids, nil
}
