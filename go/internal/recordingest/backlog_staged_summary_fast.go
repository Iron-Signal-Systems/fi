// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// SummarizeCommittedBacklogSourceWindow reads the source marker already
// atomically committed by StageVerifiedBacklogSourceWindow and groups its
// source-record kinds without parsing or rehashing the staged JSONL again.
//
// This is a deliberate private-recovery fast path, NOT a replacement for
// ReplayVerifiedBacklogSourceWindow's independent byte-for-byte auditing API.
// The original staging pass verified both source bytes and persisted SQL rows;
// typed ingestion independently reads and hashes every original source batch.
// No generation acceptance/publication is performed here.
func SummarizeCommittedBacklogSourceWindow(
	ctx context.Context,
	conn *pgx.Conn,
	g *PreparedGeneration,
	limits BacklogWindowLimits,
	index int,
	visitKind func(kind string, count uint64) error,
) (BacklogReplaySummary, error) {
	var empty BacklogReplaySummary
	if ctx == nil || conn == nil || g == nil || visitKind == nil {
		return empty, errors.New("FI fast source summary: context, connection, generation and callback required")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	descriptors, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		return empty, err
	}
	if index < 0 || index >= len(descriptors) {
		return empty, errors.New("FI fast source summary: window index out of range")
	}
	d := descriptors[index]
	if d.EndRecord > math.MaxInt64 || d.DataBytes > math.MaxInt64 {
		return empty, errors.New("FI fast source summary: SQL bigint bounds")
	}
	receipt, err := hex.DecodeString(d.ReceiptSHA256)
	if err != nil {
		return empty, err
	}
	descriptor, err := hex.DecodeString(d.DigestSHA256)
	if err != nil {
		return empty, err
	}
	previous, err := hex.DecodeString(d.PreviousDigestSHA256)
	if err != nil {
		return empty, err
	}

	began := time.Now()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback(context.Background())

	var storedDigest, storedPrevious []byte
	var fromBatch, toBatch int
	var fromRecord, toRecord, stagedRecords, stagedBytes int64
	err = tx.QueryRow(ctx, `
SELECT descriptor_sha256,previous_digest_sha256,start_batch,end_batch,
       start_record,end_record,staged_records,staged_bytes
FROM fi_recovery.source_window
WHERE receipt_sha256=$1 AND window_index=$2
`, receipt, index).Scan(&storedDigest, &storedPrevious, &fromBatch, &toBatch,
		&fromRecord, &toRecord, &stagedRecords, &stagedBytes)
	if err != nil {
		return empty, fmt.Errorf("FI fast source summary: committed source marker missing: %w", err)
	}
	if subtle.ConstantTimeCompare(storedDigest, descriptor) != 1 ||
		subtle.ConstantTimeCompare(storedPrevious, previous) != 1 ||
		fromBatch != d.StartBatch || toBatch != d.EndBatch ||
		fromRecord != int64(d.StartRecord) || toRecord != int64(d.EndRecord) ||
		stagedRecords != int64(d.EndRecord-d.StartRecord) || stagedBytes != int64(d.DataBytes) {
		return empty, errors.New("FI fast source summary: committed source marker differs from signed window")
	}

	// These rows were hash-verified against the signed staged data in the
	// source-stage transaction; a grouped SELECT replaces ~32K extra JSON
	// decodes and a complete byte-by-byte database rehash per typed window.
	rows, err := tx.Query(ctx, `
SELECT record_kind, count(*)::bigint
FROM fi_recovery.pending_source_record
WHERE receipt_sha256=$1 AND window_index=$2
GROUP BY record_kind
`, receipt, index)
	if err != nil {
		return empty, err
	}
	var total uint64
	for rows.Next() {
		var kind string
		var count int64
		if err := rows.Scan(&kind, &count); err != nil {
			rows.Close()
			return empty, err
		}
		if kind == "" || count <= 0 || uint64(count) > uint64(stagedRecords)-total {
			rows.Close()
			return empty, errors.New("FI fast source summary: invalid family counts")
		}
		if err := visitKind(kind, uint64(count)); err != nil {
			rows.Close()
			return empty, err
		}
		total += uint64(count)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return empty, rowErr
	}
	if total != uint64(stagedRecords) {
		return empty, fmt.Errorf("FI fast source summary: SQL family total %d differs from staged records %d", total, stagedRecords)
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, err
	}
	fmt.Printf("FI FAST SOURCE SUMMARY window=%d records=%d elapsed=%s source_replay_scans=0\n",
		index, total, time.Since(began).Round(time.Millisecond))
	return BacklogReplaySummary{
		BatchCount:         d.EndBatch - d.StartBatch,
		RecordCount:        total,
		DataBytes:          uint64(stagedBytes),
		ReceiptSHA256:      d.ReceiptSHA256,
		WindowDigestSHA256: d.DigestSHA256,
	}, nil
}
