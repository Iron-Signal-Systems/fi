// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
)

// BacklogReplaySummary describes a completed, read-only replay of one
// private source-record window. It NEVER means typed projection or generation
// acceptance has been committed.
type BacklogReplaySummary struct {
	BatchCount int
	RecordCount uint64
	DataBytes uint64
	ReceiptSHA256 string
	WindowDigestSHA256 string
}

// ReplayVerifiedBacklogSourceWindow supplies original FI source records in
// exact source-batch / record ordinal order, after preflight checks of BOTH
// the durable private bytes and committed private SQL source-row lineage.
//
// visit must be read-only and side-effect free: a future projector must
// transact its changes separately and roll back on ANY failure. This function
// cannot publish or modify fi.* tables, and does not create durable typed
// projections. It is an opt-in engineering seam, not used by production FI.
func ReplayVerifiedBacklogSourceWindow(
	ctx context.Context,
	connection *pgx.Conn,
	g *PreparedGeneration,
	limits BacklogWindowLimits,
	index int,
	privateRoot string,
	visit func(batchIndex int, ordinal int64, record SourceRecord) error,
) (BacklogReplaySummary, error) {
	if ctx == nil || connection == nil || visit == nil {
		return BacklogReplaySummary{}, errors.New("FI backlog replay: context, connection and visitor required")
	}
	if err := ctx.Err(); err != nil { return BacklogReplaySummary{}, err }
	descriptors,err:=DescribeBacklogWindows(g,limits)
	if err!=nil {return BacklogReplaySummary{},err}
	if index<0 || index>=len(descriptors) {return BacklogReplaySummary{},errors.New("FI backlog replay: window index out of bounds")}
	d:=descriptors[index]
	if d.EndRecord>math.MaxInt64 || d.DataBytes>math.MaxInt64 {
		return BacklogReplaySummary{},errors.New("FI backlog replay: SQL bigint limits exceeded")
	}
	if err:=VerifyMaterializedBacklogWindow(ctx,g,limits,index,privateRoot);err!=nil {
		return BacklogReplaySummary{},fmt.Errorf("FI backlog replay: private artifact validation: %w",err)
	}
	var who,db string
	if err:=connection.QueryRow(ctx,"SELECT current_user,current_database()").Scan(&who,&db);err!=nil{
		return BacklogReplaySummary{},err
	}
	if who!="fi_ingest"||db!="fi" {return BacklogReplaySummary{},fmt.Errorf("FI backlog replay: unexpected SQL identity %s/%s",who,db)}
	receipt,err:=hex.DecodeString(d.ReceiptSHA256);if err!=nil{return BacklogReplaySummary{},err}
	descriptorDigest,err:=hex.DecodeString(d.DigestSHA256);if err!=nil{return BacklogReplaySummary{},err}
	previousDigest,err:=hex.DecodeString(d.PreviousDigestSHA256);if err!=nil{return BacklogReplaySummary{},err}
	// Separate transaction gives the marker and all row metadata one MVCC
	// snapshot. Only read FI's private recovery schema here.
	tx,err:=connection.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
	if err!=nil{return BacklogReplaySummary{},err}
	defer tx.Rollback(context.Background())
	var markerDigest,markerDescriptor,markerPrevious []byte
	var startBatch,endBatch int
	var startRecord,endRecord,stagedRecords,stagedBytes int64
	err=tx.QueryRow(ctx,`
SELECT rows_digest_sha256,descriptor_sha256,previous_digest_sha256,
       start_batch,end_batch,start_record,end_record,staged_records,staged_bytes
FROM fi_recovery.source_window
WHERE receipt_sha256=$1 AND window_index=$2
`,receipt,index).Scan(&markerDigest,&markerDescriptor,&markerPrevious,
		&startBatch,&endBatch,&startRecord,&endRecord,&stagedRecords,&stagedBytes)
	if err!=nil{return BacklogReplaySummary{},fmt.Errorf("FI backlog replay: completed private source window required: %w",err)}
	if subtle.ConstantTimeCompare(markerDescriptor,descriptorDigest)!=1 ||
		subtle.ConstantTimeCompare(markerPrevious,previousDigest)!=1 ||
		startBatch!=d.StartBatch || endBatch!=d.EndBatch ||
		startRecord!=int64(d.StartRecord) || endRecord!=int64(d.EndRecord) ||
		stagedRecords!=int64(d.EndRecord-d.StartRecord) ||
		stagedBytes!=int64(d.DataBytes) {
		return BacklogReplaySummary{},errors.New("FI backlog replay: completed private source marker mismatch")
	}
	dbHash,dbRecords,dbBytes,err:=hashBacklogDatabaseSourceRows(ctx,tx,receipt,index)
	if err!=nil{return BacklogReplaySummary{},err}
	if dbRecords!=uint64(stagedRecords)||dbBytes!=uint64(stagedBytes) ||
		subtle.ConstantTimeCompare(dbHash,markerDigest)!=1 {
		return BacklogReplaySummary{},errors.New("FI backlog replay: committed private SQL source rows differ from completed marker")
	}
	// Validate the entire source stream against its committed SQL identity
	// BEFORE invoking the caller. This prevents any unvalidated, late
	// corrupt record from reaching the projection interface.
	sourceHash,records,bytes,err:=scanBacklogWindowRecords(ctx,g,d,index,privateRoot,nil)
	if err!=nil{return BacklogReplaySummary{},err}
	if records!=dbRecords||bytes!=dbBytes||subtle.ConstantTimeCompare(sourceHash,dbHash)!=1 {
		return BacklogReplaySummary{},errors.New("FI backlog replay: signed source and committed SQL source digest disagree")
	}
	if err:=tx.Commit(ctx);err!=nil{return BacklogReplaySummary{},err}
	// Re-read on replay to detect modification between preflight and delivery;
	// if it occurs, fail the replay. Callers MUST discard consumer results on
	// any failure. The visitor receives no SQL connection/transaction.
	replayedDigest,replayedRecords,replayedBytes,err:=scanBacklogWindowRecords(ctx,g,d,index,privateRoot,visit)
	if err!=nil{return BacklogReplaySummary{},err}
	if replayedRecords!=records||replayedBytes!=bytes||subtle.ConstantTimeCompare(replayedDigest,sourceHash)!=1{
		return BacklogReplaySummary{},errors.New("FI backlog replay: source changed during delivery")
	}
	return BacklogReplaySummary{
		BatchCount:d.EndBatch-d.StartBatch,
		RecordCount:records,
		DataBytes:bytes,
		ReceiptSHA256:d.ReceiptSHA256,
		WindowDigestSHA256:d.DigestSHA256,
	},nil
}
