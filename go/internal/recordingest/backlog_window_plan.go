// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"errors"
	"fmt"
	"math"
)

// BacklogWindowLimits bound a planning unit, not a signed generation.
// Data bytes refer to original source-batch data and not WAL or host memory.
// Neither limit grants authority to publish partially ingested evidence.
type BacklogWindowLimits struct {
	MaxRecords   uint64
	MaxDataBytes uint64
}

// BacklogWindow is an immutable index range over source batches in the
// original, already-verified signed generation. Both end indices are exclusive.
// It neither changes identities nor implies a durable ingestion checkpoint.
type BacklogWindow struct {
	StartBatch  int
	EndBatch    int
	StartRecord uint64
	EndRecord   uint64
	DataBytes   uint64
}

// PlanBacklogWindows prepares deterministic whole-batch windows for a
// validated PreparedGeneration. This function does no I/O or database writes.
// It cannot split an authenticated source batch. The original signed receipt
// remains the only generation authority; windows are never separate generations.
func PlanBacklogWindows(generation *PreparedGeneration, limits BacklogWindowLimits) ([]BacklogWindow, error) {
	if generation == nil {
		return nil, errors.New("FI backlog windows: prepared generation required")
	}
	if limits.MaxRecords == 0 || limits.MaxDataBytes == 0 {
		return nil, errors.New("FI backlog windows: nonzero record and byte limits required")
	}
	if len(generation.Batches) == 0 {
		return nil, errors.New("FI backlog windows: generation has no source batches")
	}
	if generation.Receipt.BatchCount != uint64(len(generation.Batches)) {
		return nil, fmt.Errorf("FI backlog windows: receipt batches %d != staged batches %d", generation.Receipt.BatchCount, len(generation.Batches))
	}
	windows := make([]BacklogWindow, 0, len(generation.Batches)/8+1)
	current := BacklogWindow{StartBatch: 0}
	var totalRecords, totalBytes uint64
	previousID := ""
	for i, batch := range generation.Batches {
		m := batch.Manifest
		if batch.BatchID == "" || m.BatchID != batch.BatchID ||
			m.DataFile != "batch-"+batch.BatchID+".jsonl" ||
			m.RecordCount <= 0 || m.TargetBatchSize <= 0 || m.RecordCount > m.TargetBatchSize || m.DataBytes <= 0 {
			return nil, fmt.Errorf("FI backlog windows: source batch %d has invalid or inconsistent manifest", i)
		}
		if previousID != "" && batch.BatchID <= previousID {
			return nil, fmt.Errorf("FI backlog windows: source batch %d is duplicated or out of order", i)
		}
		previousID = batch.BatchID
		records, bytes := uint64(m.RecordCount), uint64(m.DataBytes)
		if records > limits.MaxRecords || bytes > limits.MaxDataBytes {
			return nil, fmt.Errorf("FI backlog windows: intact source batch %d exceeds window budget (records=%d bytes=%d)", i, records, bytes)
		}
		if records > math.MaxUint64-totalRecords || bytes > math.MaxUint64-totalBytes {
			return nil, errors.New("FI backlog windows: source totals overflow uint64")
		}
		if current.EndBatch > current.StartBatch &&
			(records > limits.MaxRecords-(current.EndRecord-current.StartRecord) ||
				bytes > limits.MaxDataBytes-current.DataBytes) {
			windows = append(windows, current)
			current = BacklogWindow{StartBatch: i, StartRecord: totalRecords, EndRecord: totalRecords}
		}
		current.EndBatch = i+1
		current.EndRecord += records
		current.DataBytes += bytes
		totalRecords += records
		totalBytes += bytes
	}
	if current.EndBatch > current.StartBatch {
		windows = append(windows, current)
	}
	if generation.Receipt.RecordCount != totalRecords || generation.Receipt.DataBytes != totalBytes {
		return nil, fmt.Errorf("FI backlog windows: receipt totals mismatch records=%d/%d bytes=%d/%d", totalRecords, generation.Receipt.RecordCount, totalBytes, generation.Receipt.DataBytes)
	}
	if len(windows) == 0 || windows[0].StartBatch != 0 || windows[0].StartRecord != 0 ||
		windows[len(windows)-1].EndBatch != len(generation.Batches) || windows[len(windows)-1].EndRecord != totalRecords {
		return nil, errors.New("FI backlog windows: incomplete generation coverage")
	}
	for i, window := range windows {
		if window.EndBatch <= window.StartBatch || window.EndRecord <= window.StartRecord ||
			window.EndRecord-window.StartRecord > limits.MaxRecords || window.DataBytes > limits.MaxDataBytes {
			return nil, errors.New("FI backlog windows: invalid window bounds")
		}
		if i > 0 && (windows[i-1].EndBatch != window.StartBatch || windows[i-1].EndRecord != window.StartRecord) {
			return nil, errors.New("FI backlog windows: noncontiguous generation coverage")
		}
	}
	return windows, nil
}
