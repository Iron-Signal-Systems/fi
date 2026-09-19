// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// finalizeSpoolWriterOnReturn gives every post-NewWriter return path one final
// opportunity to resolve an accepted batch.
//
// An earlier collection error remains authoritative even if this Close succeeds:
// source checkpoint/state advancement must not occur after an incomplete
// collection attempt. Any Close error is joined rather than discarded.
//
// FinalizedBatches is refreshed after Close so error summaries accurately report
// records that nevertheless reached durable FI custody.
func finalizeSpoolWriterOnReturn(
	writer *spool.Writer,
	batches *[]spool.FinalizedBatch,
	verifiedBatches *int,
	returnErr *error,
) {
	if writer == nil {
		return
	}

	closeErr :=
		writer.Close()

	finalized :=
		writer.FinalizedBatches()

	if batches != nil {
		*batches =
			finalized
	}

	if verifiedBatches != nil {
		*verifiedBatches =
			len(finalized)
	}

	if returnErr != nil {
		*returnErr =
			errors.Join(
				*returnErr,
				closeErr,
			)
	}
}
