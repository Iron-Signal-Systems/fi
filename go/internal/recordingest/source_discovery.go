// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

// DiscoverRecordedReceiptsForSource searches only the requested source's
// authoritative directory. A missing or invalid namespace fails closed.
func DiscoverRecordedReceiptsForSource(
	recordedRoot string,
	sourceID string,
) ([]RecordedReceiptCandidate, error) {
	sourceRoot, err :=
		generationrecorder.RecordedSourceDirectory(
			recordedRoot,
			sourceID,
		)
	if err != nil {
		return nil, err
	}

	candidates, err := DiscoverRecordedReceipts(
		sourceRoot,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"discover FI recorded source %q: %w",
			sourceID,
			err,
		)
	}

	for _, candidate := range candidates {
		if candidate.SourceID != sourceID {
			return nil, fmt.Errorf(
				"FI authoritative source namespace %q contains receipt belonging to %q",
				sourceID,
				candidate.SourceID,
			)
		}
	}

	return candidates, nil
}
