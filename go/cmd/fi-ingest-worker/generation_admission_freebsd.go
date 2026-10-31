// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

// Zero limits preserve the original unrestricted worker behavior.
// Oversized generations remain pending; no attempt journal is written.
func fiCheckGenerationAdmission(
	config workerConfig,
	candidate recordingest.RecordedReceiptCandidate,
) error {
	if config.MaxGenerationRecords != 0 &&
		candidate.RecordCount > config.MaxGenerationRecords {
		return fmt.Errorf(
			"FI GENERATION ADMISSION BLOCKED source=%q generation=%q record_count=%d max_generation_records=%d: remains pending; no attempt started",
			candidate.SourceID, candidate.GenerationID,
			candidate.RecordCount, config.MaxGenerationRecords,
		)
	}

	if config.MaxGenerationDataBytes != 0 &&
		candidate.DataBytes > config.MaxGenerationDataBytes {
		return fmt.Errorf(
			"FI GENERATION ADMISSION BLOCKED source=%q generation=%q data_bytes=%d max_generation_data_bytes=%d: remains pending; no attempt started",
			candidate.SourceID, candidate.GenerationID,
			candidate.DataBytes, config.MaxGenerationDataBytes,
		)
	}

	return nil
}
