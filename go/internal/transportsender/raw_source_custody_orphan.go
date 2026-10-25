// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// inspectSourceCustodyReceiptNamespaces checks the durable sender receipt
// inventory before recovery promotes or reconciles sealed generations.
//
// Until acknowledged-transport and raw-source reclamation are coordinated,
// every recorded USN source must retain either its original raw directory
// or its durable raw retirement tombstone.
//
// This is a read-only safety gate. It is not retirement authorization.
func inspectSourceCustodyReceiptNamespaces(
	ctx context.Context,
	rawRoot, stageRoot, sourceID string,
) error {
	if ctx == nil {
		return errors.New("FI source custody inspection requires context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRawGenerationRoot(rawRoot); err != nil {
		return err
	}
	if err := validateGenerationStageRoot(stageRoot); err != nil {
		return err
	}
	if strings.TrimSpace(sourceID) == "" {
		return errors.New("FI source custody inspection requires source ID")
	}

	receiptRoot := filepath.Join(
		stageRoot, generationSourceCustodyDirectory,
	)

	info, err := os.Lstat(receiptRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf(
			"%w: source custody receipt root is not a real directory",
			ErrGenerationSourceCustodyConflict,
		)
	}

	entries, err := os.ReadDir(receiptRoot)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}

		name := entry.Name()
		if !entry.Type().IsRegular() ||
			!strings.HasPrefix(name, generationDirectoryPrefix) ||
			!strings.HasSuffix(name, ".json") {
			return fmt.Errorf(
				"%w: unexpected source custody receipt object %q",
				ErrGenerationSourceCustodyConflict, name,
			)
		}

		receipt, found, err := readSourceCustodyReceipt(
			filepath.Join(receiptRoot, name),
		)
		if err != nil {
			return err
		}
		if !found ||
			name != generationDirectoryPrefix+receipt.GenerationID+".json" ||
			receipt.SourceID != sourceID {
			return fmt.Errorf(
				"%w: receipt filename or source identity differs",
				ErrGenerationSourceCustodyConflict,
			)
		}

		rawPath := filepath.Join(
			rawRoot, generationDirectoryPrefix+receipt.GenerationID,
		)
		tombstonePath := filepath.Join(
			rawRoot, rawUSNSourceRetiredPrefix+receipt.GenerationID,
		)

		rawExists, err := inspectRawCustodyRecoveryNamespace(rawPath)
		if err != nil {
			return err
		}
		tombstoneExists, err := inspectRawCustodyRecoveryNamespace(
			tombstonePath,
		)
		if err != nil {
			return err
		}

		switch {
		case rawExists && tombstoneExists:
			return fmt.Errorf(
				"%w: raw source and tombstone both exist for %s",
				ErrGenerationSourceCustodyConflict,
				receipt.GenerationID,
			)

		case !rawExists && !tombstoneExists:
			return fmt.Errorf(
				"%w: generation %s has a custody receipt but neither raw source nor tombstone",
				ErrSourceCustodyHandoffRequired,
				receipt.GenerationID,
			)
		}
	}

	return nil
}
