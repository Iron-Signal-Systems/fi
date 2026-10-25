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
)

// rawUSNPromotionResult describes recovery of the sealed namespace only.
// It never authorizes raw-byte reclamation or changes collector checkpoints.
type rawUSNPromotionResult struct {
	Promoted      int
	AlreadyActive int
}

// recoverCommittedRawUSNPromotions reconciles interrupted, previously
// authorized USN raw-source tombstones at sender startup.
//
// Every tombstone must independently pass full committed-ledger verification
// before ANY private sealed generation is promoted. The sender must own the
// stage and raw namespaces exclusively during this operation.
//
// Recovery is restartable:
//   - PRIVATE: verify and atomically rename into the active queue.
//   - ACTIVE: verify and leave unchanged.
//
// Raw tombstone bytes are never deleted or renamed by this function.
func recoverCommittedRawUSNPromotions(
	ctx context.Context,
	rawRoot, stageRoot, stateDir, sourceID string,
	maxEncodedBytes uint64,
) (rawUSNPromotionResult, error) {
	if ctx == nil {
		return rawUSNPromotionResult{},
			errors.New("FI USN promotion context required")
	}
	if maxEncodedBytes == 0 {
		return rawUSNPromotionResult{},
			errors.New("FI USN promotion encoded-byte ceiling required")
	}

	// Verify the complete tombstone census before changing any namespace.
	states, err := InspectRawUSNCustodyRecoveryWithCommittedState(
		ctx, rawRoot, stageRoot, stateDir, sourceID,
	)
	if err != nil {
		return rawUSNPromotionResult{}, fmt.Errorf(
			"verify all FI retired USN generations: %w", err,
		)
	}

	var result rawUSNPromotionResult

	for _, state := range states {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		// Revalidate exact signed payload and encoded-byte ceiling
		// at the namespace transition boundary.
		if _, err := loadTransportGenerationAt(
			state.SealedDir,
			sourceID,
			state.GenerationID,
			maxEncodedBytes,
		); err != nil {
			return result, fmt.Errorf(
				"recheck FI USN sealed replacement %s: %w",
				state.GenerationID, err,
			)
		}

		active := filepath.Join(
			stageRoot,
			generationDirectoryPrefix+state.GenerationID,
		)

		switch state.SealedState {
		case "ACTIVE":
			// Crash occurred after promotion, or this is an
			// ordinary restart. No second rename is necessary.
			if filepath.Clean(state.SealedDir) != filepath.Clean(active) {
				return result, fmt.Errorf(
					"%w: active generation namespace differs",
					ErrGenerationSourceCustodyConflict,
				)
			}
			result.AlreadyActive++

		case "PRIVATE":
			expectedPrivate := filepath.Join(
				stageRoot,
				generationTransportBuildRootDirectoryName,
				generationDirectoryPrefix+state.GenerationID,
			)

			if filepath.Clean(state.SealedDir) !=
				filepath.Clean(expectedPrivate) {
				return result, fmt.Errorf(
					"%w: private generation namespace differs",
					ErrGenerationSourceCustodyConflict,
				)
			}

			before, err := os.Lstat(state.SealedDir)
			if err != nil {
				return result, err
			}
			if before.Mode()&os.ModeSymlink != 0 ||
				!before.IsDir() {
				return result, fmt.Errorf(
					"%w: private sealed replacement is not a real directory",
					ErrGenerationSourceCustodyConflict,
				)
			}

			// A missing or replaced tombstone cannot be ignored
			// merely because the sealed generation verified.
			tombstone, err := os.Lstat(state.TombstoneDir)
			if err != nil {
				return result, err
			}
			if tombstone.Mode()&os.ModeSymlink != 0 ||
				!tombstone.IsDir() {
				return result, fmt.Errorf(
					"%w: raw USN tombstone is not a real directory",
					ErrGenerationSourceCustodyConflict,
				)
			}

			// Never replace an existing active generation.
			if _, err := os.Lstat(active); err == nil {
				return result, fmt.Errorf(
					"%w: active generation appeared during recovery",
					ErrGenerationSourceCustodyConflict,
				)
			} else if !errors.Is(err, os.ErrNotExist) {
				return result, err
			}

			if err := ctx.Err(); err != nil {
				return result, err
			}

			// FI's existing generation publisher performs the
			// durable namespace transition for the host OS.
			// Windows Lstat may defer loading the file ID until SameFile.
			// Resolve that identity while the private path still exists.
			// The post-rename check must compare against this identity.
			if !os.SameFile(before, before) {
				return result, fmt.Errorf(
					"%w: cannot establish private sealed directory identity before promotion",
					ErrGenerationSourceCustodyConflict,
				)
			}
			if err := publishGenerationDirectory(
				state.SealedDir, active,
			); err != nil {
				return result, fmt.Errorf(
					"promote verified FI USN generation %s: %w",
					state.GenerationID, err,
				)
			}

			after, err := os.Lstat(active)
			if err != nil || !os.SameFile(before, after) {
				return result, fmt.Errorf(
					"%w: promoted generation directory identity changed: %v",
					ErrGenerationSourceCustodyConflict, err,
				)
			}

			// A failed post-rename check leaves the generation in
			// the active namespace. Startup must fail closed; the
			// next restart will independently inspect it again.
			if _, err := loadTransportGenerationAt(
				active,
				sourceID,
				state.GenerationID,
				maxEncodedBytes,
			); err != nil {
				return result, fmt.Errorf(
					"verify FI USN generation after promotion %s: %w",
					state.GenerationID, err,
				)
			}
			result.Promoted++

		default:
			return result, fmt.Errorf(
				"%w: unknown sealed custody state %q",
				ErrGenerationSourceCustodyConflict,
				state.SealedState,
			)
		}
	}

	return result, nil
}
