// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// RawUSNCustodyRecoveryState identifies the sealed replacement accompanying
// a retired raw USN source. Inspection never promotes or deletes either.
type RawUSNCustodyRecoveryState struct {
	GenerationID string
	TombstoneDir string
	SealedDir    string
	SealedState  string
}

// InspectRawUSNCustodyRecovery inventories interrupted raw-source retirement.
// Each tombstone must have exactly one sealed replacement and an unchanged
// identity-bound custody receipt. No filesystem changes are performed.
//
// This inspection does not rerun the complete committed source-ledger
// preflight. Its result is NOT authorization to promote, reclaim, or retire
// any generation. The caller must retain the fail-closed recovery boundary.
func InspectRawUSNCustodyRecovery(
	ctx context.Context,
	rawRoot, stageRoot, sourceID string,
) ([]RawUSNCustodyRecoveryState, error) {
	if ctx == nil {
		return nil, errors.New("FI raw custody recovery requires context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateRawGenerationRoot(rawRoot); err != nil {
		return nil, err
	}
	if err := validateGenerationStageRoot(stageRoot); err != nil {
		return nil, err
	}
	if strings.TrimSpace(sourceID) == "" {
		return nil, errors.New("FI source identity required")
	}

	entries, err := os.ReadDir(rawRoot)
	if err != nil {
		return nil, err
	}

	result := make([]RawUSNCustodyRecoveryState, 0)

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		name := entry.Name()
		if !strings.HasPrefix(name, rawUSNSourceRetiredPrefix) {
			continue
		}

		generationID := strings.TrimPrefix(
			name, rawUSNSourceRetiredPrefix,
		)

		if generationID == "" ||
			len(generationID) > 128 ||
			strings.ContainsAny(generationID, `\/:`) ||
			strings.TrimSpace(generationID) != generationID ||
			entry.Type()&os.ModeSymlink != 0 ||
			!entry.IsDir() {
			return nil, fmt.Errorf(
				"%w: invalid raw USN retirement object %q",
				ErrGenerationSourceCustodyConflict, name,
			)
		}

		tombstone := filepath.Join(rawRoot, name)
		raw := filepath.Join(
			rawRoot, generationDirectoryPrefix+generationID,
		)

		if _, err := os.Lstat(raw); err == nil {
			return nil, fmt.Errorf(
				"%w: raw and tombstone coexist for %s",
				ErrGenerationSourceCustodyConflict, generationID,
			)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		private := filepath.Join(
			stageRoot,
			generationTransportBuildRootDirectoryName,
			generationDirectoryPrefix+generationID,
		)
		active := filepath.Join(
			stageRoot, generationDirectoryPrefix+generationID,
		)

		privateExists, err := inspectRawCustodyRecoveryNamespace(private)
		if err != nil {
			return nil, err
		}
		activeExists, err := inspectRawCustodyRecoveryNamespace(active)
		if err != nil {
			return nil, err
		}
		if privateExists == activeExists {
			return nil, fmt.Errorf(
				"%w: expected exactly one sealed replacement for %s",
				ErrGenerationSourceCustodyConflict, generationID,
			)
		}

		sealedDir := active
		state := "ACTIVE"
		if privateExists {
			sealedDir = private
			state = "PRIVATE"
		}

		receiptPath, err := generationSourceCustodyPath(
			sealedDir, generationID,
		)
		if err != nil {
			return nil, err
		}

		receipt, found, err := readSourceCustodyReceipt(receiptPath)
		if err != nil {
			return nil, err
		}
		if !found ||
			receipt.GenerationID != generationID ||
			receipt.SourceID != sourceID {
			return nil, fmt.Errorf(
				"%w: absent or unrelated custody receipt for %s",
				ErrGenerationSourceCustodyConflict, generationID,
			)
		}

		published, err := transportgeneration.LoadSealedGeneration(
			sealedDir,
		)
		if err != nil {
			return nil, err
		}

		descriptor := published.Signed.Descriptor
		if descriptor.GenerationID != receipt.GenerationID ||
			descriptor.SourceID != receipt.SourceID ||
			descriptor.CanonicalSHA256 != receipt.CanonicalSHA256 ||
			descriptor.EncodedDataSHA256 != receipt.EncodedSHA256 {
			return nil, fmt.Errorf(
				"%w: sealed replacement identity differs for %s",
				ErrGenerationSourceCustodyConflict, generationID,
			)
		}

		metadata, err := readGenerationRetirementMetadata(
			published.MetadataPath,
		)
		if err != nil {
			return nil, err
		}

		digest := sha256.Sum256(metadata)
		if hex.EncodeToString(digest[:]) != receipt.SignedMetadataSHA256 {
			return nil, fmt.Errorf(
				"%w: signed metadata differs for %s",
				ErrGenerationSourceCustodyConflict, generationID,
			)
		}

		if err := transportgeneration.VerifyPublishedGenerationPayload(
			published,
		); err != nil {
			return nil, fmt.Errorf(
				"verify USN custody replacement: %w", err,
			)
		}

		// The raw tombstone must still contain a verified manifested
		// USN capture. This check does not grant deletion permission.
		if err := guardRawGenerationRetirement(tombstone); !errors.Is(
			err, ErrSourceCustodyHandoffRequired,
		) {
			if err == nil {
				return nil, fmt.Errorf(
					"%w: tombstone has no captured USN range",
					ErrGenerationSourceCustodyConflict,
				)
			}
			return nil, fmt.Errorf(
				"verify tombstoned raw source: %w", err,
			)
		}

		result = append(result, RawUSNCustodyRecoveryState{
			GenerationID: generationID,
			TombstoneDir: tombstone,
			SealedDir:    sealedDir,
			SealedState:  state,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].GenerationID < result[j].GenerationID
	})

	return result, nil
}

// inspectRawCustodyRecoveryNamespace rejects symlinks and non-directory
// objects instead of treating them as absent sealed replacements.
func inspectRawCustodyRecoveryNamespace(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf(
			"%w: sealed custody path is not a real directory: %s",
			ErrGenerationSourceCustodyConflict, path,
		)
	}
	return true, nil
}
