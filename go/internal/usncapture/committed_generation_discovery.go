// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// committedGenerationBoundary is the source identity recovered from one
// original USNReadBoundary in a frozen FI generation. Only committed collector
// ledgers, not these untrusted record fields, can establish source custody.
type committedGenerationBoundary struct {
	ScopeID           string
	SourceBatchSHA256 string
	StartUSN          string
}

// DiscoverCommittedGenerationLedgers locates the exact committed USN source
// inventories represented in a still-present frozen raw generation. It reads
// the collector's queue snapshots without opening a Store or claiming queue
// ownership. It never authorizes retirement, modifies a cursor, or publishes
// a new generation. The caller must hold a stable frozen-generation boundary.
//
// This locates the current two-lane capture queues, which are named
// usn-capture-<scopeID> beneath the configured storage.state_dir. It must not
// silently fall back to another queue layout if one is unavailable.
func DiscoverCommittedGenerationLedgers(
	ctx context.Context, stateDir, rawDir string,
) ([]SourceManifestLedger, error) {
	if ctx == nil {
		return nil, errors.New("FI committed source discovery requires context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(stateDir) || !filepath.IsAbs(rawDir) {
		return nil, fmt.Errorf("%w: absolute state and frozen source paths required", ErrConflict)
	}

	for _, dir := range []string{stateDir, rawDir} {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%w: FI custody directory is not a real directory", ErrCorrupt)
		}
	}

	boundaries, err := discoverFrozenGenerationBoundaries(ctx, rawDir)
	if err != nil {
		return nil, err
	}
	if len(boundaries) == 0 {
		return nil, ErrPublicationPending
	}

	ledgers := make([]SourceManifestLedger, 0, len(boundaries))
	for _, boundary := range boundaries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		queueDir := filepath.Join(stateDir, "usn-capture-"+boundary.ScopeID)

		ledger, found, err := ReadCommittedSourceLedgerSnapshot(
			queueDir, boundary.StartUSN,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"read committed FI scope %s source %s: %w",
				boundary.ScopeID, boundary.StartUSN, err,
			)
		}
		if !found {
			return nil, fmt.Errorf(
				"%w: source ledger absent for FI scope %s source %s",
				ErrPublicationPending, boundary.ScopeID, boundary.StartUSN,
			)
		}
		if ledger.ScopeID != boundary.ScopeID ||
			ledger.StartUSN != boundary.StartUSN ||
			ledger.SourceBatchSHA256 != boundary.SourceBatchSHA256 {
			return nil, fmt.Errorf(
				"%w: original source boundary does not match committed ledger",
				ErrConflict,
			)
		}

		ledgers = append(ledgers, ledger)
	}

	return ledgers, nil
}

// VerifyDiscoveredCommittedGeneration checks the complete frozen and sealed
// content after independently resolving all committed source ledgers. Neither
// this result nor a signed descriptor authorizes deleting the raw generation.
func VerifyDiscoveredCommittedGeneration(
	ctx context.Context, stateDir, rawDir, sealedDir, sourceID string,
) (CommittedGenerationPreflight, error) {
	ledgers, err := DiscoverCommittedGenerationLedgers(ctx, stateDir, rawDir)
	if err != nil {
		return CommittedGenerationPreflight{}, err
	}

	return VerifyCommittedGenerationPreflight(
		ctx, rawDir, sealedDir, sourceID, ledgers,
	)
}

// discoverFrozenGenerationBoundaries requires one unambiguous source identity
// per original boundary. Manifests are independently verified before parsing.
// The subsequent full-generation preflight checks that all other USN records
// are owned by these committed sources, including mixed FI generations.
func discoverFrozenGenerationBoundaries(
	ctx context.Context, rawDir string,
) ([]committedGenerationBoundary, error) {
	entries, err := os.ReadDir(rawDir)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var result []committedGenerationBoundary
	manifestCount := 0

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if !strings.HasSuffix(entry.Name(), ".manifest.json") {
			continue
		}
		if !strings.HasPrefix(entry.Name(), "batch-") ||
			!entry.Type().IsRegular() {
			return nil, fmt.Errorf(
				"%w: invalid frozen FI manifest", ErrCorrupt,
			)
		}

		manifestCount++

		verification, err := spool.VerifyManifest(
			filepath.Join(rawDir, entry.Name()),
		)
		if err != nil || !verification.Verified {
			return nil, fmt.Errorf(
				"%w: unverified frozen FI manifest %s: %v",
				ErrCorrupt, entry.Name(), err,
			)
		}

		file, err := os.Open(verification.DataPath)
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(
			make([]byte, 4096),
			int(spool.DefaultMaxBatchBytes)+1,
		)

		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				_ = file.Close()
				return nil, err
			}

			var record spool.Record
			if err := json.Unmarshal(
				scanner.Bytes(), &record,
			); err != nil {
				_ = file.Close()
				return nil, fmt.Errorf(
					"%w: malformed frozen FI source record: %v",
					ErrCorrupt, err,
				)
			}

			if record.RecordKind != "USNReadBoundary" {
				continue
			}

			var boundary struct {
				SourceBatchSHA256 string `json:"source_batch_sha256"`
				StartUSN          string `json:"start_usn"`
			}

			if err := json.Unmarshal(
				record.Payload, &boundary,
			); err != nil {
				_ = file.Close()
				return nil, fmt.Errorf(
					"%w: malformed frozen USN boundary", ErrCorrupt,
				)
			}

			if !validCaptureScopeID(record.ScopeID) ||
				!canonicalDecimal(boundary.StartUSN) ||
				!validSourceBatchDigest(boundary.SourceBatchSHA256) ||
				seen[boundary.SourceBatchSHA256] {
				_ = file.Close()
				return nil, fmt.Errorf(
					"%w: invalid or repeated frozen USN source identity",
					ErrConflict,
				)
			}

			seen[boundary.SourceBatchSHA256] = true

			result = append(result, committedGenerationBoundary{
				ScopeID:           record.ScopeID,
				SourceBatchSHA256: boundary.SourceBatchSHA256,
				StartUSN:          boundary.StartUSN,
			})
		}

		scanErr := scanner.Err()
		closeErr := file.Close()

		if err := errors.Join(scanErr, closeErr); err != nil {
			return nil, err
		}
	}

	if manifestCount == 0 {
		return nil, ErrPublicationPending
	}

	return result, nil
}

// validCaptureScopeID rejects empty, malformed, and path-bearing identities.
func validCaptureScopeID(value string) bool {
	if value == "" ||
		len(value) > 128 ||
		strings.ContainsAny(value, `\/.:`) {
		return false
	}

	return strings.TrimSpace(value) == value
}

// validSourceBatchDigest validates the original lowercase SHA256 identity.
func validSourceBatchDigest(value string) bool {
	if len(value) != 64 {
		return false
	}

	digest, err := hex.DecodeString(value)

	return err == nil &&
		len(digest) == 32 &&
		value == strings.ToLower(value)
}
