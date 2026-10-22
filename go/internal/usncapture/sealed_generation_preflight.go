// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// PendingGenerationSource identifies one captured USN range whose spool
// publication is expected in a single frozen FI raw generation.
// The caller must supply ALL ranges represented by source-bound USN boundaries.
// The preflight independently checks that set against the frozen batch data.
// A source may have separate capture stores; the sender must coordinate all
// such stores before treating any aggregate preflight as complete.
type PendingGenerationSource struct {
	Segment     Segment
	Correlation Correlation
}

// VerifyAndRecordGenerationPreflight is an INACTIVE sender-coordination API.
// It enumerates original USNReadBoundary source hashes in the frozen raw FI
// generation, requires them to match the complete supplied candidate set,
// verifies each candidate's original source-manifest ledger and sealed payload,
// then durably records the individual M5D handoffs.
//
// The operation is retryable: a crash may leave some handoffs but never moves
// either cursor or deletes originals. This function does not hold an exclusive
// cross-process lock on the frozen directory. Before FISender invokes it as a
// retirement gate, that lock and crash recovery must be integrated into every
// sender build/recovery path. A successful preflight alone is NOT permission
// to delete raw data, claim receiver acknowledgement, or mark USN processed.
func (s *Store) VerifyAndRecordGenerationPreflight(
	ctx context.Context,
	rawDir, sealedDir, sourceID string,
	candidates []PendingGenerationSource,
) ([]SealedSourceHandoff, error) {
	if ctx == nil {
		return nil, errors.New("FI generation preflight requires context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || !filepath.IsAbs(rawDir) || !filepath.IsAbs(sealedDir) ||
		strings.TrimSpace(sourceID) == "" || len(candidates) == 0 {
		return nil, fmt.Errorf("%w: source-bound preflight requires absolute paths and candidates", ErrConflict)
	}

	// Validate the entire candidate set before writing any handoff receipt.
	byHash := make(map[string]PendingGenerationSource, len(candidates))
	manifestOwners := make(map[string]string)
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		seg := candidate.Segment
		corr := candidate.Correlation
		if _, err := intentFor(seg, corr); err != nil {
			return nil, err
		}
		if seg.SHA256 == "" || len(seg.SHA256) != 64 {
			return nil, fmt.Errorf("%w: missing captured source hash", ErrConflict)
		}
		if _, repeated := byHash[seg.SHA256]; repeated {
			return nil, fmt.Errorf("%w: repeated captured source range", ErrConflict)
		}
		ledger, found, err := s.ReadSourceManifestLedger(seg, corr)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, ErrPublicationPending
		}
		for _, manifest := range ledger.Manifests {
			if owner, claimed := manifestOwners[manifest.Name]; claimed {
				return nil, fmt.Errorf("%w: frozen manifest %q claimed by %s and %s", ErrConflict, manifest.Name, owner, seg.SHA256)
			}
			manifestOwners[manifest.Name] = seg.SHA256
		}
		byHash[seg.SHA256] = candidate
	}

	observed, err := enumerateFrozenCapturedBoundaries(ctx, rawDir)
	if err != nil {
		return nil, err
	}
	if len(observed) != len(byHash) {
		return nil, fmt.Errorf("%w: frozen source range census differs (frozen=%d expected=%d)", ErrConflict, len(observed), len(byHash))
	}
	for hash, count := range observed {
		if count != 1 {
			return nil, fmt.Errorf("%w: frozen source boundary %s occurs %d times", ErrConflict, hash, count)
		}
		if _, exists := byHash[hash]; !exists {
			return nil, fmt.Errorf("%w: frozen source contains unaccounted USN range %s", ErrConflict, hash)
		}
	}

	// Deterministic ordering makes interrupted preflights restartable.
	keys := make([]string, 0, len(byHash))
	for key := range byHash {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	handoffs := make([]SealedSourceHandoff, 0, len(keys))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		candidate := byHash[key]
		handoff, err := s.VerifyAndRecordSealedHandoff(
			candidate.Segment, candidate.Correlation, rawDir, sealedDir, sourceID,
		)
		if err != nil {
			return nil, fmt.Errorf("verify source %s within generation: %w", key, err)
		}
		handoffs = append(handoffs, handoff)
	}
	return handoffs, nil
}

// enumerateFrozenCapturedBoundaries treats the FI spool's original verified
// manifests as the source of truth; it never infers completeness from filenames
// or the collector's currently visible active spool.
func enumerateFrozenCapturedBoundaries(ctx context.Context, rawDir string) (map[string]int, error) {
	info, err := os.Lstat(rawDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: frozen generation is not a real directory", ErrCorrupt)
	}
	entries, err := os.ReadDir(rawDir)
	if err != nil {
		return nil, err
	}
	found := make(map[string]int)
	var manifests int
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasSuffix(entry.Name(), ".manifest.json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return nil, fmt.Errorf("%w: frozen manifest is not a regular file", ErrCorrupt)
		}
		manifests++
		verification, err := spool.VerifyManifest(filepath.Join(rawDir, entry.Name()))
		if err != nil || !verification.Verified {
			return nil, fmt.Errorf("%w: frozen manifest verification failed: %v", ErrCorrupt, err)
		}
		f, err := os.Open(verification.DataPath)
		if err != nil {
			return nil, err
		}
		// Limit each line independently; FI's spool records are bounded by
		// DefaultMaxBatchBytes. Scanner errors fail closed.
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), spool.DefaultMaxBatchBytes+1)
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				_ = f.Close()
				return nil, err
			}
			var record spool.Record
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("%w: malformed raw FI record: %v", ErrCorrupt, err)
			}
			if record.RecordKind != "USNReadBoundary" {
				continue
			}
			var boundary struct {
				SourceBatchSHA256 string `json:"source_batch_sha256"`
			}
			if err := json.Unmarshal(record.Payload, &boundary); err != nil ||
				len(boundary.SourceBatchSHA256) != 64 {
				_ = f.Close()
				return nil, fmt.Errorf("%w: boundary missing valid source hash", ErrConflict)
			}
			found[boundary.SourceBatchSHA256]++
		}
		scanErr := scanner.Err()
		closeErr := f.Close()
		if scanErr != nil || closeErr != nil {
			return nil, errors.Join(scanErr, closeErr)
		}
	}
	if manifests == 0 {
		return nil, ErrPublicationPending
	}
	return found, nil
}
