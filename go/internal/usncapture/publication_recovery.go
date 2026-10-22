// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// ErrPublicationPending means the durable intent exists but FI cannot prove
// the complete publication is still present. NEVER republish on this result:
// FISender might already have frozen, sent or retired the first publication.
var ErrPublicationPending = errors.New("FI captured USN publication requires recovery")

const publicationIntentVersion = "fi-usn-publication-intent/1"

type publicationIntent struct {
	Version           string                     `json:"version"`
	SourceBatchSHA256 string                     `json:"source_batch_sha256"`
	CorrelationSHA256 string                     `json:"correlation_sha256"`
	RootIdentity      records.NTFSObjectIdentity `json:"root_identity"`
	ScopeID           string                     `json:"scope_id"`
	JournalID         string                     `json:"journal_id"`
	StartUSN          string                     `json:"start_usn"`
	NextUSN           string                     `json:"next_usn"`
}

func intentFor(seg Segment, corr Correlation) (publicationIntent, error) {
	canonical, err := BuildCorrelation(seg, corr.RootIdentity)
	if err != nil || !reflect.DeepEqual(canonical, corr) {
		return publicationIntent{}, fmt.Errorf("%w: publication correlation does not match source", ErrConflict)
	}
	return publicationIntent{
		Version: publicationIntentVersion, SourceBatchSHA256: seg.SHA256,
		CorrelationSHA256: corr.SHA256, RootIdentity: corr.RootIdentity,
		ScopeID: seg.Batch.ScopeID, JournalID: seg.Batch.JournalID,
		StartUSN: seg.Batch.StartUSN, NextUSN: seg.Batch.NextUSN,
	}, nil
}

func (s *Store) intentPath(seg Segment) string {
	return filepath.Join(s.dir, "publication-"+seg.Name)
}

func (s *Store) readPublicationIntentLocked(seg Segment, corr Correlation) (bool, error) {
	expected, err := intentFor(seg, corr)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(s.intentPath(seg))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return false, fmt.Errorf("%w: publication intent is not a bounded regular file", ErrCorrupt)
	}
	raw, err := os.ReadFile(s.intentPath(seg))
	if err != nil {
		return false, err
	}
	if len(raw) > 4096 {
		return false, fmt.Errorf("%w: oversized publication intent", ErrCorrupt)
	}
	var actual publicationIntent
	if err := json.Unmarshal(raw, &actual); err != nil {
		return false, fmt.Errorf("%w: malformed publication intent: %v", ErrCorrupt, err)
	}
	if !reflect.DeepEqual(actual, expected) {
		return false, fmt.Errorf("%w: publication intent changed identity or source", ErrConflict)
	}
	return true, nil
}

// PublicationPending checks a crash-resilient publication intent for the
// current processing segment. The intent is not itself an FI spool receipt.
func (s *Store) PublicationPending(seg Segment, corr Correlation) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seg.Batch.StartUSN != s.processed.NextUSN {
		return false, fmt.Errorf("%w: publication is not at the processing cursor", ErrConflict)
	}
	return s.readPublicationIntentLocked(seg, corr)
}

// BeginSpoolPublication MUST precede the first write to the FI spool. A
// durable intent prevents an interrupted publisher from silently creating a
// second set of manifests when it restarts. No permission to republish is
// inferred merely because its original manifests are no longer in the active
// spool (FISender may have moved them).
func (s *Store) BeginSpoolPublication(seg Segment, corr Correlation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seg.Batch.StartUSN != s.processed.NextUSN {
		return fmt.Errorf("%w: publication is not next in order", ErrConflict)
	}
	current, err := s.loadSegmentLocked(seg.Name)
	if err != nil {
		return err
	}
	if current.SHA256 != seg.SHA256 || !reflect.DeepEqual(current.Batch, seg.Batch) || !reflect.DeepEqual(current.Work, seg.Work) {
		return fmt.Errorf("%w: publication source changed", ErrConflict)
	}
	pending, err := s.readPublicationIntentLocked(seg, corr)
	if err != nil {
		return err
	}
	if pending {
		return ErrPublicationPending
	}
	intent, err := intentFor(seg, corr)
	if err != nil {
		return err
	}
	encoded := mustJSON(intent)
	used, err := s.pendingBytesLocked()
	if err != nil {
		return err
	}
	if uint64(len(encoded)) > s.maxBytes || used > s.maxBytes-uint64(len(encoded)) {
		return ErrCapacity
	}
	return atomicWrite(s.intentPath(seg), encoded)
}

// RecoverPendingSpoolPublication verifies a complete, source-bound publication
// in the *active* spool and commits its processing cursor without repeating
// expensive NTFS observations. beforeCommit must perform all required SID
// state reconciliation from those independently verified manifested records.
// The sender's publish boundary is held through verification, reconciliation,
// and cursor persistence. This does NOT yet recover publications that FISender
// has moved into sealed/retired generations: those remain fail-closed.
func (s *Store) RecoverPendingSpoolPublication(
	seg Segment, corr Correlation, dir string, beforeCommit func([]string) error,
) (bool, error) {
	if beforeCommit == nil {
		return false, errors.New("FI supporting-SID reconciliation callback is required")
	}
	pending, err := s.PublicationPending(seg, corr)
	if err != nil {
		return false, err
	}
	if !pending {
		return false, nil
	}
	guard, err := spool.AcquirePublishBoundary()
	if err != nil {
		return false, err
	}
	defer guard.Close()
	paths, err := findActiveSpoolPublication(seg, corr, dir)
	if err != nil {
		return false, err
	}
	if err := beforeCommit(paths); err != nil {
		return false, err
	}
	if err := s.CommitVerifiedSpool(seg, corr, dir, paths); err != nil {
		return false, err
	}
	return true, nil
}

// findActiveSpoolPublication only selects manifests whose *every* record
// carries the immutable captured batch digest. A generic matching File-ID,
// record count or batch timestamp is never sufficient proof of identity.
func findActiveSpoolPublication(seg Segment, corr Correlation, dir string) ([]string, error) {
	manifests, err := scanSpoolPublication(seg, corr, dir)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, fmt.Errorf("%w: no complete source-bound publication remains in active FI spool", ErrPublicationPending)
	}
	return manifests, nil
}

// scanSpoolPublication returns a verified, complete source publication, or no
// matches, from one already-authorized physical custody directory. Partial or
// corrupted source publications are never interpreted as absent. This helper
// MUST NOT be used to infer that FI may republish a missing source segment.
func scanSpoolPublication(seg Segment, corr Correlation, dir string) ([]string, error) {
	physical, err := spool.PhysicalSpoolDir(dir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(physical)
	if err != nil {
		return nil, err
	}
	var manifests []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "batch-") || !strings.HasSuffix(entry.Name(), ".manifest.json") {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("%w: nonregular spool manifest", ErrCorrupt)
		}
		path := filepath.Join(physical, entry.Name())
		verification, err := spool.VerifyManifest(path)
		if err != nil || !verification.Verified {
			return nil, fmt.Errorf("%w: unreadable active FI spool manifest %q: %v", ErrCorrupt, path, err)
		}
		file, err := os.Open(verification.DataPath)
		if err != nil {
			return nil, err
		}
		scan := bufio.NewScanner(file)
		scan.Buffer(make([]byte, 4096), int(spool.DefaultMaxBatchBytes)+1)
		matched, unrelated := false, false
		for scan.Scan() {
			var record spool.Record
			if err := json.Unmarshal(scan.Bytes(), &record); err != nil {
				file.Close()
				return nil, fmt.Errorf("%w: spool recovery record: %v", ErrCorrupt, err)
			}
			var source struct {
				SourceBatchSHA256 string `json:"source_batch_sha256"`
			}
			if err := json.Unmarshal(record.Payload, &source); err != nil {
				file.Close()
				return nil, fmt.Errorf("%w: spool recovery payload: %v", ErrCorrupt, err)
			}
			if source.SourceBatchSHA256 == seg.SHA256 {
				matched = true
			} else {
				unrelated = true
			}
		}
		scanErr := scan.Err()
		closeErr := file.Close()
		if err := errors.Join(scanErr, closeErr); err != nil {
			return nil, err
		}
		if matched && unrelated {
			return nil, fmt.Errorf("%w: mixed-source manifest cannot prove publication", ErrConflict)
		}
		if matched {
			manifests = append(manifests, path)
		}
	}
	if len(manifests) == 0 {
		return nil, nil
	}
	if _, err := VerifySpoolPublication(seg, corr, physical, manifests); err != nil {
		return nil, fmt.Errorf("%w: incomplete or invalid FI source publication: %v", ErrPublicationPending, err)
	}
	return manifests, nil
}
