// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const scopedPublicationIntentVersion = "fi-usn-scoped-publication-intent/1"

// ErrAmbiguousPublication means that a USN interval may have reached the FI
// sender spool but the capture queue lacks a durable processing receipt.
// Replaying automatically could publish the same source events twice.
// Raw capture can continue while an operator or governed recovery procedure
// reconciles the original spool custody.
var ErrAmbiguousPublication = errors.New("FI USN source publication outcome requires reconciliation")

type scopedPublicationIntent struct {
	Version           string `json:"version"`
	CaptureScopeID    string `json:"capture_scope_id"`
	JournalID         string `json:"journal_id"`
	SourceBatchSHA256 string `json:"source_batch_sha256"`
	StartUSN          string `json:"start_usn"`
	NextUSN           string `json:"next_usn"`
}

func publicationIntentPath(dir string, seg Segment) string {
	return filepath.Join(dir, "publishing-"+seg.Name)
}

// BeginScopedPublication MUST be called after computing all governed-root
// projections, and BEFORE writing the first record into the sender spool.
// It records an immutable, durable intent. A crash before CommitProcessed
// leaves an ambiguous interval: Next fails closed instead of duplicating it.
// The active capture worker is unaffected and may append further segments.
func (s *Store) BeginScopedPublication(seg Segment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if seg.Name != segmentNameMust(seg.Batch.StartUSN) ||
		seg.Batch.StartUSN != s.processed.NextUSN ||
		!matchesBatch(s.processed, seg.Batch) {
		return fmt.Errorf("%w: unexpected scoped publication interval", ErrConflict)
	}
	current, err := s.loadSegmentLocked(seg.Name)
	if err != nil {
		return err
	}
	if current.SHA256 != seg.SHA256 || current.Batch.NextUSN != seg.Batch.NextUSN {
		return fmt.Errorf("%w: scoped publication source changed", ErrCorrupt)
	}
	path := publicationIntentPath(s.dir, current)
	already, err := s.readPublicationIntentLocked(current)
	if err != nil {
		return err
	}
	if already {
		return fmt.Errorf("%w: %s", ErrAmbiguousPublication, seg.Name)
	}
	intent := scopedPublicationIntent{
		Version:           scopedPublicationIntentVersion,
		CaptureScopeID:    current.Batch.ScopeID,
		JournalID:         current.Batch.JournalID,
		SourceBatchSHA256: current.SHA256,
		StartUSN:          current.Batch.StartUSN,
		NextUSN:           current.Batch.NextUSN,
	}
	return atomicWrite(path, mustJSON(intent))
}

func (s *Store) blockUnresolvedPublicationLocked(seg Segment) error {
	exists, err := s.readPublicationIntentLocked(seg)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: interval %s to %s", ErrAmbiguousPublication,
			seg.Batch.StartUSN, seg.Batch.NextUSN)
	}
	return nil
}

func (s *Store) requirePublicationIntentLocked(seg Segment) error {
	exists, err := s.readPublicationIntentLocked(seg)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: missing pre-publication intent for %s", ErrConflict, seg.Name)
	}
	return nil
}

func (s *Store) readPublicationIntentLocked(seg Segment) (bool, error) {
	path := publicationIntentPath(s.dir, seg)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return false, fmt.Errorf("%w: invalid scoped publication intent %s", ErrCorrupt, seg.Name)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var intent scopedPublicationIntent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return false, fmt.Errorf("%w: malformed publication intent %s: %v", ErrCorrupt, seg.Name, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false, fmt.Errorf("%w: trailing publication intent data %s", ErrCorrupt, seg.Name)
	}
	if intent.Version != scopedPublicationIntentVersion ||
		intent.CaptureScopeID != seg.Batch.ScopeID ||
		intent.JournalID != seg.Batch.JournalID ||
		intent.SourceBatchSHA256 != seg.SHA256 ||
		intent.StartUSN != seg.Batch.StartUSN ||
		intent.NextUSN != seg.Batch.NextUSN {
		return false, fmt.Errorf("%w: publication intent does not match source %s", ErrCorrupt, seg.Name)
	}
	return true, nil
}
