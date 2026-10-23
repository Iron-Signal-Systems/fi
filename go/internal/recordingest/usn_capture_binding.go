// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// Source-bound capture associations exist only for one relational generation.
// The map is populated in recorded source order and never shared by workers.
// It prevents cross-generation, cross-source, and cross-scope reuse of a batch
// hash without a database lookup for each USN object.
type usnCaptureContextKey struct{}

type usnCaptureKey struct {
	sourceID          string
	scopeID           string
	sourceBatchSHA256 string
}

type usnCaptureBoundary struct {
	recordID        int64
	volumeID        int64
	root            records.NTFSObjectIdentity
	expectedObjects int
	expectedChanges int
	observedObjects int
	observedChanges int
}

type usnCaptureState struct {
	sourceID     string
	generationID string
	boundaries   map[usnCaptureKey]*usnCaptureBoundary
}

func newUSNCaptureState(sourceID, generationID string) *usnCaptureState {
	return &usnCaptureState{
		sourceID:     sourceID,
		generationID: generationID,
		boundaries:   make(map[usnCaptureKey]*usnCaptureBoundary),
	}
}

// validateUSNBoundaryContract distinguishes the original synchronous reader
// from M6.1 durable capture. Partial or mixed records are invalid, not legacy.
func validateUSNBoundaryContract(value usnReadBoundaryPayload) (bool, error) {
	if value.ReObservationOperationID == "" {
		return false, errors.New("FI USN re-observation operation ID is required")
	}
	sourceBound := value.SourceBatchSHA256 != "" || value.CorrelationSHA256 != "" || value.RootIdentity != nil
	if !sourceBound {
		if value.USNReadOperationID == "" {
			return false, errors.New("FI legacy USN read operation ID is required")
		}
		return false, nil
	}
	if value.USNReadOperationID != "" {
		return false, errors.New("FI source-bound USN capture cannot carry a synchronous read operation ID")
	}
	if _, err := decodeHex(value.SourceBatchSHA256, 32, true, "usn_read_boundary.source_batch_sha256"); err != nil {
		return false, err
	}
	if _, err := decodeHex(value.CorrelationSHA256, 32, true, "usn_read_boundary.correlation_sha256"); err != nil {
		return false, err
	}
	if value.RootIdentity == nil {
		return false, errors.New("FI source-bound USN root identity is required")
	}
	if err := records.ValidateNTFSObjectIdentity(*value.RootIdentity); err != nil {
		return false, fmt.Errorf("FI source-bound USN root identity: %w", err)
	}
	if value.SourceRecordCount != value.SelectedRecordCount ||
		value.SourceDistinctObjectCount != value.SelectedObjectCount ||
		value.ScopeUnresolvedObjectCount != value.SelectedObjectCount ||
		value.IgnoredVolumeRecordCount != 0 || value.IgnoredVolumeObjectCount != 0 ||
		value.SourceRecordCount < value.SourceDistinctObjectCount {
		return false, errors.New("FI source-bound USN capture counts are inconsistent")
	}
	return true, nil
}

func (s *usnCaptureState) remember(sourceID, scopeID, digest string, b usnCaptureBoundary) error {
	if s == nil || s.sourceID != sourceID || scopeID == "" || b.recordID <= 0 || b.volumeID <= 0 {
		return errors.New("FI source-bound USN generation context is invalid")
	}
	key := usnCaptureKey{sourceID, scopeID, digest}
	if _, exists := s.boundaries[key]; exists {
		return errors.New("FI duplicate source-bound USN capture batch in one generation and scope")
	}
	value := b
	s.boundaries[key] = &value
	return nil
}

func (s *usnCaptureState) resolve(sourceID, scopeID, digest string, recordID int64) (*usnCaptureBoundary, error) {
	if s == nil || sourceID != s.sourceID || scopeID == "" || recordID <= 0 {
		return nil, errors.New("FI source-bound USN object lacks its generation context")
	}
	if _, err := decodeHex(digest, 32, true, "usn_object_observation.source_batch_sha256"); err != nil {
		return nil, err
	}
	b, exists := s.boundaries[usnCaptureKey{sourceID, scopeID, digest}]
	if !exists || b.recordID >= recordID {
		return nil, errors.New("FI source-bound USN object has no preceding matching capture boundary in this generation")
	}
	return b, nil
}

func (s *usnCaptureState) completeObject(b *usnCaptureBoundary, changes int) error {
	if s == nil || b == nil || changes <= 0 {
		return errors.New("FI source-bound USN completion is invalid")
	}
	if b.observedObjects >= b.expectedObjects || changes > b.expectedChanges-b.observedChanges {
		return errors.New("FI source-bound USN object/change count exceeds its source capture")
	}
	b.observedObjects++
	b.observedChanges += changes
	return nil
}

// Called before a generation may commit. A source-bound boundary is never
// accepted with missing object observations or discarded original USN changes.
func (s *usnCaptureState) verify() error {
	if s == nil {
		return errors.New("FI USN capture state is required")
	}
	for key, b := range s.boundaries {
		if b.observedObjects != b.expectedObjects || b.observedChanges != b.expectedChanges {
			return fmt.Errorf("FI source-bound USN capture %s scope %s incomplete: objects=%d/%d changes=%d/%d",
				key.sourceBatchSHA256, key.scopeID, b.observedObjects, b.expectedObjects,
				b.observedChanges, b.expectedChanges)
		}
	}
	return nil
}
