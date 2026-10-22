// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// ScopeHint is a fast, NON-AUTHORITATIVE membership hint. A hint is never
// permission to discard an object, or proof that all of its USN records were
// within the governed root. Full historical ancestry and hard-link resolution
// remain mandatory downstream.
const (
	ScopeHintDirectParent  = "DirectParentObserved"
	ScopeHintPossibleChain = "PossibleAncestry"
	ScopeHintUnresolved    = "Unresolved"
	CorrelationVersion     = "fi-usn-correlation/1"
)

// CorrelatedObject is derived from the original captured history. It retains
// every triggering USN even when expensive NTFS collection will be deduplicated.
// DirectUSNs are ONLY the exact USN records naming the root as a parent (or
// reporting the governed root object itself); they say nothing about the
// object's other historical USN changes or hard-link memberships.
type CorrelatedObject struct {
	FileIdentity     records.NTFSObjectIdentity   `json:"file_identity"`
	ParentIdentities []records.NTFSObjectIdentity `json:"parent_identities"`
	TriggerUSNs      []string                     `json:"trigger_usns"`
	DirectUSNs       []string                     `json:"direct_usns"`
	ScopeHint        string                       `json:"scope_hint"`
}

// Correlation is an immutable cache artifact, NOT an FI spool observation,
// processing checkpoint, source continuity assessment or scope-exclusion proof.
type Correlation struct {
	Version           string                     `json:"version"`
	SegmentName       string                     `json:"segment_name"`
	SourceBatchSHA256 string                     `json:"source_batch_sha256"`
	RootIdentity      records.NTFSObjectIdentity `json:"root_identity"`
	StartUSN          string                     `json:"start_usn"`
	NextUSN           string                     `json:"next_usn"`
	Work              []CorrelatedObject         `json:"work"`
	SHA256            string                     `json:"sha256"`
}

// BuildCorrelation uses only source facts from a verified segment. It can
// establish that some specific USN records directly name the root as parent.
// Chains reconstructed from a bounded batch are *hints only*: a rename, move,
// deleted directory, file-ID reuse, or hard link may invalidate a historical
// inference. No object is marked outside the root or filtered away.
func BuildCorrelation(seg Segment, root records.NTFSObjectIdentity) (Correlation, error) {
	if err := records.ValidateNTFSObjectIdentity(root); err != nil {
		return Correlation{}, fmt.Errorf("governed root identity: %w", err)
	}
	if err := validateBatch(seg.Batch); err != nil {
		return Correlation{}, err
	}
	if seg.Name != segmentNameMust(seg.Batch.StartUSN) || seg.SHA256 == "" || !reflect.DeepEqual(seg.Work, DistinctWork(seg.Batch)) {
		return Correlation{}, fmt.Errorf("%w: invalid correlation source segment", ErrCorrupt)
	}

	// Membership lookup includes the NTFS sequence number. A reused MFT record
	// number MUST NOT inherit a former object's ancestry.
	children := make(map[records.NTFSObjectIdentity][]records.NTFSObjectIdentity)
	for _, work := range seg.Work {
		for _, parent := range work.ParentIdentities {
			children[parent] = append(children[parent], work.FileIdentity)
		}
	}
	// Reachability is advisory, deliberately not historical containment proof.
	possible := map[records.NTFSObjectIdentity]bool{root: true}
	frontier := []records.NTFSObjectIdentity{root}
	for len(frontier) != 0 {
		parent := frontier[0]
		frontier = frontier[1:]
		for _, child := range children[parent] {
			if !possible[child] {
				possible[child] = true
				frontier = append(frontier, child)
			}
		}
	}

	direct := make(map[records.NTFSObjectIdentity][]string)
	for _, event := range seg.Batch.Records {
		if event.FileIdentity == root || event.ParentIdentity == root {
			direct[event.FileIdentity] = append(direct[event.FileIdentity], event.USN)
		}
	}

	value := Correlation{
		Version:           CorrelationVersion,
		SegmentName:       seg.Name,
		SourceBatchSHA256: seg.SHA256,
		RootIdentity:      root,
		StartUSN:          seg.Batch.StartUSN,
		NextUSN:           seg.Batch.NextUSN,
		Work:              make([]CorrelatedObject, 0, len(seg.Work)),
	}
	for _, original := range seg.Work {
		item := CorrelatedObject{
			FileIdentity:     original.FileIdentity,
			ParentIdentities: append([]records.NTFSObjectIdentity(nil), original.ParentIdentities...),
			TriggerUSNs:      append([]string(nil), original.TriggerUSNs...),
			DirectUSNs:       append([]string(nil), direct[original.FileIdentity]...),
			ScopeHint:        ScopeHintUnresolved,
		}
		switch {
		case len(item.DirectUSNs) > 0:
			item.ScopeHint = ScopeHintDirectParent
		case possible[item.FileIdentity]:
			item.ScopeHint = ScopeHintPossibleChain
		}
		value.Work = append(value.Work, item)
	}
	digest, err := correlationDigest(value)
	if err != nil {
		return Correlation{}, err
	}
	value.SHA256 = digest
	return value, nil
}

func correlationDigest(value Correlation) (string, error) {
	value.SHA256 = ""
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func correlationFileName(seg Segment) string { return "correlation-" + seg.Name }

// CorrelateNext publishes an independent, durable correlation cache for the
// oldest unprocessed USN capture batch. It NEVER advances processed.json.
func (s *Store) CorrelateNext(root records.NTFSObjectIdentity) (Correlation, bool, error) {
	seg, ok, err := s.Next()
	if err != nil || !ok {
		return Correlation{}, ok, err
	}
	result, err := s.Correlate(seg, root)
	return result, err == nil, err
}

// Correlate publishes once, then validates its immutable artifact on replay.
// An existing artifact for a DIFFERENT root is a conflict, never overwritten.
func (s *Store) Correlate(seg Segment, root records.NTFSObjectIdentity) (Correlation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.loadSegmentLocked(seg.Name)
	if err != nil {
		return Correlation{}, err
	}
	if stored.SHA256 != seg.SHA256 || stored.Batch.NextUSN != seg.Batch.NextUSN {
		return Correlation{}, fmt.Errorf("%w: correlation source changed", ErrConflict)
	}
	value, err := BuildCorrelation(stored, root)
	if err != nil {
		return Correlation{}, err
	}
	path := filepath.Join(s.dir, correlationFileName(stored))
	if _, err := os.Lstat(path); err == nil {
		return readAndCompareCorrelation(path, value)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Correlation{}, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return Correlation{}, err
	}
	if int64(len(encoded)) > maxEnvelopeBytes {
		return Correlation{}, fmt.Errorf("%w: correlation cache exceeds size limit", ErrCapacity)
	}
	used, err := s.pendingBytesLocked()
	if err != nil {
		return Correlation{}, err
	}
	if uint64(len(encoded)) > s.maxBytes || used > s.maxBytes-uint64(len(encoded)) {
		return Correlation{}, ErrCapacity
	}
	if err := atomicWrite(path, encoded); err != nil {
		return Correlation{}, err
	}
	return readAndCompareCorrelation(path, value)
}

func readAndCompareCorrelation(path string, expected Correlation) (Correlation, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Correlation{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxEnvelopeBytes {
		return Correlation{}, fmt.Errorf("%w: nonregular or oversized correlation artifact", ErrCorrupt)
	}
	file, err := os.Open(path)
	if err != nil {
		return Correlation{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxEnvelopeBytes+1))
	if err != nil {
		return Correlation{}, err
	}
	if int64(len(raw)) > maxEnvelopeBytes {
		return Correlation{}, fmt.Errorf("%w: correlation artifact too large", ErrCorrupt)
	}
	var actual Correlation
	if err := json.Unmarshal(raw, &actual); err != nil {
		return Correlation{}, fmt.Errorf("%w: correlation JSON: %v", ErrCorrupt, err)
	}
	digest, err := correlationDigest(actual)
	if err != nil {
		return Correlation{}, err
	}
	if !strings.EqualFold(digest, actual.SHA256) {
		return Correlation{}, fmt.Errorf("%w: correlation SHA256", ErrCorrupt)
	}
	if !reflect.DeepEqual(actual, expected) {
		return Correlation{}, fmt.Errorf("%w: correlation source, root or work mismatch", ErrConflict)
	}
	return actual, nil
}
