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
    "reflect"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// ScopedProjectionVersion is intentionally not a FI spool record kind.
// A new source-bound sender and backend contract must be reviewed before
// these projection files are published to FISender or the C220 receiver.
const ScopedProjectionVersion = "fi-usn-scoped-projection/1"

// ScopedProjection is a locally derived transport candidate, bound to one
// immutable and independently verified source segment. Filtering does not
// affect the source segment or its capture cursor.
//
// Individual USN changes remain in original order. Object observations and
// hashes are separate evidence, never invented from journal-only facts.
type ScopedProjection struct {
    Version string `json:"version"`
    ScopeID string `json:"scope_id"`
    JournalID string `json:"journal_id"`
    VolumeIdentity records.VolumeIdentity `json:"volume_identity"`
    StartUSN string `json:"start_usn"`
    NextUSN string `json:"next_usn"`
    SourceBatchSHA256 string `json:"source_batch_sha256"`
    SourceRecordCount int `json:"source_record_count"`
    IncludedRecordCount int `json:"included_record_count"`
    ProvenOutsideRecordCount int `json:"proven_outside_record_count"`
    UnresolvedRecordCount int `json:"unresolved_record_count"`
    GovernedRecordCount int `json:"governed_record_count"`
    Included []ScopedChange `json:"included"`
}

// BuildScopedProjection fails closed when source history, filtering decisions,
// or segment custody disagree. The sole input is a verified Store.Next segment.
func BuildScopedProjection(seg Segment, selection ScopeSelection) (ScopedProjection, error) {
    if seg.SHA256 == "" || len(seg.SHA256) != 64 {
        return ScopedProjection{}, errors.New("verified raw capture segment SHA-256 required")
    }
    if seg.Name != segmentNameMust(seg.Batch.StartUSN) {
        return ScopedProjection{}, errors.New("raw capture segment name mismatch")
    }
    if err := validateBatch(seg.Batch); err != nil {
        return ScopedProjection{}, fmt.Errorf("validate source USN batch: %w", err)
    }
    raw, err := json.Marshal(seg.Batch)
    if err != nil {
        return ScopedProjection{}, err
    }
    digest := sha256.Sum256(raw)
    if hex.EncodeToString(digest[:]) != seg.SHA256 {
        return ScopedProjection{}, errors.New("raw capture source digest mismatch")
    }
    if selection.Total != len(seg.Batch.Records) ||
        selection.Governed+selection.Unresolved != len(selection.Included) ||
        selection.Excluded+len(selection.Included) != selection.Total {
        return ScopedProjection{}, errors.New("scoped capture record conservation failed")
    }
    // Preserve original event order and multiplicity, including repeated USNs
    // or repeated File IDs. Never convert a change event to a file observation.
    index := 0
    for _, change := range selection.Included {
        if change.Class != ScopeGoverned && change.Class != ScopeUnresolved {
            return ScopedProjection{}, errors.New("unsupported scoped change classification")
        }
        for index < len(seg.Batch.Records) && !reflect.DeepEqual(seg.Batch.Records[index], change.Source) {
            index++
        }
        if index >= len(seg.Batch.Records) {
            return ScopedProjection{}, errors.New("included scoped USN change is not an ordered source event")
        }
        index++
    }
    if selection.Excluded > 0 {
        // Until excluded-event proof is durably persisted and independently
        // verifiable by the downstream contract, no source event may be lost.
        return ScopedProjection{}, errors.New("outside-scope exclusion requires durable proof contract")
    }
    included := append([]ScopedChange(nil), selection.Included...)
    return ScopedProjection{
        Version: ScopedProjectionVersion,
        ScopeID: seg.Batch.ScopeID,
        JournalID: seg.Batch.JournalID,
        VolumeIdentity: seg.Batch.VolumeIdentity,
        StartUSN: seg.Batch.StartUSN,
        NextUSN: seg.Batch.NextUSN,
        SourceBatchSHA256: seg.SHA256,
        SourceRecordCount: selection.Total,
        IncludedRecordCount: len(included),
        ProvenOutsideRecordCount: selection.Excluded,
        UnresolvedRecordCount: selection.Unresolved,
        GovernedRecordCount: selection.Governed,
        Included: included,
    }, nil
}
