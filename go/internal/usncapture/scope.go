// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// ScopeClass is a statement about historical source membership, not a
// filesystem state observation taken after the event.
type ScopeClass string

const (
    ScopeGoverned   ScopeClass = "Governed"
    ScopeOutside    ScopeClass = "Outside"
    ScopeUnresolved ScopeClass = "Unresolved"
)

// ScopeEvidence is a bounded proof from a historical directory/link index.
// It is intentionally NOT derived from an object's current path/parent alone.
// Any incomplete, stale or mismatched proof degrades to Unresolved (included).
type ScopeEvidence struct {
    Class                 ScopeClass
    ScopeID               string
    JournalID             string
    RootIdentity          records.NTFSObjectIdentity
    FileIdentity          records.NTFSObjectIdentity
    ParentIdentity        records.NTFSObjectIdentity
    EventUSN              string
    HistoricalAncestry    bool
    CompleteLinkCoverage  bool
    Reason                string
}

// ScopeResolver may consult a durable historical ancestry and hard-link index,
// but it must NOT read file content, hash files, or govern raw journal capture.
type ScopeResolver func(records.USNChangeObservation) (ScopeEvidence, error)

type ScopedChange struct {
    Source records.USNChangeObservation `json:"source"`
    Class  ScopeClass `json:"class"`
    Reason string `json:"reason"`
}

type ScopeSelection struct {
    Included []ScopedChange
    Excluded int
    Governed int
    Unresolved int
    Total int
}

// SelectCapturedScope produces one decision per original USN record without
// modifying or deduplicating source facts. The immutable raw capture segment
// remains the source of truth. No negative proof => do not discard history.
//
// A historical outside decision requires a complete link+ancestry proof for
// the exact object, parent, scope, journal and USN position. Current containment
// by itself can never satisfy these requirements.
func SelectCapturedScope(batch records.USNReadBatch, governedScopeID string, root records.NTFSObjectIdentity, resolve ScopeResolver) (ScopeSelection, error) {
    if batch.ScopeID == "" || governedScopeID == "" || batch.JournalID == "" {
        return ScopeSelection{}, errors.New("FI scoped USN capture requires source scope and journal")
    }
    if err := records.ValidateNTFSObjectIdentity(root); err != nil {
        return ScopeSelection{}, fmt.Errorf("validate governed root identity: %w", err)
    }
    if resolve == nil {
        return ScopeSelection{}, errors.New("FI scoped capture resolver required")
    }
    result := ScopeSelection{Included: make([]ScopedChange, 0, len(batch.Records)), Total: len(batch.Records)}
    for _, change := range batch.Records {
        evidence, err := resolve(change)
        if err != nil {
            return ScopeSelection{}, fmt.Errorf("resolve USN %s: %w", change.USN, err)
        }

        // A scope proof must be bound to the precise historical event.
        bound := evidence.ScopeID == governedScopeID &&
            evidence.JournalID == batch.JournalID &&
            evidence.RootIdentity == root &&
            evidence.FileIdentity == change.FileIdentity &&
            evidence.ParentIdentity == change.ParentIdentity &&
            evidence.EventUSN == change.USN

        switch {
        case bound && evidence.Class == ScopeGoverned && evidence.HistoricalAncestry:
            result.Governed++
            result.Included = append(result.Included, ScopedChange{Source: change, Class: ScopeGoverned, Reason: evidence.Reason})
        case bound && evidence.Class == ScopeOutside && evidence.HistoricalAncestry && evidence.CompleteLinkCoverage:
            result.Excluded++
        default:
            // A current-path check, incomplete hard-link inventory or missing
            // historical data is not proof that the source event was irrelevant.
            result.Unresolved++
            result.Included = append(result.Included, ScopedChange{Source: change, Class: ScopeUnresolved, Reason: "MissingVerifiedHistoricalScope"})
        }
    }
    if result.Total != result.Excluded+len(result.Included) ||
        len(result.Included) != result.Governed+result.Unresolved {
        return ScopeSelection{}, errors.New("FI scope conservation invariant failed")
    }
    return result, nil
}
