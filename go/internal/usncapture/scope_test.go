// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "errors"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func scopeTestIdentity(n string) records.NTFSObjectIdentity {
    return records.NTFSObjectIdentity{MethodVersion: "ntfs-file-id/1", FileReferenceNumber: n, SequenceNumber: "1"}
}

func scopeTestBatch() (records.USNReadBatch, records.NTFSObjectIdentity) {
    root := scopeTestIdentity("1")
    parent := scopeTestIdentity("2")
    obj := scopeTestIdentity("3")
    batch := exampleBatch(exampleAnchor(), 100, 180)
    batch.ScopeID = "volume-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    batch.Records = []records.USNChangeObservation{{
        FileIdentity: obj, ParentIdentity: parent, USN: "151",
    }}
    return batch, root
}

func scopeEvidenceFor(batch records.USNReadBatch, root records.NTFSObjectIdentity, change records.USNChangeObservation, class ScopeClass) ScopeEvidence {
    return ScopeEvidence{
        Class: class,
        ScopeID: "root-test", JournalID: batch.JournalID,
        RootIdentity: root, FileIdentity: change.FileIdentity,
        ParentIdentity: change.ParentIdentity, EventUSN: change.USN,
        HistoricalAncestry: true, CompleteLinkCoverage: true,
        Reason: "HistoricallyBoundIndex",
    }
}

func TestScopeAllowsHistoricalInside(t *testing.T) {
    batch, root := scopeTestBatch()
    result, err := SelectCapturedScope(batch, "root-test", root, func(c records.USNChangeObservation) (ScopeEvidence, error) {
        return scopeEvidenceFor(batch, root, c, ScopeGoverned), nil
    })
    if err != nil || result.Governed != 1 || result.Excluded != 0 || len(result.Included) != 1 {
        t.Fatalf("inside: %+v %v", result, err)
    }
}

func TestScopeExcludesOnlyVerifiedHistoricalOutside(t *testing.T) {
    batch, root := scopeTestBatch()
    result, err := SelectCapturedScope(batch, "root-test", root, func(c records.USNChangeObservation) (ScopeEvidence, error) {
        return scopeEvidenceFor(batch, root, c, ScopeOutside), nil
    })
    if err != nil || result.Excluded != 1 || len(result.Included) != 0 {
        t.Fatalf("outside: %+v %v", result, err)
    }
}

func TestScopeCannotDropStaleOrUnprovedOutside(t *testing.T) {
    batch, root := scopeTestBatch()
    cases := map[string]func(*ScopeEvidence){
        "current-path-only": func(p *ScopeEvidence) {p.HistoricalAncestry = false},
        "hard-links-unknown": func(p *ScopeEvidence) {p.CompleteLinkCoverage = false},
        "stale-event": func(p *ScopeEvidence) {p.EventUSN = "150"},
        "wrong-parent": func(p *ScopeEvidence) {p.ParentIdentity = scopeTestIdentity("4")},
        "wrong-volume-journal": func(p *ScopeEvidence) {p.JournalID = "21"},
        "wrong-root": func(p *ScopeEvidence) {p.RootIdentity = scopeTestIdentity("5")},
        "wrong-object-sequence": func(p *ScopeEvidence) {p.FileIdentity.SequenceNumber = "2"},
        "missing-evidence": func(p *ScopeEvidence) { *p = ScopeEvidence{} },
    }
    for name, modify := range cases {
        t.Run(name, func(t *testing.T) {
            result, err := SelectCapturedScope(batch, "root-test", root, func(c records.USNChangeObservation) (ScopeEvidence, error) {
                p := scopeEvidenceFor(batch, root, c, ScopeOutside)
                modify(&p)
                return p, nil
            })
            if err != nil || result.Excluded != 0 || result.Unresolved != 1 || len(result.Included) != 1 {
                t.Fatalf("unsafe drop: %+v %v", result, err)
            }
        })
    }
}

func TestScopeMustPreserveEveryUnresolvedEventIncludingRepeatedFileIDs(t *testing.T) {
    batch, root := scopeTestBatch()
    second := batch.Records[0]
    second.USN = "160"
    batch.Records = append(batch.Records, second)
    result, err := SelectCapturedScope(batch, "root-test", root, func(records.USNChangeObservation) (ScopeEvidence, error) {
        return ScopeEvidence{}, nil
    })
    if err != nil || result.Total != 2 || result.Unresolved != 2 || len(result.Included) != 2 ||
        result.Included[0].Source.USN != "151" || result.Included[1].Source.USN != "160" {
        t.Fatalf("source history lost or deduplicated: %+v %v", result, err)
    }
}

func TestScopeResolverFailureFailsClosed(t *testing.T) {
    batch, root := scopeTestBatch()
    marker := errors.New("ancestry index damaged")
    _, err := SelectCapturedScope(batch, "root-test", root, func(records.USNChangeObservation) (ScopeEvidence, error) {
        return ScopeEvidence{}, marker
    })
    if !errors.Is(err, marker) {
        t.Fatalf("expected explicit failure, got %v", err)
    }
}
