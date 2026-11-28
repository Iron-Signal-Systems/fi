// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func exampleScopedSegment(t *testing.T) Segment {
    t.Helper()
    batch := exampleBatch(exampleAnchor(), 100, 200)
    volumeScope, err := VolumeCaptureScopeID(batch.VolumeIdentity)
    if err != nil { t.Fatal(err) }
    batch.ScopeID = volumeScope
    batch.Records = []records.USNChangeObservation{
        { MajorVersion: "2", MinorVersion: "0",
          FileIdentity: records.NTFSObjectIdentity{MethodVersion: "ntfs/1", FileReferenceNumber: "22", SequenceNumber: "1"},
          ParentIdentity: records.NTFSObjectIdentity{MethodVersion: "ntfs/1", FileReferenceNumber: "11", SequenceNumber: "1"},
          USN: "111", Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
          ReasonRaw: "256", SourceInfoRaw: "0", SecurityID: "0", FileAttributesRaw: "32", FileNameUTF16LEBase64URL: "YQA"},
        { MajorVersion: "2", MinorVersion: "0",
          FileIdentity: records.NTFSObjectIdentity{MethodVersion: "ntfs/1", FileReferenceNumber: "22", SequenceNumber: "1"},
          ParentIdentity: records.NTFSObjectIdentity{MethodVersion: "ntfs/1", FileReferenceNumber: "11", SequenceNumber: "1"},
          USN: "120", Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
          ReasonRaw: "0", SourceInfoRaw: "0", SecurityID: "0", FileAttributesRaw: "32", FileNameUTF16LEBase64URL: "YQA"},
    }
    if err := records.ValidateUSNReadBatch(batch); err != nil {
        t.Fatalf("invalid test journal: %v", err)
    }
    raw, _ := json.Marshal(batch)
    sum := sha256.Sum256(raw)
    return Segment{
        Name: segmentName(100), Batch: batch,
        SHA256: hex.EncodeToString(sum[:]),
    }
}
func TestBuildScopedProjectionPreservesEveryUnresolvedChange(t *testing.T) {
    seg := exampleScopedSegment(t)
    selection := ScopeSelection{Total: 2, Unresolved: 2,
        Included: []ScopedChange{
            {Source: seg.Batch.Records[0], Class: ScopeUnresolved},
            {Source: seg.Batch.Records[1], Class: ScopeUnresolved},
        },
    }
    projection, err := BuildScopedProjection(seg, "root-test", scopeTestIdentity("1"), selection)
    if err != nil || projection.SourceRecordCount != 2 ||
        projection.IncludedRecordCount != 2 || projection.UnresolvedRecordCount != 2 ||
        projection.Included[0].Source.USN != "111" || projection.Included[1].Source.USN != "120" {
        t.Fatalf("lost raw USN history: %+v %v", projection, err)
    }
    if projection.CaptureScopeID != seg.Batch.ScopeID || projection.GovernedScopeID != "root-test" || projection.CapturedAt != seg.Batch.ObservedAt || projection.RootIdentity != scopeTestIdentity("1") {t.Fatal("contract is not bound to governed root and original volume")}
    if projection.SourceBatchSHA256 != seg.SHA256 {
        t.Fatal("projection detached from durable raw source")
    }
}
func TestBuildScopedProjectionRejectsUnprovedExclusion(t *testing.T) {
    seg := exampleScopedSegment(t)
    selection := ScopeSelection{Total: 2, Excluded: 1, Governed: 1,
        Included: []ScopedChange{{Source: seg.Batch.Records[0], Class: ScopeGoverned}},
    }
    if _, err := BuildScopedProjection(seg, "root-test", scopeTestIdentity("1"), selection); err == nil {
        t.Fatal("accepted dropped historical USN event without durable proof")
    }
}
func TestBuildScopedProjectionRejectsForgedOrReorderedChanges(t *testing.T) {
    seg := exampleScopedSegment(t)
    changed := seg.Batch.Records[0]
    changed.USN = "130"
    for name, included := range map[string][]ScopedChange{
        "forged": {{Source: changed, Class: ScopeUnresolved}, {Source: seg.Batch.Records[1], Class: ScopeUnresolved}},
        "reordered": {{Source: seg.Batch.Records[1], Class: ScopeUnresolved}, {Source: seg.Batch.Records[0], Class: ScopeUnresolved}},
    } {
        t.Run(name, func(t *testing.T) {
            _, err := BuildScopedProjection(seg, "root-test", scopeTestIdentity("1"), ScopeSelection{Total: 2, Unresolved: 2, Included: included})
            if err == nil {
                t.Fatal("accepted source event mutation")
            }
        })
    }
    seg.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
    _, err := BuildScopedProjection(seg, "root-test", scopeTestIdentity("1"), ScopeSelection{Total: 2, Unresolved: 2, Included: []ScopedChange{
        {Source: seg.Batch.Records[0], Class: ScopeUnresolved},
        {Source: seg.Batch.Records[1], Class: ScopeUnresolved},
    }})
    if err == nil {
        t.Fatal("accepted detached source checksum")
    }
}
