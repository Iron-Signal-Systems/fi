// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package checkpoint

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestAssessContinuous(t *testing.T) {
	checkpoint, root, journal := testState()
	assessment, err := Assess(checkpoint, root, journal)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityContinuous || assessment.ReasonCode != "" {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
}

func TestAssessJournalIDChanged(t *testing.T) {
	checkpoint, root, journal := testState()
	journal.JournalID = "778"
	assessment, err := Assess(checkpoint, root, journal)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityGap || assessment.ReasonCode != "JournalIDChanged" {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
}

func TestAssessCheckpointAgedOut(t *testing.T) {
	checkpoint, root, journal := testState()
	checkpoint.NextUSN = "100"
	journal.FirstUSN = "101"
	assessment, err := Assess(checkpoint, root, journal)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityGap || assessment.ReasonCode != "CheckpointAgedOut" {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
}

func TestAssessCheckpointBeforeLowestValidUSN(t *testing.T) {
	checkpoint, root, journal := testState()
	checkpoint.NextUSN = "100"
	journal.FirstUSN = "90"
	journal.LowestValidUSN = "101"
	assessment, err := Assess(checkpoint, root, journal)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityGap || assessment.ReasonCode != "CheckpointBeforeLowestValidUSN" {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
}

func TestAssessGovernedRootObjectChanged(t *testing.T) {
	checkpoint, root, journal := testState()
	root.ObjectIdentity.FileReferenceNumber = "43"
	assessment, err := Assess(checkpoint, root, journal)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityGap || assessment.ReasonCode != "GovernedRootObjectChanged" {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
}

func TestValidateAdvance(t *testing.T) {
	checkpoint, root, journal := testState()
	assessment, err := Assess(checkpoint, root, journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAdvance(assessment, "150", "175"); err != nil {
		t.Fatalf("valid advance rejected: %v", err)
	}
	if err := ValidateAdvance(assessment, "149", "175"); err != ErrCheckpointConflict {
		t.Fatalf("expected conflict, got %v", err)
	}
	if err := ValidateAdvance(assessment, "150", "201"); err == nil {
		t.Fatal("advance beyond journal NextUSN accepted")
	}
}

func testState() (USNCheckpoint, records.GovernedRootIdentity, records.USNJournalState) {
	volume := records.VolumeIdentity{
		MethodVersion: "windows-file-id-info-ntfs/0.1",
		VolumeGUID:    `\\?\Volume{6d8101b5-0000-0000-0000-501f00000000}\`,
		VolumeSerial:  "5528245215150056436",
	}
	root := records.GovernedRootIdentity{
		ScopeID:                       "manual-test",
		RequestedPathUTF16LEBase64URL: testUTF16(`C:\Users\jwood.admin\Downloads`),
		ResolvedPathUTF16LEBase64URL:  testUTF16(`\\?\Volume{6d8101b5-0000-0000-0000-501f00000000}\Users\jwood.admin\Downloads`),
		MethodVersion:                 "windows-final-volume-path-containment/0.1",
		VolumeIdentity:                volume,
		ObjectIdentity: records.NTFSObjectIdentity{
			MethodVersion:       "windows-file-id-info-ntfs/0.1",
			FileReferenceNumber: "42",
			SequenceNumber:      "8",
		},
	}
	checkpoint := USNCheckpoint{
		Version:      SchemaVersion,
		ScopeID:      "manual-test",
		GovernedRoot: root,
		JournalID:    "777",
		NextUSN:      "150",
		UpdatedAt:    "2026-08-22T13:00:00Z",
	}
	journal := records.USNJournalState{
		ObservedAt:       "2026-08-22T13:01:00.000000000Z",
		CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID:          "manual-test",
		VolumeIdentity:   volume,
		JournalID:        "777",
		FirstUSN:         "100",
		NextUSN:          "200",
		LowestValidUSN:   "0",
		MaxUSN:           "9223372036854710272",
		MaximumSize:      "33554432",
		AllocationDelta:  "8388608",
	}
	return checkpoint, root, journal
}

func testUTF16(value string) string {
	units := utf16.Encode([]rune(value))
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
