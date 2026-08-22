// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import "testing"

func testUSNVolumeIdentity() VolumeIdentity {
	return VolumeIdentity{
		MethodVersion: "windows-file-id-info-ntfs/0.1",
		VolumeGUID:    `\\?\Volume{11111111-1111-1111-1111-111111111111}\`,
		VolumeSerial:  "123",
	}
}

func testUSNObjectIdentity(record, sequence string) NTFSObjectIdentity {
	return NTFSObjectIdentity{
		MethodVersion:       "windows-file-id-info-ntfs/0.1",
		FileReferenceNumber: record,
		SequenceNumber:      sequence,
	}
}

func TestValidateUSNJournalState(t *testing.T) {
	state := USNJournalState{
		ObservedAt:       "2026-08-22T13:00:00.000000000Z",
		CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID:          "scope-test",
		VolumeIdentity:   testUSNVolumeIdentity(),
		JournalID:        "10",
		FirstUSN:         "20",
		NextUSN:          "30",
		LowestValidUSN:   "20",
		MaxUSN:           "100",
		MaximumSize:      "1048576",
		AllocationDelta:  "65536",
	}
	if err := ValidateUSNJournalState(state); err != nil {
		t.Fatal(err)
	}
}

func TestValidateUSNReadBatch(t *testing.T) {
	batch := USNReadBatch{
		ObservedAt:       "2026-08-22T13:00:00.000000000Z",
		CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID:          "scope-test",
		VolumeIdentity:   testUSNVolumeIdentity(),
		JournalID:        "10",
		StartUSN:         "20",
		NextUSN:          "31",
		Records: []USNChangeObservation{{
			MajorVersion:             "2",
			MinorVersion:             "0",
			FileIdentity:             testUSNObjectIdentity("100", "2"),
			ParentIdentity:           testUSNObjectIdentity("50", "3"),
			USN:                      "30",
			Timestamp:                "2026-08-22T13:00:00.000000000Z",
			ReasonRaw:                "256",
			ReasonNames:              []string{"FileCreate"},
			SourceInfoRaw:            "0",
			SecurityID:               "7",
			FileAttributesRaw:        "32",
			FileNameUTF16LEBase64URL: "ZgBpAGwAZQAuAHQAeAB0AA",
		}},
	}
	if err := ValidateUSNReadBatch(batch); err != nil {
		t.Fatal(err)
	}
}

func TestValidateUSNReadBatchRejectsDescendingUSN(t *testing.T) {
	base := USNChangeObservation{
		MajorVersion:             "2",
		MinorVersion:             "0",
		FileIdentity:             testUSNObjectIdentity("100", "2"),
		ParentIdentity:           testUSNObjectIdentity("50", "3"),
		Timestamp:                "2026-08-22T13:00:00.000000000Z",
		ReasonRaw:                "256",
		ReasonNames:              []string{"FileCreate"},
		SourceInfoRaw:            "0",
		SecurityID:               "7",
		FileAttributesRaw:        "32",
		FileNameUTF16LEBase64URL: "ZgBpAGwAZQAuAHQAeAB0AA",
	}
	first := base
	first.USN = "31"
	second := base
	second.USN = "30"

	batch := USNReadBatch{
		ObservedAt:       "2026-08-22T13:00:00.000000000Z",
		CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID:          "scope-test",
		VolumeIdentity:   testUSNVolumeIdentity(),
		JournalID:        "10",
		StartUSN:         "20",
		NextUSN:          "32",
		Records:          []USNChangeObservation{first, second},
	}
	if err := ValidateUSNReadBatch(batch); err == nil {
		t.Fatal("expected descending USN validation failure")
	}
}
