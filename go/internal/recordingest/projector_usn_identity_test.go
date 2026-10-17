package recordingest

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestUSNObjectObservationFileIdentityConsistency(t *testing.T) {
	identity := records.NTFSObjectIdentity{
		MethodVersion:       "test-method",
		FileReferenceNumber: "100",
		SequenceNumber:      "1",
	}

	parent := records.NTFSObjectIdentity{
		MethodVersion:       "test-method",
		FileReferenceNumber: "50",
		SequenceNumber:      "1",
	}

	makeChange := func(usn string) records.USNChangeObservation {
		return records.USNChangeObservation{
			MajorVersion:             "2",
			MinorVersion:             "0",
			FileIdentity:             identity,
			ParentIdentity:           parent,
			USN:                      usn,
			Timestamp:                "2026-10-17T20:00:00.000000000Z",
			ReasonRaw:                "1",
			SourceInfoRaw:            "0",
			SecurityID:               "0",
			FileAttributesRaw:        "32",
			FileNameUTF16LEBase64URL: "ZgA",
		}
	}

	value := usnObjectObservationPayload{
		FileIdentity: identity,
		ScopeBasis:   "CurrentObjectContained",
		Status:       "Unavailable",
		ReasonCode:   "TEST_UNAVAILABLE",
		Changes: []records.USNChangeObservation{
			makeChange("10"),
			makeChange("11"),
		},
	}

	if err := validateUSNObjectObservationPayload("test-scope", value); err != nil {
		t.Fatalf("matching identities rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*records.NTFSObjectIdentity)
	}{
		{
			name: "file reference",
			mutate: func(id *records.NTFSObjectIdentity) {
				id.FileReferenceNumber = "101"
			},
		},
		{
			name: "sequence number",
			mutate: func(id *records.NTFSObjectIdentity) {
				id.SequenceNumber = "2"
			},
		},
		{
			name: "identity method",
			mutate: func(id *records.NTFSObjectIdentity) {
				id.MethodVersion = "different-method"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := value
			candidate.Changes = append(
				[]records.USNChangeObservation(nil),
				value.Changes...,
			)

			tc.mutate(&candidate.Changes[1].FileIdentity)

			err := validateUSNObjectObservationPayload(
				"test-scope",
				candidate,
			)

			if err == nil ||
				!strings.Contains(err.Error(), "file identity does not match") {
				t.Fatalf("expected identity mismatch, got %v", err)
			}
		})
	}
}
