package transportrecovery

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
)

func TestSingleMemberTransportStructuresAreValid(t *testing.T) {
	member := Member{
		BatchID:        "20260915T230001.000000000Z-0000000000000001",
		RecordCount:    1,
		ManifestBytes:  100,
		ManifestSHA256: "11" + repeatHex("00", 31),
		DataBytes:      200,
		DataSHA256:     "22" + repeatHex("00", 31),
	}
	index := Index{
		Version: MemberIndexVersion,
		Members: []Member{member},
	}
	if err := index.Validate(); err != nil {
		t.Fatalf("single-member FI index rejected: %v", err)
	}
	encoded, err := MarshalIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalIndex(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Members) != 1 || decoded.Members[0].BatchID != member.BatchID {
		t.Fatal("single-member FI index did not round-trip")
	}

	descriptor := Descriptor{
		Version:           DescriptorVersion,
		SourceID:          "iss-fs-01.iss.local",
		RecoveryID:        "20260915T230002.000000000Z-0011223344556677",
		MemberCount:       1,
		RecordCount:       1,
		CanonicalBytes:    300,
		CanonicalSHA256:   "33" + repeatHex("00", 31),
		DataEncoding:      transportencoding.DataEncodingZstd,
		EncodedDataBytes:  50,
		EncodedDataSHA256: "44" + repeatHex("00", 31),
		IndexSHA256:       "55" + repeatHex("00", 31),
		FirstBatchID:      member.BatchID,
		LastBatchID:       member.BatchID,
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("single-member FI descriptor rejected: %v", err)
	}

	offer := Offer{
		Version:               "fi-recovery-offer/0.1",
		SourceID:              descriptor.SourceID,
		PendingMembers:        1,
		PendingCanonicalBytes: descriptor.CanonicalBytes,
		OldestBatchID:         member.BatchID,
		NewestBatchID:         member.BatchID,
		ProposedMembers:       1,
	}
	if err := offer.Validate(); err != nil {
		t.Fatalf("single-member FI offer rejected: %v", err)
	}
	decision := Decision{
		Version:           "fi-recovery-decision/0.1",
		Accepted:          true,
		MaxCanonicalBytes: 1 << 20,
		MaxEncodedBytes:   1 << 20,
		MaxMembers:        1,
	}
	if err := decision.Validate(); err != nil {
		t.Fatalf("single-member FI decision rejected: %v", err)
	}
	ack := Acknowledgement{
		Version:           "fi-recovery-ack/0.1",
		Outcome:           AcknowledgementDurableNew,
		SourceID:          descriptor.SourceID,
		RecoveryID:        descriptor.RecoveryID,
		MemberCount:       1,
		CanonicalBytes:    descriptor.CanonicalBytes,
		CanonicalSHA256:   descriptor.CanonicalSHA256,
		EncodedDataBytes:  descriptor.EncodedDataBytes,
		EncodedDataSHA256: descriptor.EncodedDataSHA256,
		IndexSHA256:       descriptor.IndexSHA256,
		FirstBatchID:      member.BatchID,
		LastBatchID:       member.BatchID,
		FrameBytes:        1234,
		FrameSHA256:       "66" + repeatHex("00", 31),
	}
	if err := ack.Validate(); err != nil {
		t.Fatalf("single-member FI acknowledgement rejected: %v", err)
	}
}
