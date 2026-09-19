package transportrecovery

import (
	"bytes"
	"testing"
)

func TestRecoveryControlRoundTrips(t *testing.T) {
	offer := Offer{
		Version:               "fi-recovery-offer/0.1",
		SourceID:              "iss-fs-01.iss.local",
		PendingMembers:        100000,
		PendingCanonicalBytes: 50 << 30,
		OldestBatchID:         "a",
		NewestBatchID:         "z",
		ProposedMembers:       50000,
	}
	var wire bytes.Buffer
	if err := WriteOffer(&wire, offer); err != nil {
		t.Fatal(err)
	}
	actual, err := ReadOffer(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if actual != offer {
		t.Fatalf("offer mismatch: %#v != %#v", actual, offer)
	}

	decision := Decision{Version: "fi-recovery-decision/0.1", Accepted: true, MaxCanonicalBytes: 64 << 30, MaxEncodedBytes: 8 << 30, MaxMembers: 50000}
	wire.Reset()
	if err := WriteDecision(&wire, decision); err != nil {
		t.Fatal(err)
	}
	actualDecision, err := ReadDecision(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if actualDecision != decision {
		t.Fatal("decision mismatch")
	}
}

func TestAcknowledgementMatchesExactFrame(t *testing.T) {
	descriptor := testDescriptor()
	ack := Acknowledgement{
		Version:           "fi-recovery-ack/0.1",
		Outcome:           AcknowledgementDurableNew,
		SourceID:          descriptor.SourceID,
		RecoveryID:        descriptor.RecoveryID,
		MemberCount:       descriptor.MemberCount,
		CanonicalBytes:    descriptor.CanonicalBytes,
		CanonicalSHA256:   descriptor.CanonicalSHA256,
		EncodedDataBytes:  descriptor.EncodedDataBytes,
		EncodedDataSHA256: descriptor.EncodedDataSHA256,
		IndexSHA256:       descriptor.IndexSHA256,
		FirstBatchID:      descriptor.FirstBatchID,
		LastBatchID:       descriptor.LastBatchID,
		FrameBytes:        1234,
		FrameSHA256:       "44" + repeatHex("00", 31),
	}
	if err := AcknowledgementMatches(ack, descriptor, 1234, ack.FrameSHA256); err != nil {
		t.Fatal(err)
	}
	ack.FrameBytes++
	if err := AcknowledgementMatches(ack, descriptor, 1234, ack.FrameSHA256); err == nil {
		t.Fatal("mismatched frame bytes unexpectedly authorized")
	}
}
