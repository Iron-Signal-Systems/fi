// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const sampleCaptureDigest = "f0b110dcda6e81a9fedc0192380e52ac39144acf74271f15883108fbeaad2590"
const sampleCorrelationDigest = "e0b110dcda6e81a9fedc0192380e52ac39144acf74271f15883108fbeaad2590"

func validCaptureBoundary() usnReadBoundaryPayload {
	return usnReadBoundaryPayload{
		SourceBatchSHA256:          sampleCaptureDigest,
		CorrelationSHA256:          sampleCorrelationDigest,
		RootIdentity:               &records.NTFSObjectIdentity{MethodVersion: "test", FileReferenceNumber: "99", SequenceNumber: "1"},
		SourceRecordCount:          3,
		SourceDistinctObjectCount:  2,
		SelectedRecordCount:        3,
		SelectedObjectCount:        2,
		ScopeUnresolvedObjectCount: 2,
		ReObservationOperationID:   "reobserve-test",
	}
}

func TestUSNBoundaryLegacyAndCaptureContracts(t *testing.T) {
	v := validCaptureBoundary()
	captured, err := validateUSNBoundaryContract(v)
	if err != nil || !captured {
		t.Fatalf("capture rejected: %v", err)
	}
	legacy := v
	legacy.SourceBatchSHA256, legacy.CorrelationSHA256, legacy.RootIdentity = "", "", nil
	legacy.USNReadOperationID = "legacy-operation"
	captured, err = validateUSNBoundaryContract(legacy)
	if err != nil || captured {
		t.Fatalf("legacy rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*usnReadBoundaryPayload)
	}{
		{"missing correlation", func(v *usnReadBoundaryPayload) { v.CorrelationSHA256 = "" }},
		{"bad digest", func(v *usnReadBoundaryPayload) { v.SourceBatchSHA256 = "abc" }},
		{"uppercase digest", func(v *usnReadBoundaryPayload) { v.SourceBatchSHA256 = strings.ToUpper(v.SourceBatchSHA256) }},
		{"missing root", func(v *usnReadBoundaryPayload) { v.RootIdentity = nil }},
		{"mixed operations", func(v *usnReadBoundaryPayload) { v.USNReadOperationID = "made-up" }},
		{"missing reobservation", func(v *usnReadBoundaryPayload) { v.ReObservationOperationID = "" }},
		{"bad selection count", func(v *usnReadBoundaryPayload) { v.SelectedRecordCount-- }},
		{"bad unresolved count", func(v *usnReadBoundaryPayload) { v.ScopeUnresolvedObjectCount-- }},
		{"bad ignored count", func(v *usnReadBoundaryPayload) { v.IgnoredVolumeRecordCount++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := validCaptureBoundary()
			tc.mutate(&v)
			if _, err := validateUSNBoundaryContract(v); err == nil {
				t.Fatal("malformed capture accepted")
			}
		})
	}
	legacy.USNReadOperationID = ""
	if _, err := validateUSNBoundaryContract(legacy); err == nil {
		t.Fatal("legacy without operation ID accepted")
	}
}

func TestUSNCaptureBindingScopeSourceGenerationAndCounts(t *testing.T) {
	state := newUSNCaptureState("source-a", "gen-a")
	root := *validCaptureBoundary().RootIdentity
	b := usnCaptureBoundary{recordID: 10, volumeID: 17, root: root, expectedObjects: 2, expectedChanges: 3}
	if err := state.remember("source-a", "scope-1", sampleCaptureDigest, b); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source, scope, digest string
		recordID              int64
	}{
		{"source-b", "scope-1", sampleCaptureDigest, 11},
		{"source-a", "scope-2", sampleCaptureDigest, 11},
		{"source-a", "scope-1", sampleCorrelationDigest, 11},
		{"source-a", "scope-1", sampleCaptureDigest, 9},
	} {
		if _, err := state.resolve(tc.source, tc.scope, tc.digest, tc.recordID); err == nil {
			t.Fatal("invalid capture association resolved", tc)
		}
	}
	if _, err := newUSNCaptureState("source-a", "gen-b").resolve("source-a", "scope-1", sampleCaptureDigest, 11); err == nil {
		t.Fatal("cross-generation association")
	}
	if err := state.remember("source-a", "scope-1", sampleCaptureDigest, b); err == nil {
		t.Fatal("duplicate boundary accepted")
	}
	value, err := state.resolve("source-a", "scope-1", sampleCaptureDigest, 11)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.completeObject(value, 2); err != nil {
		t.Fatal(err)
	}
	if err := state.verify(); err == nil {
		t.Fatal("incomplete batch accepted")
	}
	if err := state.completeObject(value, 1); err != nil {
		t.Fatal(err)
	}
	if err := state.verify(); err != nil {
		t.Fatal(err)
	}
	if err := state.completeObject(value, 1); err == nil {
		t.Fatal("object overrun accepted")
	}
}

// These JSON shapes mirror the two Windows producers: the legacy boundary
// contains synchronous operation IDs, while M6.1 provides a source-batch
// digest, correlation digest and root identity with no read-operation ID.
func TestUSNM61StrictPayloadShapes(t *testing.T) {
	capture := []byte(`{"source_batch_sha256":"` + sampleCaptureDigest + `","correlation_sha256":"` + sampleCorrelationDigest + `","root_identity":{"method_version":"test","file_reference_number":"99","sequence_number":"1"},"reobservation_operation_id":"r1","source_record_count":3,"source_distinct_object_count":2,"selected_record_count":3,"selected_object_count":2,"scope_unresolved_object_count":2}`)
	var boundary usnReadBoundaryPayload
	if err := decodeStrictPayload(capture, &boundary); err != nil {
		t.Fatal(err)
	}
	if bound, err := validateUSNBoundaryContract(boundary); err != nil || !bound {
		t.Fatalf("M6.1 payload rejected: %v", err)
	}
	old := []byte(`{"usn_read_operation_id":"legacy-1","reobservation_operation_id":"r1"}`)
	// Production decodes into a new value for every source record.
	boundary = usnReadBoundaryPayload{}
	if err := decodeStrictPayload(old, &boundary); err != nil {
		t.Fatal(err)
	}
	if bound, err := validateUSNBoundaryContract(boundary); err != nil || bound {
		t.Fatalf("legacy payload rejected: %v", err)
	}
	var object usnObjectObservationPayload
	if err := decodeStrictPayload([]byte(`{"source_batch_sha256":"`+sampleCaptureDigest+`","file_identity":{"method_version":"test","file_reference_number":"123","sequence_number":"1"}}`), &object); err != nil {
		t.Fatal(err)
	}
	if object.SourceBatchSHA256 != sampleCaptureDigest {
		t.Fatal("capture association disappeared")
	}
	if err := decodeStrictPayload([]byte(`{"source_batch_sha256":"`+sampleCaptureDigest+`","unknown_future_field":true}`), &object); err == nil {
		t.Fatal("unknown source-bound field accepted")
	}
}
