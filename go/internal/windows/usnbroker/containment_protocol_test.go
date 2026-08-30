// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"bytes"
	"testing"
)

func TestRequestRoundTripContainment(t *testing.T) {
	var buffer bytes.Buffer
	want := request{
		Operation:           operationContainment,
		GovernedRoot:        `C:\FI-Lab`,
		FileReferenceNumber: 251660,
		SequenceNumber:      2,
	}
	if err := writeRequest(&buffer, want); err != nil {
		t.Fatal(err)
	}
	got, err := readRequest(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("request = %+v, want %+v", got, want)
	}
}

func TestRequestRejectsContainmentFileReferenceAbove48Bits(t *testing.T) {
	var buffer bytes.Buffer
	err := writeRequest(&buffer, request{
		Operation:           operationContainment,
		GovernedRoot:        `C:\FI-Lab`,
		FileReferenceNumber: 1 << 48,
		SequenceNumber:      2,
	})
	if err == nil {
		t.Fatal("expected oversized file-reference rejection")
	}
}

func TestContainmentResponseRoundTrip(t *testing.T) {
	for _, want := range []ContainmentResult{
		ContainmentContained,
		ContainmentOutside,
		ContainmentUnavailable,
	} {
		var buffer bytes.Buffer
		if err := writeResponse(&buffer, response{Data: []byte{byte(want)}}); err != nil {
			t.Fatal(err)
		}
		got, err := readResponse(&buffer)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Data) != 1 || ContainmentResult(got.Data[0]) != want {
			t.Fatalf("data = %v, want containment %d", got.Data, want)
		}
	}
}
