// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package objbroker

import (
	"bytes"
	"strings"
	"testing"
)

func TestObservationLimitIsDerivedFromCollectorBounds(t *testing.T) {
	const want = 56688640
	if MaxObservationBytes != want {
		t.Fatalf("MaxObservationBytes = %d, want %d", MaxObservationBytes, want)
	}
}

func TestRequestRoundTripObserveObject(t *testing.T) {
	var buffer bytes.Buffer
	want := request{
		Operation:           operationObserveObject,
		GovernedRoot:        `D:\CountyShares`,
		FileReferenceNumber: 270203,
		SequenceNumber:      1070,
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

func TestRequestRejectsOversizedRoot(t *testing.T) {
	var buffer bytes.Buffer
	err := writeRequest(&buffer, request{
		Operation:           operationObserveObject,
		GovernedRoot:        `C:\` + strings.Repeat("x", maxRootBytes),
		FileReferenceNumber: 1,
	})
	if err == nil {
		t.Fatal("expected oversized governed-root rejection")
	}
}

func TestRequestRejectsOversizedFileReference(t *testing.T) {
	var buffer bytes.Buffer
	err := writeRequest(&buffer, request{
		Operation:           operationObserveObject,
		GovernedRoot:        `C:\FI-Lab`,
		FileReferenceNumber: 1 << 48,
	})
	if err == nil {
		t.Fatal("expected 48-bit file-reference rejection")
	}
}

func TestResponseRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	want := response{
		Data: []byte(`{"collection_method":"BackupAuthorityWindowsNTFS"}`),
	}
	if err := writeResponse(&buffer, want); err != nil {
		t.Fatal(err)
	}

	got, err := readResponse(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got.ErrorCode != 0 || got.Error != "" || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("response = %+v, want %+v", got, want)
	}
}

func TestResponseRoundTripError(t *testing.T) {
	var buffer bytes.Buffer
	want := response{
		ErrorCode: 5,
		Error:     "requested governed root is not configured for FI",
	}
	if err := writeResponse(&buffer, want); err != nil {
		t.Fatal(err)
	}

	got, err := readResponse(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got.ErrorCode != want.ErrorCode || got.Error != want.Error || len(got.Data) != 0 {
		t.Fatalf("response = %+v, want %+v", got, want)
	}
}

func TestResponseRejectsDataAndErrorTogether(t *testing.T) {
	var buffer bytes.Buffer
	err := writeResponse(&buffer, response{
		Data:  []byte{1},
		Error: "failure",
	})
	if err == nil {
		t.Fatal("expected mixed response rejection")
	}
}
