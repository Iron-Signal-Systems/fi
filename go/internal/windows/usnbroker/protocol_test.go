// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"bytes"
	"strings"
	"testing"
)

func TestRequestRoundTripQuery(t *testing.T) {
	var buffer bytes.Buffer
	want := request{Operation: operationQuery, GovernedRoot: `C:\FI-Lab`}
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

func TestRequestRoundTripRead(t *testing.T) {
	var buffer bytes.Buffer
	want := request{Operation: operationRead, GovernedRoot: `D:\CountyShares`, StartUSN: 123456}
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
		Operation:    operationQuery,
		GovernedRoot: `C:\` + strings.Repeat("x", maxRootBytes),
	})
	if err == nil {
		t.Fatal("expected oversized governed-root rejection")
	}
}

func TestResponseRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	want := response{
		Journal: Journal{
			JournalID:       11,
			FirstUSN:        12,
			NextUSN:         13,
			LowestValidUSN:  14,
			MaxUSN:          15,
			MaximumSize:     16,
			AllocationDelta: 17,
		},
		Data: []byte{1, 2, 3, 4},
	}
	if err := writeResponse(&buffer, want); err != nil {
		t.Fatal(err)
	}
	got, err := readResponse(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got.Journal != want.Journal || !bytes.Equal(got.Data, want.Data) || got.Error != "" || got.ErrorCode != 0 {
		t.Fatalf("response = %+v, want %+v", got, want)
	}
}

func TestResponseRoundTripError(t *testing.T) {
	var buffer bytes.Buffer
	want := response{ErrorCode: 5, Error: "volume not configured"}
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
