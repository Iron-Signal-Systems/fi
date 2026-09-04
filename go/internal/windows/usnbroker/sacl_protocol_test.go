// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"bytes"
	"testing"
)

func TestRequestRejectsSACLFileReferenceAbove48Bits(t *testing.T) {
	var buffer bytes.Buffer
	err := writeRequest(&buffer, request{
		Operation:           operationSACL,
		GovernedRoot:        `C:\FI-Lab`,
		FileReferenceNumber: 1 << 48,
		SequenceNumber:      2,
	})
	if err == nil {
		t.Fatal("expected oversized SACL file-reference rejection")
	}
}

func TestRequestRoundTripSACL(t *testing.T) {
	var buffer bytes.Buffer
	want := request{
		Operation:           operationSACL,
		GovernedRoot:        `C:\FI-Lab`,
		FileReferenceNumber: 108488,
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
