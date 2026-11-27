// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAuditPolicyRequestRoundTrip(t *testing.T) {
	var b bytes.Buffer
	expected := request{Operation: operationAuditPolicy}
	if err := writeRequest(&b, expected); err != nil {
		t.Fatal(err)
	}
	got, err := readRequest(&b)
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Fatalf("got %+v want %+v", got, expected)
	}
}

func TestAuditPolicyRejectsCallerParameters(t *testing.T) {
	cases := []request{
		{Operation: operationAuditPolicy, GovernedRoot: `C:\Governed`},
		{Operation: operationAuditPolicy, StartUSN: 1},
		{Operation: operationAuditPolicy, FileReferenceNumber: 1},
		{Operation: operationAuditPolicy, SequenceNumber: 1},
	}
	for _, request := range cases {
		var b bytes.Buffer
		if err := writeRequest(&b, request); err == nil {
			t.Fatalf("accepted variable audit-policy request %+v", request)
		}
	}
}

func TestAuditPolicyRejectsMalformedWireRequest(t *testing.T) {
	var b bytes.Buffer
	if err := writeRequest(&b, request{Operation: operationAuditPolicy}); err != nil {
		t.Fatal(err)
	}
	original := b.Bytes()
	for _, mutate := range []func([]byte){
		func(v []byte) { binary.LittleEndian.PutUint32(v[8:12], 1) },
		func(v []byte) { binary.LittleEndian.PutUint64(v[12:20], 1) },
		func(v []byte) { binary.LittleEndian.PutUint32(v[20:24], 1) },
	} {
		corrupted := append([]byte(nil), original...)
		mutate(corrupted)
		if _, err := readRequest(bytes.NewReader(corrupted)); err == nil {
			t.Fatal("accepted malformed audit-policy request")
		}
	}
}
