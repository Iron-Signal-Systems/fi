// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadBufferSizesRoundTrip(t *testing.T) {
	for _, size := range []uint32{1, 2, 4, 8, 16, 32, 64} {
		var wire bytes.Buffer
		want := request{Operation: operationRead, GovernedRoot: `F:\FI-Governed-10M`, StartUSN: 42, ReadBufferMiB: size}
		if err := writeRequest(&wire, want); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		got, err := readRequest(&wire)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if got != want {
			t.Fatalf("size %d: got %+v, want %+v", size, got, want)
		}
	}
}

func TestReadBufferSizesRejectInvalid(t *testing.T) {
	for _, size := range []uint32{0, 65, 1024} {
		var wire bytes.Buffer
		err := writeRequest(&wire, request{Operation: operationRead, GovernedRoot: `F:\FI-Governed-10M`, ReadBufferMiB: size})
		if err == nil {
			t.Fatalf("size %d unexpectedly accepted", size)
		}
	}
}

func TestReadRequestRejectsForgedOversizedBuffer(t *testing.T) {
	var wire bytes.Buffer
	want := request{Operation: operationRead, GovernedRoot: `F:\FI-Governed-10M`, ReadBufferMiB: 8}
	if err := writeRequest(&wire, want); err != nil {
		t.Fatal(err)
	}
	bytes := wire.Bytes()
	binary.LittleEndian.PutUint32(bytes[20:24], 65)
	if _, err := readRequest(&wire); err == nil {
		t.Fatal("oversized wire request unexpectedly accepted")
	}
}

func TestReadResponseBoundedAt64MiB(t *testing.T) {
	var wire bytes.Buffer
	if err := writeResponse(&wire, response{Data: make([]byte, MaxUSNDataBytes)}); err != nil {
		t.Fatalf("64 MiB response: %v", err)
	}
	if _, err := readResponse(&wire); err != nil {
		t.Fatalf("64 MiB read: %v", err)
	}
	var tooBig bytes.Buffer
	if err := writeResponse(&tooBig, response{Data: make([]byte, MaxUSNDataBytes+1)}); err == nil {
		t.Fatal("response exceeding 64 MiB unexpectedly accepted")
	}
}
