// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportwire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
)

func TestReadHeaderV2RejectsBadMagic(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)
	encoded[0] ^= 0xff

	_, err := ReadHeaderV2(bytes.NewReader(encoded))
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want bad magic rejection")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Fatalf("ReadHeaderV2() error = %q, want bad magic rejection", err)
	}
}

func TestReadHeaderV2RejectsOversizedCertificateLengthBeforeAllocation(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)
	binary.BigEndian.PutUint32(
		encoded[160:164],
		transportpackage.MaxBatchSigningCertificateDERBytes+1,
	)

	_, err := ReadHeaderV2(bytes.NewReader(encoded[:fixedHeaderBytesV2]))
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want certificate length rejection")
	}
	if !strings.Contains(err.Error(), "certificate DER length is invalid") {
		t.Fatalf(
			"ReadHeaderV2() error = %q, want certificate length rejection",
			err,
		)
	}
}

func TestReadHeaderV2RejectsOversizedManifestLength(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)
	binary.BigEndian.PutUint64(encoded[52:60], MaxManifestBytes+1)

	_, err := ReadHeaderV2(bytes.NewReader(encoded[:fixedHeaderBytesV2]))
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want manifest length rejection")
	}
	if !strings.Contains(err.Error(), "published manifest length is invalid") {
		t.Fatalf(
			"ReadHeaderV2() error = %q, want manifest length rejection",
			err,
		)
	}
}

func TestReadHeaderV2RejectsOversizedSignatureLengthBeforeAllocation(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)
	binary.BigEndian.PutUint32(
		encoded[156:160],
		transportpackage.MaxBatchSignatureBytes+1,
	)

	_, err := ReadHeaderV2(bytes.NewReader(encoded[:fixedHeaderBytesV2]))
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want signature length rejection")
	}
	if !strings.Contains(err.Error(), "batch signature length is invalid") {
		t.Fatalf(
			"ReadHeaderV2() error = %q, want signature length rejection",
			err,
		)
	}
}

func TestReadHeaderV2RejectsOversizedSourceIDBeforeAllocation(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)
	binary.BigEndian.PutUint32(encoded[16:20], MaxTextBytes+1)

	_, err := ReadHeaderV2(bytes.NewReader(encoded[:fixedHeaderBytesV2]))
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want source ID length rejection")
	}
	if !strings.Contains(err.Error(), "source ID length is invalid") {
		t.Fatalf(
			"ReadHeaderV2() error = %q, want source ID length rejection",
			err,
		)
	}
}

func TestReadHeaderV2RejectsTruncatedFixedHeader(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)

	_, err := ReadHeaderV2(
		bytes.NewReader(encoded[:fixedHeaderBytesV2-1]),
	)
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want fixed-header truncation rejection")
	}
}

func TestReadHeaderV2RejectsTruncatedVariableHeader(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)

	_, err := ReadHeaderV2(bytes.NewReader(encoded[:len(encoded)-1]))
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want variable-header truncation rejection")
	}
}

func TestReadHeaderV2RejectsZeroManifestLength(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)
	binary.BigEndian.PutUint64(encoded[52:60], 0)

	_, err := ReadHeaderV2(bytes.NewReader(encoded[:fixedHeaderBytesV2]))
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want zero manifest length rejection")
	}
	if !strings.Contains(err.Error(), "published manifest length is invalid") {
		t.Fatalf(
			"ReadHeaderV2() error = %q, want manifest length rejection",
			err,
		)
	}
}

func TestWriteHeaderV2Deterministic(t *testing.T) {
	signedBatch, manifest := newWireTestBatchV2(t)

	var first bytes.Buffer
	if err := WriteHeaderV2(&first, signedBatch, manifest); err != nil {
		t.Fatalf("WriteHeaderV2(first) error = %v", err)
	}

	var second bytes.Buffer
	if err := WriteHeaderV2(&second, signedBatch, manifest); err != nil {
		t.Fatalf("WriteHeaderV2(second) error = %v", err)
	}

	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("WriteHeaderV2() produced non-deterministic bytes")
	}
}

func TestWriteHeaderV2RejectsManifestHashMismatch(t *testing.T) {
	signedBatch, manifest := newWireTestBatchV2(t)
	manifest = append(append([]byte(nil), manifest...), 'x')

	err := WriteHeaderV2(&bytes.Buffer{}, signedBatch, manifest)
	if err == nil {
		t.Fatal("WriteHeaderV2() error = nil, want manifest hash rejection")
	}
	if !strings.Contains(err.Error(), "does not match signed descriptor") {
		t.Fatalf(
			"WriteHeaderV2() error = %q, want manifest hash rejection",
			err,
		)
	}
}

func TestWriteHeaderV2RejectsNilWriter(t *testing.T) {
	signedBatch, manifest := newWireTestBatchV2(t)

	if err := WriteHeaderV2(nil, signedBatch, manifest); err == nil {
		t.Fatal("WriteHeaderV2() error = nil, want nil writer rejection")
	}
}

func FuzzReadHeaderV2(f *testing.F) {
	_, valid, _ := encodedWireTestHeaderV2(f)

	f.Add([]byte{})
	f.Add([]byte(frameMagicV2))
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadHeaderV2(bytes.NewReader(data))
	})
}
