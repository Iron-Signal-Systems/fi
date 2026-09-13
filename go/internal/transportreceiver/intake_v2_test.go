// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportreceiver

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportwire"
)

func TestReadValidatedBatchV2(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)

	reader := bytes.NewReader(append(frame, []byte("NEXT")...))
	var received bytes.Buffer

	result, err := ReadValidatedBatch(reader, &received, fixture.config)
	if err != nil {
		t.Fatalf("ReadValidatedBatch() error = %v", err)
	}
	if result.Header.SignedBatch.Descriptor.Version !=
		transportbatch.DescriptorVersionV2 {
		t.Fatalf(
			"descriptor version = %q, want %q",
			result.Header.SignedBatch.Descriptor.Version,
			transportbatch.DescriptorVersionV2,
		)
	}
	if !bytes.Equal(received.Bytes(), fixture.data) {
		t.Fatalf("received canonical data = %q, want %q", received.Bytes(), fixture.data)
	}

	remaining := make([]byte, len("NEXT"))
	if _, err := reader.Read(remaining); err != nil {
		t.Fatalf("read following bytes: %v", err)
	}
	if string(remaining) != "NEXT" {
		t.Fatalf("remaining bytes = %q, want NEXT", remaining)
	}
}

func TestReadValidatedBatchV2RejectsCanonicalHashMismatch(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	descriptor.DataSHA256 = strings.Repeat("0", 64)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want canonical hash rejection")
	}
	if !strings.Contains(err.Error(), "data SHA-256") {
		t.Fatalf("ReadValidatedBatch() error = %q, want canonical hash rejection", err)
	}
}

func TestReadValidatedBatchV2RejectsCorruptEncodedPayload(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	corrupt := append([]byte(nil), encoded...)
	corrupt[len(corrupt)/2] ^= 0xff

	// Bind and sign the corrupted encoded representation. This ensures rejection
	// comes from zstd/canonical validation rather than a stale encoded digest.
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, corrupt)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, corrupt)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want corrupt zstd rejection")
	}
}

func TestReadValidatedBatchV2RejectsDecodedDataBeyondSignedBoundary(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	canonical := fixture.data[:len(fixture.data)-1]
	descriptor := intakeTestDescriptorV2(fixture, canonical, encoded)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want canonical-boundary rejection")
	}
	if !strings.Contains(err.Error(), "exceeds signed canonical byte count") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want canonical-boundary rejection",
			err,
		)
	}
}

func TestReadValidatedBatchV2RejectsEncodedHashMismatch(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	descriptor.EncodedDataSHA256 = strings.Repeat("0", 64)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want encoded hash rejection")
	}
	if !strings.Contains(err.Error(), "encoded data SHA-256") {
		t.Fatalf("ReadValidatedBatch() error = %q, want encoded hash rejection", err)
	}
}

func TestReadValidatedBatchV2RejectsEncodedPayloadAboveReceiverLimit(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	canonical := []byte("x")
	encoded := encodeIntakeTestZstd(t, canonical)
	if len(encoded) <= len(canonical) {
		t.Fatalf(
			"encoded test payload = %d bytes, need more than canonical %d",
			len(encoded),
			len(canonical),
		)
	}

	descriptor := intakeTestDescriptorV2(fixture, canonical, encoded)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)
	config := fixture.config
	config.MaxDataBytes = uint64(len(canonical))

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want encoded receiver-limit rejection")
	}
	if !strings.Contains(err.Error(), "encoded data byte count") ||
		!strings.Contains(err.Error(), "exceeds receiver limit") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want encoded receiver-limit rejection",
			err,
		)
	}
}

func TestReadValidatedBatchV2RejectsInvalidMagic(t *testing.T) {
	fixture := newIntakeTestFixture(t)

	_, err := ReadValidatedBatch(
		bytes.NewReader([]byte("FIWB9999")),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want invalid-magic rejection")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Fatalf("ReadValidatedBatch() error = %q, want invalid-magic rejection", err)
	}
}

func TestReadValidatedBatchV2RejectsTruncatedEncodedPayload(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	frame := encodeIntakeTestFrameV2(
		t,
		fixture,
		descriptor,
		encoded[:len(encoded)-1],
	)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want truncated encoded payload rejection")
	}
}

func encodeIntakeTestFrameV2(
	t *testing.T,
	fixture intakeTestFixture,
	descriptor transportbatch.Descriptor,
	encoded []byte,
) []byte {
	t.Helper()

	signedBatch, err := transportpackage.NewSignedBatch(
		descriptor,
		fixture.leaf,
		fixture.leafKey,
	)
	if err != nil {
		t.Fatalf("transportpackage.NewSignedBatch() error = %v", err)
	}

	var frame bytes.Buffer
	if err := transportwire.WriteHeaderV2(
		&frame,
		signedBatch,
		fixture.manifest,
	); err != nil {
		t.Fatalf("transportwire.WriteHeaderV2() error = %v", err)
	}
	frame.Write(fixture.manifest)
	frame.Write(encoded)
	return frame.Bytes()
}

func encodeIntakeTestZstd(t *testing.T, canonical []byte) []byte {
	t.Helper()

	var encoded bytes.Buffer
	encoder, err := transportencoding.NewZstdEncoder(&encoded)
	if err != nil {
		t.Fatalf("transportencoding.NewZstdEncoder() error = %v", err)
	}
	if _, err := encoder.Write(canonical); err != nil {
		encoder.Close()
		t.Fatalf("zstd Write() error = %v", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("zstd Close() error = %v", err)
	}
	return append([]byte(nil), encoded.Bytes()...)
}

func intakeTestDescriptorV2(
	fixture intakeTestFixture,
	canonical []byte,
	encoded []byte,
) transportbatch.Descriptor {
	value := fixture.signedBatch.Descriptor
	value.Version = transportbatch.DescriptorVersionV2
	value.RecordCount = 1
	value.DataBytes = uint64(len(canonical))
	value.DataSHA256 = digestHex(canonical)
	value.DataEncoding = transportencoding.DataEncodingZstd
	value.EncodedDataBytes = uint64(len(encoded))
	value.EncodedDataSHA256 = digestHex(encoded)
	return value
}
