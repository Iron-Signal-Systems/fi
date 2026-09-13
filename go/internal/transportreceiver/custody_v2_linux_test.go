// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

func TestReceiveToDurableCustodyV2PreservesExactCompressedFrame(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)
	reader := bytes.NewReader(append(frame, []byte("NEXT")...))
	root := t.TempDir()

	result, err := ReceiveToDurableCustody(
		reader,
		CustodyConfig{
			Intake:  fixture.config,
			RootDir: root,
		},
	)
	if err != nil {
		t.Fatalf("ReceiveToDurableCustody() error = %v", err)
	}
	if result.Disposition != CustodyDispositionNew {
		t.Fatalf(
			"Disposition = %q, want %q",
			result.Disposition,
			CustodyDispositionNew,
		)
	}
	if result.DataBytes != descriptor.DataBytes {
		t.Fatalf("DataBytes = %d, want %d", result.DataBytes, descriptor.DataBytes)
	}
	if result.DataSHA256 != descriptor.DataSHA256 {
		t.Fatalf("DataSHA256 = %q, want %q", result.DataSHA256, descriptor.DataSHA256)
	}
	if result.ManifestSHA256 != descriptor.ManifestSHA256 {
		t.Fatalf(
			"ManifestSHA256 = %q, want %q",
			result.ManifestSHA256,
			descriptor.ManifestSHA256,
		)
	}
	if result.FrameBytes != uint64(len(frame)) {
		t.Fatalf("FrameBytes = %d, want %d", result.FrameBytes, len(frame))
	}
	frameDigest := sha256.Sum256(frame)
	wantFrameSHA256 := hex.EncodeToString(frameDigest[:])
	if result.FrameSHA256 != wantFrameSHA256 {
		t.Fatalf("FrameSHA256 = %q, want %q", result.FrameSHA256, wantFrameSHA256)
	}

	stored, err := os.ReadFile(result.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, frame) {
		t.Fatal("durable custody object does not equal exact received FIWB0002 frame")
	}

	remaining := make([]byte, len("NEXT"))
	if _, err := reader.Read(remaining); err != nil {
		t.Fatalf("read following bytes: %v", err)
	}
	if string(remaining) != "NEXT" {
		t.Fatalf("remaining bytes = %q, want NEXT", remaining)
	}
}

func TestReceiveToDurableCustodyV2RejectsDifferentFrameForSameIdentity(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	firstFrame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)
	secondFrame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)
	if bytes.Equal(firstFrame, secondFrame) {
		t.Fatal("independent RSA-PSS FIWB0002 frames unexpectedly match exactly")
	}

	root := t.TempDir()
	config := CustodyConfig{
		Intake:  fixture.config,
		RootDir: root,
	}

	first, err := ReceiveToDurableCustody(bytes.NewReader(firstFrame), config)
	if err != nil {
		t.Fatalf("first ReceiveToDurableCustody() error = %v", err)
	}

	_, err = ReceiveToDurableCustody(bytes.NewReader(secondFrame), config)
	if err == nil {
		t.Fatal("second ReceiveToDurableCustody() error = nil, want custody conflict")
	}
	if !errors.Is(err, ErrCustodyConflict) {
		t.Fatalf("second ReceiveToDurableCustody() error = %v, want ErrCustodyConflict", err)
	}

	stored, err := os.ReadFile(first.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, firstFrame) {
		t.Fatal("FIWB0002 custody conflict changed the original durable frame")
	}
}

func TestReceiveToDurableCustodyV2ReturnsDuplicateForExactRetry(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)
	root := t.TempDir()
	config := CustodyConfig{
		Intake:  fixture.config,
		RootDir: root,
	}

	first, err := ReceiveToDurableCustody(bytes.NewReader(frame), config)
	if err != nil {
		t.Fatalf("first ReceiveToDurableCustody() error = %v", err)
	}
	second, err := ReceiveToDurableCustody(bytes.NewReader(frame), config)
	if err != nil {
		t.Fatalf("second ReceiveToDurableCustody() error = %v", err)
	}

	if first.Disposition != CustodyDispositionNew {
		t.Fatalf("first Disposition = %q, want NEW", first.Disposition)
	}
	if second.Disposition != CustodyDispositionDuplicate {
		t.Fatalf("second Disposition = %q, want DUPLICATE", second.Disposition)
	}
	if second.FramePath != first.FramePath {
		t.Fatalf("duplicate FramePath = %q, want %q", second.FramePath, first.FramePath)
	}
	if second.FrameSHA256 != first.FrameSHA256 {
		t.Fatalf("duplicate FrameSHA256 = %q, want %q", second.FrameSHA256, first.FrameSHA256)
	}

	stored, err := os.ReadFile(first.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, frame) {
		t.Fatal("exact FIWB0002 retry changed durable custody bytes")
	}
}
