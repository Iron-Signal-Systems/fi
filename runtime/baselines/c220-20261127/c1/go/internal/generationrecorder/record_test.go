// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func TestRecordedReceiptRoundTrip(t *testing.T) {
	receipt := testRecordedReceipt()

	raw, err := MarshalRecordedReceipt(receipt)
	if err != nil {
		t.Fatalf("MarshalRecordedReceipt() error = %v", err)
	}

	decoded, err := UnmarshalRecordedReceipt(raw)
	if err != nil {
		t.Fatalf("UnmarshalRecordedReceipt() error = %v", err)
	}

	if decoded != receipt {
		t.Fatalf("decoded receipt = %#v, want %#v", decoded, receipt)
	}
}

func TestRecordedReceiptRejectsUnknownField(t *testing.T) {
	receipt := testRecordedReceipt()

	raw, err := MarshalRecordedReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}

	raw = bytes.TrimSpace(raw)
	raw = append(raw[:len(raw)-1], []byte(",\"unexpected\":true}\n")...)

	if _, err := UnmarshalRecordedReceipt(raw); err == nil {
		t.Fatal("UnmarshalRecordedReceipt() error = nil, want unknown-field rejection")
	}
}

func TestRecordedReceiptRejectsTrailingJSON(t *testing.T) {
	raw, err := MarshalRecordedReceipt(testRecordedReceipt())
	if err != nil {
		t.Fatal(err)
	}

	raw = append(raw, []byte("{}\n")...)

	if _, err := UnmarshalRecordedReceipt(raw); err == nil {
		t.Fatal("UnmarshalRecordedReceipt() error = nil, want trailing-JSON rejection")
	}
}

func testRecordedReceipt() RecordedReceipt {
	descriptor := transportgeneration.Descriptor{
		Version:           transportgeneration.DescriptorVersion,
		SourceID:          "iss-fs-01.iss.local",
		GenerationID:      "20260918T163000.000000000Z-0123456789abcdef",
		CanonicalVersion:  transportgeneration.CanonicalVersion,
		DataEncoding:      "zstd",
		ArtifactCount:     2,
		SourceBytes:       2048,
		CanonicalBytes:    2300,
		CanonicalSHA256:   strings.Repeat("1", 64),
		EncodedDataBytes:  1024,
		EncodedDataSHA256: strings.Repeat("2", 64),
	}

	return RecordedReceipt{
		Version:        RecordedReceiptVersion,
		Descriptor:     descriptor,
		MetadataBytes:  512,
		MetadataSHA256: strings.Repeat("3", 64),
		TransferBytes:  generationTransferHeaderBytes + 512 + 1024,
		TransferSHA256: strings.Repeat("4", 64),
		BatchCount:     1,
		DataBytes:      1800,
		RecordCount:    7,
	}
}
