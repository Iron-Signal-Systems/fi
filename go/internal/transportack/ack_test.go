// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// Tests.

func TestAcknowledgementValidateRejectsInvalidValues(t *testing.T) {
	valid := validAcknowledgement()
	tests := []struct {
		name    string
		mutate  func(*Acknowledgement)
		wantErr string
	}{
		{
			name: "bad version",
			mutate: func(value *Acknowledgement) {
				value.Version = "fi-transport-ack/9.9"
			},
			wantErr: "acknowledgement version",
		},
		{
			name: "bad outcome",
			mutate: func(value *Acknowledgement) {
				value.Outcome = "CONFLICT"
			},
			wantErr: "unsupported durable acknowledgement outcome",
		},
		{
			name: "missing source",
			mutate: func(value *Acknowledgement) {
				value.SourceID = ""
			},
			wantErr: "source ID is required",
		},
		{
			name: "missing batch",
			mutate: func(value *Acknowledgement) {
				value.BatchID = ""
			},
			wantErr: "batch ID is required",
		},
		{
			name: "zero data bytes",
			mutate: func(value *Acknowledgement) {
				value.DataBytes = 0
			},
			wantErr: "data byte count",
		},
		{
			name: "zero frame bytes",
			mutate: func(value *Acknowledgement) {
				value.FrameBytes = 0
			},
			wantErr: "frame byte count",
		},
		{
			name: "short data digest",
			mutate: func(value *Acknowledgement) {
				value.DataSHA256 = "00"
			},
			wantErr: "data SHA-256",
		},
		{
			name: "uppercase manifest digest",
			mutate: func(value *Acknowledgement) {
				value.ManifestSHA256 = strings.ToUpper(value.ManifestSHA256)
			},
			wantErr: "lowercase hexadecimal",
		},
		{
			name: "invalid frame digest",
			mutate: func(value *Acknowledgement) {
				value.FrameSHA256 = strings.Repeat("z", 64)
			},
			wantErr: "invalid hexadecimal",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			err := value.Validate()
			if err == nil {
				t.Fatalf("Validate() error = nil, want %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %q, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestNewDurableAcknowledgement(t *testing.T) {
	want := validAcknowledgement()
	got, err := NewDurableAcknowledgement(
		want.Outcome,
		want.SourceID,
		want.BatchID,
		want.DataBytes,
		want.DataSHA256,
		want.ManifestSHA256,
		want.FrameBytes,
		want.FrameSHA256,
	)
	if err != nil {
		t.Fatalf("NewDurableAcknowledgement() error = %v", err)
	}
	if got != want {
		t.Fatalf("NewDurableAcknowledgement() = %#v, want %#v", got, want)
	}
}

func TestNewDurableAcknowledgementAcceptsDuplicate(t *testing.T) {
	value := validAcknowledgement()
	value.Outcome = OutcomeDurableDuplicate

	got, err := NewDurableAcknowledgement(
		value.Outcome,
		value.SourceID,
		value.BatchID,
		value.DataBytes,
		value.DataSHA256,
		value.ManifestSHA256,
		value.FrameBytes,
		value.FrameSHA256,
	)
	if err != nil {
		t.Fatalf("NewDurableAcknowledgement() error = %v", err)
	}
	if got.Outcome != OutcomeDurableDuplicate {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, OutcomeDurableDuplicate)
	}
}

func TestNewDurableAcknowledgementRejectsConflict(t *testing.T) {
	value := validAcknowledgement()
	_, err := NewDurableAcknowledgement(
		"CONFLICT",
		value.SourceID,
		value.BatchID,
		value.DataBytes,
		value.DataSHA256,
		value.ManifestSHA256,
		value.FrameBytes,
		value.FrameSHA256,
	)
	if err == nil {
		t.Fatal("NewDurableAcknowledgement() error = nil, want conflict rejection")
	}
}

func TestReadAcknowledgementLeavesFollowingBytes(t *testing.T) {
	want := validAcknowledgement()
	var encoded bytes.Buffer
	if err := WriteAcknowledgement(&encoded, want); err != nil {
		t.Fatalf("WriteAcknowledgement() error = %v", err)
	}

	reader := bytes.NewReader(append(encoded.Bytes(), []byte("NEXT")...))
	got, err := ReadAcknowledgement(reader)
	if err != nil {
		t.Fatalf("ReadAcknowledgement() error = %v", err)
	}
	if got != want {
		t.Fatalf("ReadAcknowledgement() = %#v, want %#v", got, want)
	}

	remaining := make([]byte, 4)
	if _, err := io.ReadFull(reader, remaining); err != nil {
		t.Fatalf("read following bytes: %v", err)
	}
	if string(remaining) != "NEXT" {
		t.Fatalf("following bytes = %q, want NEXT", remaining)
	}
}

func TestReadAcknowledgementRejectsInvalidMagic(t *testing.T) {
	encoded := encodeAcknowledgement(t, validAcknowledgement())
	encoded[0] ^= 0x01

	_, err := ReadAcknowledgement(bytes.NewReader(encoded))
	if err == nil {
		t.Fatal("ReadAcknowledgement() error = nil, want magic rejection")
	}
	if !strings.Contains(err.Error(), "wire magic") {
		t.Fatalf("ReadAcknowledgement() error = %q, want magic rejection", err)
	}
}

func TestReadAcknowledgementRejectsLengthBeforeAllocation(t *testing.T) {
	encoded := encodeAcknowledgement(t, validAcknowledgement())
	binary.BigEndian.PutUint32(encoded[16:20], MaxTextBytes+1)

	_, err := ReadAcknowledgement(bytes.NewReader(encoded))
	if err == nil {
		t.Fatal("ReadAcknowledgement() error = nil, want length rejection")
	}
	if !strings.Contains(err.Error(), "source ID length is invalid") {
		t.Fatalf("ReadAcknowledgement() error = %q, want source length rejection", err)
	}
}

func TestReadAcknowledgementRejectsTruncatedFrame(t *testing.T) {
	encoded := encodeAcknowledgement(t, validAcknowledgement())
	encoded = encoded[:len(encoded)-1]

	_, err := ReadAcknowledgement(bytes.NewReader(encoded))
	if err == nil {
		t.Fatal("ReadAcknowledgement() error = nil, want truncated-frame rejection")
	}
}

func TestWriteAcknowledgementIsDeterministic(t *testing.T) {
	value := validAcknowledgement()
	first := encodeAcknowledgement(t, value)
	second := encodeAcknowledgement(t, value)
	if !bytes.Equal(first, second) {
		t.Fatal("acknowledgement encoding is not deterministic")
	}

	wantLength := fixedAcknowledgementBytes +
		len(value.Version) +
		len(value.Outcome) +
		len(value.SourceID) +
		len(value.BatchID)
	if len(first) != wantLength {
		t.Fatalf("encoded acknowledgement length = %d, want %d", len(first), wantLength)
	}
}

func TestWriteAcknowledgementRejectsInvalidValue(t *testing.T) {
	value := validAcknowledgement()
	value.Outcome = "CONFLICT"

	var encoded bytes.Buffer
	err := WriteAcknowledgement(&encoded, value)
	if err == nil {
		t.Fatal("WriteAcknowledgement() error = nil, want invalid-value rejection")
	}
	if encoded.Len() != 0 {
		t.Fatalf("WriteAcknowledgement() wrote %d bytes before validation failure", encoded.Len())
	}
}

func TestWriteAcknowledgementRejectsNilWriter(t *testing.T) {
	err := WriteAcknowledgement(nil, validAcknowledgement())
	if err == nil {
		t.Fatal("WriteAcknowledgement() error = nil, want nil-writer rejection")
	}
}

func TestWriteAcknowledgementHandlesShortWrites(t *testing.T) {
	value := validAcknowledgement()
	writer := &limitedWriter{max: 7}
	if err := WriteAcknowledgement(writer, value); err != nil {
		t.Fatalf("WriteAcknowledgement() error = %v", err)
	}

	got, err := ReadAcknowledgement(bytes.NewReader(writer.bytes.Bytes()))
	if err != nil {
		t.Fatalf("ReadAcknowledgement() error = %v", err)
	}
	if got != value {
		t.Fatalf("round trip = %#v, want %#v", got, value)
	}
}

func TestWriteAcknowledgementPropagatesWriterFailure(t *testing.T) {
	err := WriteAcknowledgement(failingWriter{}, validAcknowledgement())
	if err == nil {
		t.Fatal("WriteAcknowledgement() error = nil, want writer failure")
	}
	if !errors.Is(err, errAcknowledgementTestWriter) {
		t.Fatalf("WriteAcknowledgement() error = %v, want writer failure", err)
	}
}

// Test helpers.

var errAcknowledgementTestWriter = errors.New("test writer failure")

type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) {
	return 0, errAcknowledgementTestWriter
}

type limitedWriter struct {
	bytes bytes.Buffer
	max   int
}

func (writer *limitedWriter) Write(value []byte) (int, error) {
	if len(value) > writer.max {
		value = value[:writer.max]
	}
	return writer.bytes.Write(value)
}

func encodeAcknowledgement(t *testing.T, value Acknowledgement) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := WriteAcknowledgement(&encoded, value); err != nil {
		t.Fatalf("WriteAcknowledgement() error = %v", err)
	}
	return append([]byte(nil), encoded.Bytes()...)
}

func validAcknowledgement() Acknowledgement {
	return Acknowledgement{
		Version:        AcknowledgementVersion,
		Outcome:        OutcomeDurableNew,
		SourceID:       "iss-fs-01.iss.local",
		BatchID:        "20260912T193000.000000000Z-0011223344556677",
		DataBytes:      28,
		DataSHA256:     strings.Repeat("1a", 32),
		ManifestSHA256: strings.Repeat("2b", 32),
		FrameBytes:     4096,
		FrameSHA256:    strings.Repeat("3c", 32),
	}
}
