// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
)

// Tests.

func TestRetirementAuthorizationRejectsZeroValue(t *testing.T) {
	if _, err := (RetirementAuthorization{}).Acknowledgement(); err == nil {
		t.Fatal("Acknowledgement() error = nil, want zero-value rejection")
	}
}

func TestSentFrameValidateRejectsInvalidValues(t *testing.T) {
	valid := validSentFrame()
	tests := []struct {
		name    string
		mutate  func(*SentFrame)
		wantErr string
	}{
		{
			name: "invalid descriptor",
			mutate: func(value *SentFrame) {
				value.Descriptor.BatchID = ""
			},
			wantErr: "validate transport descriptor",
		},
		{
			name: "zero frame bytes",
			mutate: func(value *SentFrame) {
				value.FrameBytes = 0
			},
			wantErr: "frame byte count",
		},
		{
			name: "short frame digest",
			mutate: func(value *SentFrame) {
				value.FrameSHA256 = strings.Repeat("a", 63)
			},
			wantErr: "64 lowercase hexadecimal",
		},
		{
			name: "uppercase frame digest",
			mutate: func(value *SentFrame) {
				value.FrameSHA256 = strings.Repeat("A", 64)
			},
			wantErr: "lowercase hexadecimal",
		},
		{
			name: "invalid frame digest",
			mutate: func(value *SentFrame) {
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

func TestVerifyDurableAcknowledgementAcceptsDurableDuplicate(t *testing.T) {
	sent := validSentFrame()
	acknowledgement := acknowledgementForSentFrame(
		t,
		sent,
		transportack.OutcomeDurableDuplicate,
	)
	encoded := encodeAcknowledgement(t, acknowledgement)

	authorization, err := VerifyDurableAcknowledgement(
		bytes.NewReader(encoded),
		sent,
	)
	if err != nil {
		t.Fatalf("VerifyDurableAcknowledgement() error = %v", err)
	}
	got, err := authorization.Acknowledgement()
	if err != nil {
		t.Fatalf("Acknowledgement() error = %v", err)
	}
	if got != acknowledgement {
		t.Fatalf("Acknowledgement() = %#v, want %#v", got, acknowledgement)
	}
}

func TestVerifyDurableAcknowledgementAcceptsDurableNew(t *testing.T) {
	sent := validSentFrame()
	acknowledgement := acknowledgementForSentFrame(
		t,
		sent,
		transportack.OutcomeDurableNew,
	)
	encoded := encodeAcknowledgement(t, acknowledgement)

	authorization, err := VerifyDurableAcknowledgement(
		bytes.NewReader(encoded),
		sent,
	)
	if err != nil {
		t.Fatalf("VerifyDurableAcknowledgement() error = %v", err)
	}
	got, err := authorization.Acknowledgement()
	if err != nil {
		t.Fatalf("Acknowledgement() error = %v", err)
	}
	if got.Outcome != transportack.OutcomeDurableNew {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, transportack.OutcomeDurableNew)
	}
}

func TestVerifyDurableAcknowledgementDoesNotConsumeFollowingBytes(t *testing.T) {
	sent := validSentFrame()
	acknowledgement := acknowledgementForSentFrame(
		t,
		sent,
		transportack.OutcomeDurableNew,
	)
	encoded := append(encodeAcknowledgement(t, acknowledgement), []byte("NEXT")...)
	reader := bytes.NewReader(encoded)

	if _, err := VerifyDurableAcknowledgement(reader, sent); err != nil {
		t.Fatalf("VerifyDurableAcknowledgement() error = %v", err)
	}

	remaining := make([]byte, len("NEXT"))
	if _, err := reader.Read(remaining); err != nil {
		t.Fatalf("read trailing bytes: %v", err)
	}
	if string(remaining) != "NEXT" {
		t.Fatalf("trailing bytes = %q, want NEXT", remaining)
	}
}

func TestVerifyDurableAcknowledgementRejectsMismatches(t *testing.T) {
	sent := validSentFrame()
	tests := []struct {
		name    string
		mutate  func(*transportack.Acknowledgement)
		wantErr string
	}{
		{
			name: "source ID",
			mutate: func(value *transportack.Acknowledgement) {
				value.SourceID = "other-source.iss.local"
			},
			wantErr: "source ID",
		},
		{
			name: "batch ID",
			mutate: func(value *transportack.Acknowledgement) {
				value.BatchID = "other-batch"
			},
			wantErr: "batch ID",
		},
		{
			name: "data bytes",
			mutate: func(value *transportack.Acknowledgement) {
				value.DataBytes++
			},
			wantErr: "data byte count",
		},
		{
			name: "data digest",
			mutate: func(value *transportack.Acknowledgement) {
				value.DataSHA256 = strings.Repeat("3", 64)
			},
			wantErr: "data SHA-256",
		},
		{
			name: "manifest digest",
			mutate: func(value *transportack.Acknowledgement) {
				value.ManifestSHA256 = strings.Repeat("4", 64)
			},
			wantErr: "manifest SHA-256",
		},
		{
			name: "frame bytes",
			mutate: func(value *transportack.Acknowledgement) {
				value.FrameBytes++
			},
			wantErr: "frame byte count",
		},
		{
			name: "frame digest",
			mutate: func(value *transportack.Acknowledgement) {
				value.FrameSHA256 = strings.Repeat("5", 64)
			},
			wantErr: "frame SHA-256",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acknowledgement := acknowledgementForSentFrame(
				t,
				sent,
				transportack.OutcomeDurableNew,
			)
			test.mutate(&acknowledgement)
			encoded := encodeAcknowledgement(t, acknowledgement)

			_, err := VerifyDurableAcknowledgement(bytes.NewReader(encoded), sent)
			if err == nil {
				t.Fatalf("VerifyDurableAcknowledgement() error = nil, want %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"VerifyDurableAcknowledgement() error = %q, want containing %q",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func TestVerifyDurableAcknowledgementRejectsNilReader(t *testing.T) {
	if _, err := VerifyDurableAcknowledgement(nil, validSentFrame()); err == nil {
		t.Fatal("VerifyDurableAcknowledgement() error = nil, want nil-reader rejection")
	}
}

func TestVerifyDurableAcknowledgementRejectsTruncatedAcknowledgement(t *testing.T) {
	sent := validSentFrame()
	acknowledgement := acknowledgementForSentFrame(
		t,
		sent,
		transportack.OutcomeDurableNew,
	)
	encoded := encodeAcknowledgement(t, acknowledgement)
	encoded = encoded[:len(encoded)-1]

	_, err := VerifyDurableAcknowledgement(bytes.NewReader(encoded), sent)
	if err == nil {
		t.Fatal("VerifyDurableAcknowledgement() error = nil, want truncation rejection")
	}
	if !strings.Contains(err.Error(), "read FI durable acknowledgement") {
		t.Fatalf("VerifyDurableAcknowledgement() error = %q, want read failure", err)
	}
}

func TestVerifyDurableAcknowledgementValidatesSentFrameBeforeReading(t *testing.T) {
	sent := validSentFrame()
	sent.FrameBytes = 0
	reader := bytes.NewReader([]byte("UNTOUCHED"))

	_, err := VerifyDurableAcknowledgement(reader, sent)
	if err == nil {
		t.Fatal("VerifyDurableAcknowledgement() error = nil, want sent-frame rejection")
	}
	if reader.Len() != len("UNTOUCHED") {
		t.Fatalf("reader consumed %d bytes before sent-frame validation", len("UNTOUCHED")-reader.Len())
	}
}

// Test helpers.

func acknowledgementForSentFrame(
	t *testing.T,
	sent SentFrame,
	outcome transportack.Outcome,
) transportack.Acknowledgement {
	t.Helper()

	value, err := transportack.NewDurableAcknowledgement(
		outcome,
		sent.Descriptor.SourceID,
		sent.Descriptor.BatchID,
		sent.Descriptor.DataBytes,
		sent.Descriptor.DataSHA256,
		sent.Descriptor.ManifestSHA256,
		sent.FrameBytes,
		sent.FrameSHA256,
	)
	if err != nil {
		t.Fatalf("transportack.NewDurableAcknowledgement() error = %v", err)
	}
	return value
}

func encodeAcknowledgement(
	t *testing.T,
	value transportack.Acknowledgement,
) []byte {
	t.Helper()

	var encoded bytes.Buffer
	if err := transportack.WriteAcknowledgement(&encoded, value); err != nil {
		t.Fatalf("transportack.WriteAcknowledgement() error = %v", err)
	}
	return encoded.Bytes()
}

func validSentFrame() SentFrame {
	return SentFrame{
		Descriptor: transportbatch.Descriptor{
			Version:        transportbatch.DescriptorVersion,
			SourceID:       "iss-fs-01.iss.local",
			BatchID:        "20260912T215000.000000000Z-0011223344556677",
			RecordCount:    2,
			DataBytes:      30,
			DataSHA256:     strings.Repeat("1", 64),
			ManifestSHA256: strings.Repeat("2", 64),
		},
		FrameBytes:  4096,
		FrameSHA256: strings.Repeat("a", 64),
	}
}
