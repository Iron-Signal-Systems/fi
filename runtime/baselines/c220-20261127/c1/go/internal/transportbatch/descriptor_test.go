// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportbatch

import (
	"encoding/hex"
	"testing"
)

func TestDescriptorSignatureInput(t *testing.T) {
	descriptor := validDescriptor()

	value, err := descriptor.SignatureInput()
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}

	const expected = "46492d42415443482d5349474e41545552452d5631000000001666692d7472616e73706f72742d62617463682f302e31000000136973732d66732d30312e6973732e6c6f63616c0000000a62617463682d30303031000000000000000700000000000010000123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	if actual := hex.EncodeToString(value); actual != expected {
		t.Fatalf(
			"SignatureInput() = %q, want %q",
			actual,
			expected,
		)
	}
}

func TestDescriptorSignatureInputRejectsInvalidDescriptor(t *testing.T) {
	descriptor := validDescriptor()
	descriptor.BatchID = ""

	if _, err := descriptor.SignatureInput(); err == nil {
		t.Fatal("SignatureInput() error = nil, want error")
	}
}

func TestDescriptorValidate(t *testing.T) {
	if err := validDescriptor().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDescriptorValidateFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Descriptor)
	}{
		{
			name: "wrong version",
			mutate: func(value *Descriptor) {
				value.Version = "fi-transport-batch/9.9"
			},
		},
		{
			name: "missing source ID",
			mutate: func(value *Descriptor) {
				value.SourceID = ""
			},
		},
		{
			name: "missing batch ID",
			mutate: func(value *Descriptor) {
				value.BatchID = ""
			},
		},
		{
			name: "zero record count",
			mutate: func(value *Descriptor) {
				value.RecordCount = 0
			},
		},
		{
			name: "zero data bytes",
			mutate: func(value *Descriptor) {
				value.DataBytes = 0
			},
		},
		{
			name: "uppercase data hash",
			mutate: func(value *Descriptor) {
				value.DataSHA256 = "A" + value.DataSHA256[1:]
			},
		},
		{
			name: "short manifest hash",
			mutate: func(value *Descriptor) {
				value.ManifestSHA256 = value.ManifestSHA256[:63]
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validDescriptor()
			test.mutate(&value)

			if err := value.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
		})
	}
}

func validDescriptor() Descriptor {
	return Descriptor{
		Version:     DescriptorVersion,
		SourceID:    "iss-fs-01.iss.local",
		BatchID:     "batch-0001",
		RecordCount: 7,
		DataBytes:   4096,
		DataSHA256: "0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef",
		ManifestSHA256: "abcdef0123456789abcdef0123456789" +
			"abcdef0123456789abcdef0123456789",
	}
}
