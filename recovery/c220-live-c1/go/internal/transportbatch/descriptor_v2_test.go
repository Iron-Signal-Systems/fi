// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportbatch

import (
	"encoding/hex"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
)

func TestDescriptorV2SignatureInput(t *testing.T) {
	descriptor := validDescriptorV2()

	value, err := descriptor.SignatureInput()
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}

	const expected = "46492d42415443482d5349474e41545552452d5632000000001666692d7472616e73706f72742d62617463682f302e32000000136973732d66732d30312e6973732e6c6f63616c0000000a62617463682d30303031000000047a7374640000000000000007000000000000100000000000000002000123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	if actual := hex.EncodeToString(value); actual != expected {
		t.Fatalf(
			"SignatureInput() = %q, want %q",
			actual,
			expected,
		)
	}
}

func TestDescriptorV1RejectsEncodedFields(t *testing.T) {
	descriptor := validDescriptor()
	descriptor.DataEncoding = transportencoding.DataEncodingZstd
	descriptor.EncodedDataBytes = 512
	descriptor.EncodedDataSHA256 =
		"00112233445566778899aabbccddeeff" +
			"00112233445566778899aabbccddeeff"

	if err := descriptor.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want encoded-field rejection")
	}
}

func TestDescriptorV2Validate(t *testing.T) {
	if err := validDescriptorV2().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDescriptorV2ValidateFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Descriptor)
	}{
		{
			name: "missing encoding",
			mutate: func(value *Descriptor) {
				value.DataEncoding = ""
			},
		},
		{
			name: "unsupported encoding",
			mutate: func(value *Descriptor) {
				value.DataEncoding = "gzip"
			},
		},
		{
			name: "zero encoded bytes",
			mutate: func(value *Descriptor) {
				value.EncodedDataBytes = 0
			},
		},
		{
			name: "uppercase encoded hash",
			mutate: func(value *Descriptor) {
				value.EncodedDataSHA256 =
					"A" + value.EncodedDataSHA256[1:]
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validDescriptorV2()
			test.mutate(&value)

			if err := value.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
		})
	}
}

func validDescriptorV2() Descriptor {
	value := validDescriptor()
	value.Version = DescriptorVersionV2
	value.DataEncoding = transportencoding.DataEncodingZstd
	value.EncodedDataBytes = 512
	value.EncodedDataSHA256 =
		"00112233445566778899aabbccddeeff" +
			"00112233445566778899aabbccddeeff"
	return value
}
