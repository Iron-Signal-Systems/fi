// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package certstore

import "testing"

func TestNormalizeCertificateSHA256(t *testing.T) {
	const upper = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	const lower = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	got, err := normalizeCertificateSHA256(upper)
	if err != nil {
		t.Fatalf("normalizeCertificateSHA256() error = %v", err)
	}
	if got != lower {
		t.Fatalf(
			"normalizeCertificateSHA256() = %q, want %q",
			got,
			lower,
		)
	}
}

func TestNormalizeCertificateSHA256RejectsInvalidValues(t *testing.T) {
	tests := []string{
		"",
		"abcd",
		"zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	for _, value := range tests {
		if _, err := normalizeCertificateSHA256(value); err == nil {
			t.Fatalf(
				"normalizeCertificateSHA256(%q) error = nil",
				value,
			)
		}
	}
}
