// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestValidateIssuingCAValidity(t *testing.T) {
	at := time.Date(
		2026,
		time.September,
		12,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	tests := []struct {
		name        string
		certificate *x509.Certificate
		wantError   bool
	}{
		{
			name: "valid",
			certificate: &x509.Certificate{
				NotBefore: at.Add(-time.Hour),
				NotAfter:  at.Add(time.Hour),
			},
			wantError: false,
		},
		{
			name: "not before boundary",
			certificate: &x509.Certificate{
				NotBefore: at,
				NotAfter:  at.Add(time.Hour),
			},
			wantError: false,
		},
		{
			name: "not after boundary",
			certificate: &x509.Certificate{
				NotBefore: at.Add(-time.Hour),
				NotAfter:  at,
			},
			wantError: false,
		},
		{
			name: "not yet valid",
			certificate: &x509.Certificate{
				NotBefore: at.Add(time.Second),
				NotAfter:  at.Add(time.Hour),
			},
			wantError: true,
		},
		{
			name: "expired",
			certificate: &x509.Certificate{
				NotBefore: at.Add(-time.Hour),
				NotAfter:  at.Add(-time.Second),
			},
			wantError: true,
		},
		{
			name:        "nil",
			certificate: nil,
			wantError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateIssuingCAValidity(test.certificate, at)

			if test.wantError && err == nil {
				t.Fatal("ValidateIssuingCAValidity() error = nil, want error")
			}

			if !test.wantError && err != nil {
				t.Fatalf("ValidateIssuingCAValidity() error = %v", err)
			}
		})
	}
}
