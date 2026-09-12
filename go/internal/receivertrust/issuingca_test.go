// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"testing"
)

func TestValidateIssuingCAStructure(t *testing.T) {
	certificate := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	if err := ValidateIssuingCAStructure(certificate); err != nil {
		t.Fatalf("ValidateIssuingCAStructure() error = %v", err)
	}
}

func TestValidateIssuingCAStructureFailures(t *testing.T) {
	tests := []struct {
		name        string
		certificate *x509.Certificate
	}{
		{
			name:        "nil",
			certificate: nil,
		},
		{
			name: "basic constraints invalid",
			certificate: &x509.Certificate{
				BasicConstraintsValid: false,
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			},
		},
		{
			name: "not CA",
			certificate: &x509.Certificate{
				BasicConstraintsValid: true,
				IsCA:                  false,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			},
		},
		{
			name: "missing certificate signing",
			certificate: &x509.Certificate{
				BasicConstraintsValid: true,
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCRLSign,
			},
		},
		{
			name: "missing CRL signing",
			certificate: &x509.Certificate{
				BasicConstraintsValid: true,
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCertSign,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateIssuingCAStructure(test.certificate); err == nil {
				t.Fatal("ValidateIssuingCAStructure() error = nil, want error")
			}
		})
	}
}
