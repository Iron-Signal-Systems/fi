// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"testing"
)

func TestValidateReceiverHostname(t *testing.T) {
	certificate := &x509.Certificate{
		DNSNames: []string{
			"fi-receiver-test",
			"fi-receiver-test.iss.local",
		},
	}

	tests := []struct {
		name     string
		hostname string
	}{
		{
			name:     "short hostname",
			hostname: "fi-receiver-test",
		},
		{
			name:     "FQDN",
			hostname: "fi-receiver-test.iss.local",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReceiverHostname(
				certificate,
				test.hostname,
			); err != nil {
				t.Fatalf(
					"ValidateReceiverHostname() error = %v",
					err,
				)
			}
		})
	}
}

func TestValidateReceiverHostnameFailures(t *testing.T) {
	certificate := &x509.Certificate{
		DNSNames: []string{"fi-receiver-test.iss.local"},
	}

	tests := []struct {
		name        string
		certificate *x509.Certificate
		hostname    string
	}{
		{
			name:        "nil certificate",
			certificate: nil,
			hostname:    "fi-receiver-test.iss.local",
		},
		{
			name:        "empty hostname",
			certificate: certificate,
			hostname:    "",
		},
		{
			name:        "whitespace hostname",
			certificate: certificate,
			hostname:    "   ",
		},
		{
			name:        "hostname mismatch",
			certificate: certificate,
			hostname:    "other-receiver.iss.local",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReceiverHostname(
				test.certificate,
				test.hostname,
			); err == nil {
				t.Fatal(
					"ValidateReceiverHostname() error = nil, want error",
				)
			}
		})
	}
}
