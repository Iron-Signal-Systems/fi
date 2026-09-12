// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestValidateRootCAValidityExpired(t *testing.T) {
	at := time.Date(2026, time.September, 11, 18, 0, 0, 0, time.UTC)
	certificate := &x509.Certificate{
		NotBefore: at.Add(-2 * time.Hour),
		NotAfter:  at.Add(-time.Hour),
	}

	err := ValidateRootCAValidity(certificate, at)
	if err == nil {
		t.Fatal("ValidateRootCAValidity() error = nil, want error")
	}

	want := "root CA expired at 2026-09-11T17:00:00Z"
	if err.Error() != want {
		t.Fatalf(
			"ValidateRootCAValidity() error = %q, want %q",
			err.Error(),
			want,
		)
	}
}

func TestValidateRootCAValidityNotAfterBoundary(t *testing.T) {
	at := time.Date(2026, time.September, 11, 18, 0, 0, 0, time.UTC)
	certificate := &x509.Certificate{
		NotBefore: at.Add(-time.Hour),
		NotAfter:  at,
	}

	if err := ValidateRootCAValidity(certificate, at); err != nil {
		t.Fatalf("ValidateRootCAValidity() error = %v", err)
	}
}

func TestValidateRootCAValidityNotBeforeBoundary(t *testing.T) {
	at := time.Date(2026, time.September, 11, 18, 0, 0, 0, time.UTC)
	certificate := &x509.Certificate{
		NotBefore: at,
		NotAfter:  at.Add(time.Hour),
	}

	if err := ValidateRootCAValidity(certificate, at); err != nil {
		t.Fatalf("ValidateRootCAValidity() error = %v", err)
	}
}

func TestValidateRootCAValidityNotYetValid(t *testing.T) {
	at := time.Date(2026, time.September, 11, 18, 0, 0, 0, time.UTC)
	certificate := &x509.Certificate{
		NotBefore: at.Add(time.Hour),
		NotAfter:  at.Add(2 * time.Hour),
	}

	err := ValidateRootCAValidity(certificate, at)
	if err == nil {
		t.Fatal("ValidateRootCAValidity() error = nil, want error")
	}

	want := "root CA is not valid before 2026-09-11T19:00:00Z"
	if err.Error() != want {
		t.Fatalf(
			"ValidateRootCAValidity() error = %q, want %q",
			err.Error(),
			want,
		)
	}
}

func TestValidateRootCAValidityNullCertificate(t *testing.T) {
	at := time.Date(2026, time.September, 11, 18, 0, 0, 0, time.UTC)

	err := ValidateRootCAValidity(nil, at)
	if err == nil {
		t.Fatal("ValidateRootCAValidity() error = nil, want error")
	}

	want := "root CA certificate is required"
	if err.Error() != want {
		t.Fatalf(
			"ValidateRootCAValidity() error = %q, want %q",
			err.Error(),
			want,
		)
	}
}

func TestValidateRootCAValidityValid(t *testing.T) {
	at := time.Date(2026, time.September, 11, 18, 0, 0, 0, time.UTC)
	certificate := &x509.Certificate{
		NotBefore: at.Add(-time.Hour),
		NotAfter:  at.Add(time.Hour),
	}

	if err := ValidateRootCAValidity(certificate, at); err != nil {
		t.Fatalf("ValidateRootCAValidity() error = %v", err)
	}
}
