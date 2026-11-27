// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"testing"
)

func TestValidateRootCABasicConstraintsInvalid(t *testing.T) {
	certificate := newValidRootCATestCertificate()
	certificate.BasicConstraintsValid = false

	err := ValidateRootCA(certificate)
	if err == nil {
		t.Fatal("ValidateRootCA() error = nil, want error")
	}

	if err.Error() != "root CA basic constraints are not valid" {
		t.Fatalf(
			"ValidateRootCA() error = %q, want %q",
			err.Error(),
			"root CA basic constraints are not valid",
		)
	}
}

func TestValidateRootCACertificateSigningMissing(t *testing.T) {
	certificate := newValidRootCATestCertificate()
	certificate.KeyUsage = x509.KeyUsageCRLSign

	err := ValidateRootCA(certificate)
	if err == nil {
		t.Fatal("ValidateRootCA() error = nil, want error")
	}

	if err.Error() != "root CA key usage does not include certificate signing" {
		t.Fatalf(
			"ValidateRootCA() error = %q, want %q",
			err.Error(),
			"root CA key usage does not include certificate signing",
		)
	}
}

func TestValidateRootCACRLSigningMissing(t *testing.T) {
	certificate := newValidRootCATestCertificate()
	certificate.KeyUsage = x509.KeyUsageCertSign

	err := ValidateRootCA(certificate)
	if err == nil {
		t.Fatal("ValidateRootCA() error = nil, want error")
	}

	if err.Error() != "root CA key usage does not include CRL signing" {
		t.Fatalf(
			"ValidateRootCA() error = %q, want %q",
			err.Error(),
			"root CA key usage does not include CRL signing",
		)
	}
}

func TestValidateRootCANil(t *testing.T) {
	err := ValidateRootCA(nil)
	if err == nil {
		t.Fatal("ValidateRootCA() error = nil, want error")
	}

	if err.Error() != "root CA certificate is required" {
		t.Fatalf(
			"ValidateRootCA() error = %q, want %q",
			err.Error(),
			"root CA certificate is required",
		)
	}
}

func TestValidateRootCANotCA(t *testing.T) {
	certificate := newValidRootCATestCertificate()
	certificate.IsCA = false

	err := ValidateRootCA(certificate)
	if err == nil {
		t.Fatal("ValidateRootCA() error = nil, want error")
	}

	if err.Error() != "root CA certificate is not a CA" {
		t.Fatalf(
			"ValidateRootCA() error = %q, want %q",
			err.Error(),
			"root CA certificate is not a CA",
		)
	}
}

func TestValidateRootCAValid(t *testing.T) {
	if err := ValidateRootCA(newValidRootCATestCertificate()); err != nil {
		t.Fatalf("ValidateRootCA() error = %v", err)
	}
}

func newValidRootCATestCertificate() *x509.Certificate {
	return &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}
