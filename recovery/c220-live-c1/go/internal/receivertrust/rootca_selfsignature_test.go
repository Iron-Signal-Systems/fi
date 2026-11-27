// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestValidateRootCASelfSignatureInvalid(t *testing.T) {
	certificate := newRootCASelfSignatureTestCertificate(t, true, false)

	err := ValidateRootCASelfSignature(certificate)
	if err == nil {
		t.Fatal("ValidateRootCASelfSignature() error = nil, want error")
	}

	if !strings.Contains(
		err.Error(),
		"root CA self-signature is invalid",
	) {
		t.Fatalf(
			"ValidateRootCASelfSignature() error = %q, want self-signature error",
			err.Error(),
		)
	}
}

func TestValidateRootCASelfSignatureIssuerMismatch(t *testing.T) {
	certificate := newRootCASelfSignatureTestCertificate(t, false, true)

	err := ValidateRootCASelfSignature(certificate)
	if err == nil {
		t.Fatal("ValidateRootCASelfSignature() error = nil, want error")
	}

	if err.Error() != "root CA issuer does not match subject" {
		t.Fatalf(
			"ValidateRootCASelfSignature() error = %q, want %q",
			err.Error(),
			"root CA issuer does not match subject",
		)
	}
}

func TestValidateRootCASelfSignatureNil(t *testing.T) {
	err := ValidateRootCASelfSignature(nil)
	if err == nil {
		t.Fatal("ValidateRootCASelfSignature() error = nil, want error")
	}

	if err.Error() != "root CA certificate is required" {
		t.Fatalf(
			"ValidateRootCASelfSignature() error = %q, want %q",
			err.Error(),
			"root CA certificate is required",
		)
	}
}

func TestValidateRootCASelfSignatureValid(t *testing.T) {
	certificate := newRootCASelfSignatureTestCertificate(t, true, true)

	if err := ValidateRootCASelfSignature(certificate); err != nil {
		t.Fatalf(
			"ValidateRootCASelfSignature() error = %v",
			err,
		)
	}
}

func newRootCASelfSignatureTestCertificate(
	t *testing.T,
	selfIssued bool,
	selfSigned bool,
) *x509.Certificate {
	t.Helper()

	publicKeyOwner, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(publicKeyOwner) error = %v", err)
	}

	signer := publicKeyOwner
	if !selfSigned {
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey(signer) error = %v", err)
		}
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "FI Root CA Self-Signature Test",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	parent := *template
	if !selfIssued {
		parent.Subject = pkix.Name{
			CommonName: "Different Issuer",
		}
	}

	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		&parent,
		&publicKeyOwner.PublicKey,
		signer,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	return certificate
}
