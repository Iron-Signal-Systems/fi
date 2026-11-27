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
	"testing"
	"time"
)

func TestValidateIssuingCAIssuer(t *testing.T) {
	root, issuer := newIssuingCARelationshipCertificates(t)

	if err := ValidateIssuingCAIssuer(issuer, root); err != nil {
		t.Fatalf("ValidateIssuingCAIssuer() error = %v", err)
	}
}

func TestValidateIssuingCAIssuerFailures(t *testing.T) {
	root, issuer := newIssuingCARelationshipCertificates(t)

	t.Run("nil certificate", func(t *testing.T) {
		if err := ValidateIssuingCAIssuer(nil, root); err == nil {
			t.Fatal("ValidateIssuingCAIssuer() error = nil, want error")
		}
	})

	t.Run("nil root", func(t *testing.T) {
		if err := ValidateIssuingCAIssuer(issuer, nil); err == nil {
			t.Fatal("ValidateIssuingCAIssuer() error = nil, want error")
		}
	})

	t.Run("issuer mismatch", func(t *testing.T) {
		otherRoot, _ := newIssuingCARelationshipCertificatesWithName(
			t,
			"Other FI Root CA",
		)

		if err := ValidateIssuingCAIssuer(issuer, otherRoot); err == nil {
			t.Fatal("ValidateIssuingCAIssuer() error = nil, want error")
		}
	})

	t.Run("signature mismatch", func(t *testing.T) {
		otherRoot, _ := newIssuingCARelationshipCertificatesWithName(
			t,
			"FI Relationship Test Root",
		)

		if err := ValidateIssuingCAIssuer(issuer, otherRoot); err == nil {
			t.Fatal("ValidateIssuingCAIssuer() error = nil, want error")
		}
	})
}

func newIssuingCARelationshipCertificates(
	t *testing.T,
) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	return newIssuingCARelationshipCertificatesWithName(
		t,
		"FI Relationship Test Root",
	)
}

func newIssuingCARelationshipCertificatesWithName(
	t *testing.T,
	rootName string,
) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(root) error = %v", err)
	}

	now := time.Now()

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: rootName,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(root) error = %v", err)
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(root) error = %v", err)
	}

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(issuer) error = %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "FI Relationship Test Issuing CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerDER, err := x509.CreateCertificate(
		rand.Reader,
		issuerTemplate,
		root,
		&issuerKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(issuer) error = %v", err)
	}

	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(issuer) error = %v", err)
	}

	return root, issuer
}
