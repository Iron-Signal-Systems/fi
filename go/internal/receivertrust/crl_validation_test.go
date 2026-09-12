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

func TestValidateCRL(t *testing.T) {
	issuer, _, crl := newCRLValidationMaterial(t, "FI CRL Test CA")

	if err := ValidateCRL(crl, issuer, time.Now()); err != nil {
		t.Fatalf("ValidateCRL() error = %v", err)
	}
}

func TestValidateCRLFailures(t *testing.T) {
	at := time.Now()

	issuer, _, crl := newCRLValidationMaterial(t, "FI CRL Test CA")
	otherIssuer, _, _ := newCRLValidationMaterial(t, "Other FI CRL Test CA")
	sameNameOtherKeyIssuer, _, _ := newCRLValidationMaterial(
		t,
		"FI CRL Test CA",
	)

	tests := []struct {
		name   string
		crl    *x509.RevocationList
		issuer *x509.Certificate
		at     time.Time
	}{
		{
			name:   "nil CRL",
			crl:    nil,
			issuer: issuer,
			at:     at,
		},
		{
			name:   "nil issuer",
			crl:    crl,
			issuer: nil,
			at:     at,
		},
		{
			name:   "zero current time",
			crl:    crl,
			issuer: issuer,
			at:     time.Time{},
		},
		{
			name:   "issuer mismatch",
			crl:    crl,
			issuer: otherIssuer,
			at:     at,
		},
		{
			name:   "signature mismatch",
			crl:    crl,
			issuer: sameNameOtherKeyIssuer,
			at:     at,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateCRL(test.crl, test.issuer, test.at); err == nil {
				t.Fatal("ValidateCRL() error = nil, want error")
			}
		})
	}
}

func TestValidateCRLFreshness(t *testing.T) {
	issuer, key, validCRL := newCRLValidationMaterial(
		t,
		"FI CRL Freshness CA",
	)
	at := time.Now()

	t.Run("current", func(t *testing.T) {
		crl := newCRLValidationList(
			t,
			issuer,
			key,
			at.Add(-time.Minute),
			at.Add(time.Hour),
		)

		if err := ValidateCRL(crl, issuer, at); err != nil {
			t.Fatalf("ValidateCRL() error = %v", err)
		}
	})

	t.Run("this update boundary", func(t *testing.T) {
		crl := newCRLValidationList(
			t,
			issuer,
			key,
			at,
			at.Add(time.Hour),
		)

		if err := ValidateCRL(crl, issuer, at); err != nil {
			t.Fatalf("ValidateCRL() error = %v", err)
		}
	})

	t.Run("future this update", func(t *testing.T) {
		crl := newCRLValidationList(
			t,
			issuer,
			key,
			at.Add(time.Second),
			at.Add(time.Hour),
		)

		if err := ValidateCRL(crl, issuer, at); err == nil {
			t.Fatal("ValidateCRL() error = nil, want error")
		}
	})

	t.Run("missing next update", func(t *testing.T) {
		crl := *validCRL
		crl.NextUpdate = time.Time{}

		if err := ValidateCRL(&crl, issuer, at); err == nil {
			t.Fatal("ValidateCRL() error = nil, want error")
		}
	})

	t.Run("next update boundary expired", func(t *testing.T) {
		crl := newCRLValidationList(
			t,
			issuer,
			key,
			at.Add(-time.Hour),
			at,
		)

		if err := ValidateCRL(crl, issuer, at); err == nil {
			t.Fatal("ValidateCRL() error = nil, want error")
		}
	})

	t.Run("expired", func(t *testing.T) {
		crl := newCRLValidationList(
			t,
			issuer,
			key,
			at.Add(-time.Hour),
			at.Add(-time.Second),
		)

		if err := ValidateCRL(crl, issuer, at); err == nil {
			t.Fatal("ValidateCRL() error = nil, want error")
		}
	})
}

func newCRLValidationMaterial(
	t *testing.T,
	commonName string,
) (*x509.Certificate, *rsa.PrivateKey, *x509.RevocationList) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	crl := newCRLValidationList(
		t,
		issuer,
		key,
		now.Add(-time.Minute),
		now.Add(time.Hour),
	)

	return issuer, key, crl
}

func newCRLValidationList(
	t *testing.T,
	issuer *x509.Certificate,
	key *rsa.PrivateKey,
	thisUpdate time.Time,
	nextUpdate time.Time,
) *x509.RevocationList {
	t.Helper()

	der, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: thisUpdate,
			NextUpdate: nextUpdate,
		},
		issuer,
		key,
	)
	if err != nil {
		t.Fatalf("x509.CreateRevocationList() error = %v", err)
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("x509.ParseRevocationList() error = %v", err)
	}

	return crl
}
