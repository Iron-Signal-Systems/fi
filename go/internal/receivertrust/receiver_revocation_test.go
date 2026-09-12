// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestValidateReceiverCertificateNotRevoked(t *testing.T) {
	_, issuer, leaf, issuerKey, _ := newReceiverIdentityMaterial(t)
	crl := newReceiverRevocationTestCRL(
		t,
		issuer,
		issuerKey,
		nil,
	)

	if err := ValidateReceiverCertificateNotRevoked(
		leaf,
		crl,
	); err != nil {
		t.Fatalf(
			"ValidateReceiverCertificateNotRevoked() error = %v",
			err,
		)
	}
}

func TestValidateReceiverCertificateNotRevokedFailures(t *testing.T) {
	_, issuer, leaf, issuerKey, _ := newReceiverIdentityMaterial(t)

	t.Run("nil certificate", func(t *testing.T) {
		crl := newReceiverRevocationTestCRL(
			t,
			issuer,
			issuerKey,
			nil,
		)

		if err := ValidateReceiverCertificateNotRevoked(
			nil,
			crl,
		); err == nil {
			t.Fatal(
				"ValidateReceiverCertificateNotRevoked() error = nil, want error",
			)
		}
	})

	t.Run("missing serial number", func(t *testing.T) {
		certificate := *leaf
		certificate.SerialNumber = nil

		crl := newReceiverRevocationTestCRL(
			t,
			issuer,
			issuerKey,
			nil,
		)

		if err := ValidateReceiverCertificateNotRevoked(
			&certificate,
			crl,
		); err == nil {
			t.Fatal(
				"ValidateReceiverCertificateNotRevoked() error = nil, want error",
			)
		}
	})

	t.Run("nil CRL", func(t *testing.T) {
		if err := ValidateReceiverCertificateNotRevoked(
			leaf,
			nil,
		); err == nil {
			t.Fatal(
				"ValidateReceiverCertificateNotRevoked() error = nil, want error",
			)
		}
	})

	t.Run("current revocation entries", func(t *testing.T) {
		crl := newReceiverRevocationTestCRL(
			t,
			issuer,
			issuerKey,
			[]x509.RevocationListEntry{
				{
					SerialNumber:   leaf.SerialNumber,
					RevocationTime: time.Now().Add(-time.Minute),
				},
			},
		)

		if err := ValidateReceiverCertificateNotRevoked(
			leaf,
			crl,
		); err == nil {
			t.Fatal(
				"ValidateReceiverCertificateNotRevoked() error = nil, want revoked error",
			)
		}
	})

	t.Run("legacy revoked certificates", func(t *testing.T) {
		crl := newReceiverRevocationTestCRL(
			t,
			issuer,
			issuerKey,
			nil,
		)

		legacy := *crl
		legacy.RevokedCertificateEntries = nil
		legacy.RevokedCertificates = []pkix.RevokedCertificate{
			{
				SerialNumber: leaf.SerialNumber,
			},
		}

		if err := ValidateReceiverCertificateNotRevoked(
			leaf,
			&legacy,
		); err == nil {
			t.Fatal(
				"ValidateReceiverCertificateNotRevoked() error = nil, want revoked error",
			)
		}
	})
}

func newReceiverRevocationTestCRL(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey crypto.Signer,
	entries []x509.RevocationListEntry,
) *x509.RevocationList {
	t.Helper()

	now := time.Now()

	der, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:                    big.NewInt(1),
			ThisUpdate:                now.Add(-time.Minute),
			NextUpdate:                now.Add(time.Hour),
			RevokedCertificateEntries: entries,
		},
		issuer,
		issuerKey,
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
