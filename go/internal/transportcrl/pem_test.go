// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportcrl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncodeCanonicalPEMRoundTripsExactDER(
	t *testing.T,
) {
	der := []byte{
		1,
		2,
		3,
		4,
		5,
	}

	encoded, err := EncodeCanonicalPEM(
		der,
	)
	if err != nil {
		t.Fatal(err)
	}

	block, remainder := pem.Decode(
		encoded,
	)

	if block == nil {
		t.Fatal(
			"canonical PEM did not decode",
		)
	}

	if block.Type != "X509 CRL" {
		t.Fatalf(
			"PEM type=%q want X509 CRL",
			block.Type,
		)
	}

	if len(remainder) != 0 {
		t.Fatalf(
			"canonical PEM contains %d trailing bytes",
			len(remainder),
		)
	}

	if string(block.Bytes) != string(der) {
		t.Fatal(
			"canonical PEM did not reproduce exact DER",
		)
	}
}

func TestEncodeCanonicalPEMRejectsEmptyDER(
	t *testing.T,
) {
	if _, err := EncodeCanonicalPEM(
		nil,
	); err == nil {
		t.Fatal(
			"empty CRL DER was unexpectedly accepted",
		)
	}
}

func TestVerifyPersistedPEM(
	t *testing.T,
) {
	der := createPersistedPEMTestCRL(
		t,
	)

	encoded, err := EncodeCanonicalPEM(
		der,
	)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(
		t.TempDir(),
		"transport.crl.pem",
	)

	if err := os.WriteFile(
		path,
		encoded,
		0600,
	); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(
		der,
	)

	if err := VerifyPersistedPEM(
		path,
		der,
		hex.EncodeToString(
			digest[:],
		),
	); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPersistedPEMRejectsDifferentDER(
	t *testing.T,
) {
	der := createPersistedPEMTestCRL(
		t,
	)

	encoded, err := EncodeCanonicalPEM(
		der,
	)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(
		t.TempDir(),
		"transport.crl.pem",
	)

	if err := os.WriteFile(
		path,
		encoded,
		0600,
	); err != nil {
		t.Fatal(err)
	}

	expected := append(
		[]byte(nil),
		der...,
	)

	expected[0] ^= 0xff

	digest := sha256.Sum256(
		expected,
	)

	if err := VerifyPersistedPEM(
		path,
		expected,
		hex.EncodeToString(
			digest[:],
		),
	); err == nil {
		t.Fatal(
			"persisted CRL with different DER was unexpectedly accepted",
		)
	}
}

func createPersistedPEMTestCRL(
	t *testing.T,
) []byte {
	t.Helper()

	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	key, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(
			1,
		),
		Subject: pkix.Name{
			CommonName: "FI Persisted CRL Test CA",
		},
		NotBefore: now.Add(
			-time.Hour,
		),
		NotAfter: now.Add(
			24 * time.Hour,
		),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{
			1,
			2,
			3,
			4,
		},
	}

	certificateDER, err :=
		x509.CreateCertificate(
			rand.Reader,
			template,
			template,
			&key.PublicKey,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	issuer, err :=
		x509.ParseCertificate(
			certificateDER,
		)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number: big.NewInt(
				1,
			),
			ThisUpdate: now.Add(
				-time.Minute,
			),
			NextUpdate: now.Add(
				time.Hour,
			),
		},
		issuer,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	return der
}
