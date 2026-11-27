// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

func TestRenderApproval2TransportTrustConfigRoundTrip(
	t *testing.T,
) {
	t.Parallel()

	root := t.TempDir()

	value := config.TransportTrustConfig{
		VersionID: config.TransportTrustVersion1,

		BatchSigningCertificateSHA256: strings.Repeat(
			"b",
			64,
		),

		RootCertificateSHA256: strings.Repeat(
			"d",
			64,
		),

		TransportCertificateSHA256: strings.Repeat(
			"a",
			64,
		),

		TransportCRLPath: filepath.Join(
			root,
			"fi-transport-ca.crl.pem",
		),

		TransportIssuerSHA256: strings.Repeat(
			"d",
			64,
		),
	}

	encoded, err :=
		renderApproval2TransportTrustConfig(
			value,
		)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err :=
		config.ParseTransportTrust(
			strings.NewReader(
				string(encoded),
			),
		)
	if err != nil {
		t.Fatal(err)
	}

	if !sameApproval2TransportTrustConfig(
		parsed,
		value,
	) {
		t.Fatalf(
			"transport-trust round trip differs: parsed=%+v want=%+v",
			parsed,
			value,
		)
	}
}

func TestVerifyApproval2DerivedTrustContractAllowsDirectRoot(
	t *testing.T,
) {
	t.Parallel()

	handoff := approval1CompleteTestHandoff()

	derived := approval1TransportTrustMaterial{
		CRLDestinationPath: handoff.CRLDestinationPath,

		CRLDistributionPoint: handoff.CRLDistributionPoint,

		IssuerCertificateSHA256: handoff.TransportIssuerSHA256,

		RootCertificateSHA256: handoff.RootCertificateSHA256,

		TransportCertificateSHA256: handoff.TransportCertificateSHA256,
	}

	if err := verifyApproval2DerivedTrustContract(
		handoff,
		derived,
	); err != nil {
		t.Fatal(err)
	}

	if handoff.TransportIssuerSHA256 !=
		handoff.RootCertificateSHA256 {
		t.Fatal(
			"test fixture is not direct-root",
		)
	}
}

func TestVerifyApproval2ReacquiredCRLContractRejectsHashDrift(
	t *testing.T,
) {
	t.Parallel()

	handoff := approval1CompleteTestHandoff()

	crl := approval1CRLMaterial{
		DER: []byte(
			"different CRL",
		),

		DestinationPath: handoff.CRLDestinationPath,

		NextUpdate: handoff.CRLNextUpdate,

		SHA256: handoff.CRLSHA256,

		Source: handoff.CRLDistributionPoint,

		ThisUpdate: handoff.CRLThisUpdate,
	}

	if err := verifyApproval2ReacquiredCRLContract(
		handoff,
		crl,
	); err == nil {
		t.Fatal(
			"CRL DER drift was unexpectedly accepted",
		)
	}
}

func TestCreateApproval2TransportTrustFiles(
	t *testing.T,
) {
	t.Parallel()

	root := t.TempDir()

	configDirectory := filepath.Join(
		root,
		"config",
	)
	crlDirectory := filepath.Join(
		root,
		"pki",
		"trust",
	)

	if err := os.MkdirAll(
		configDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(
		crlDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	crlDER := createApproval2TestCRL(
		t,
	)

	digest := sha256.Sum256(
		crlDER,
	)
	crlSHA256 := hex.EncodeToString(
		digest[:],
	)

	crlPath := filepath.Join(
		crlDirectory,
		"fi-transport-ca.crl.pem",
	)

	trustPath := filepath.Join(
		configDirectory,
		"fi-transport-trust.conf",
	)

	value := config.TransportTrustConfig{
		VersionID: config.TransportTrustVersion1,

		BatchSigningCertificateSHA256: strings.Repeat(
			"b",
			64,
		),

		RootCertificateSHA256: strings.Repeat(
			"d",
			64,
		),

		TransportCertificateSHA256: strings.Repeat(
			"a",
			64,
		),

		TransportCRLPath: crlPath,

		TransportIssuerSHA256: strings.Repeat(
			"d",
			64,
		),
	}

	configBytes, err :=
		renderApproval2TransportTrustConfig(
			value,
		)
	if err != nil {
		t.Fatal(err)
	}

	rollback, err :=
		createApproval2TransportTrustFiles(
			trustPath,
			crlPath,
			configBytes,
			crlDER,
			crlSHA256,
			"unit-test",
		)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := config.LoadTransportTrust(
		trustPath,
	); err != nil {
		t.Fatalf(
			"activated transport-trust config is invalid: %v",
			err,
		)
	}

	if err := verifyApproval2PersistedCRL(
		crlPath,
		crlDER,
		crlSHA256,
	); err != nil {
		t.Fatal(err)
	}

	if err := rollback(); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		trustPath,
		crlPath,
	} {
		if _, err := os.Lstat(
			path,
		); !errors.Is(
			err,
			os.ErrNotExist,
		) {
			t.Fatalf(
				"rollback left %s present: %v",
				path,
				err,
			)
		}
	}
}

func TestCreateApproval2TransportTrustFilesRefusesExistingDestination(
	t *testing.T,
) {
	t.Parallel()

	root := t.TempDir()

	configDirectory := filepath.Join(
		root,
		"config",
	)
	crlDirectory := filepath.Join(
		root,
		"pki",
		"trust",
	)

	if err := os.MkdirAll(
		configDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(
		crlDirectory,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	trustPath := filepath.Join(
		configDirectory,
		"fi-transport-trust.conf",
	)

	crlPath := filepath.Join(
		crlDirectory,
		"fi-transport-ca.crl.pem",
	)

	if err := os.WriteFile(
		trustPath,
		[]byte("preexisting"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	crlDER := createApproval2TestCRL(
		t,
	)

	digest := sha256.Sum256(
		crlDER,
	)

	_, err :=
		createApproval2TransportTrustFiles(
			trustPath,
			crlPath,
			[]byte("unused"),
			crlDER,
			hex.EncodeToString(
				digest[:],
			),
			"unit-test",
		)

	if err == nil {
		t.Fatal(
			"existing Approval 2 destination was unexpectedly overwritten",
		)
	}

	if _, err := os.Lstat(
		crlPath,
	); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"CRL was created despite preexisting trust destination: %v",
			err,
		)
	}
}

func createApproval2TestCRL(
	t *testing.T,
) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(
			1,
		),

		Subject: pkix.Name{
			CommonName: "FI Approval 2 Test CA",
		},

		NotBefore: now.Add(
			-time.Hour,
		),

		NotAfter: now.Add(
			24 * time.Hour,
		),

		IsCA: true,

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

	certificate, err :=
		x509.ParseCertificate(
			certificateDER,
		)
	if err != nil {
		t.Fatal(err)
	}

	crlDER, err :=
		x509.CreateRevocationList(
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
			certificate,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	return crlDER
}
