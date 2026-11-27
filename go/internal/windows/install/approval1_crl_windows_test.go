// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestParseApproval1LDAPCRLDistributionPoint(
	t *testing.T,
) {
	t.Parallel()

	const raw = "ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint"

	source, err :=
		parseApproval1LDAPCRLDistributionPoint(
			raw,
		)
	if err != nil {
		t.Fatal(err)
	}

	const wantBase = "CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=iss,DC=local"

	if source.BaseDN != wantBase {
		t.Fatalf(
			"base DN=%q want=%q",
			source.BaseDN,
			wantBase,
		)
	}

	if source.Attribute !=
		"certificateRevocationList" {
		t.Fatalf(
			"attribute=%q",
			source.Attribute,
		)
	}

	if source.Filter !=
		"(objectClass=cRLDistributionPoint)" {
		t.Fatalf(
			"filter=%q",
			source.Filter,
		)
	}
}

func TestValidateApproval1TransportCRL(
	t *testing.T,
) {
	t.Parallel()

	issuerKey, err :=
		rsa.GenerateKey(
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

	issuerTemplate :=
		&x509.Certificate{
			SerialNumber: big.NewInt(
				1,
			),
			Subject: pkix.Name{
				CommonName: "Test FI CA",
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

	issuerDER, err :=
		x509.CreateCertificate(
			rand.Reader,
			issuerTemplate,
			issuerTemplate,
			&issuerKey.PublicKey,
			issuerKey,
		)
	if err != nil {
		t.Fatal(err)
	}

	issuer, err :=
		x509.ParseCertificate(
			issuerDER,
		)
	if err != nil {
		t.Fatal(err)
	}

	leaf :=
		&x509.Certificate{
			SerialNumber: big.NewInt(
				100,
			),
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
			issuer,
			issuerKey,
		)
	if err != nil {
		t.Fatal(err)
	}

	if _, err :=
		validateApproval1TransportCRL(
			crlDER,
			issuer,
			leaf,
			now,
		); err != nil {
		t.Fatal(err)
	}
}

func TestValidateApproval1TransportCRLRejectsRevokedLeaf(
	t *testing.T,
) {
	t.Parallel()

	issuerKey, err :=
		rsa.GenerateKey(
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

	issuerTemplate :=
		&x509.Certificate{
			SerialNumber: big.NewInt(
				2,
			),
			Subject: pkix.Name{
				CommonName: "Test FI CA",
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
				5,
				6,
				7,
				8,
			},
		}

	issuerDER, err :=
		x509.CreateCertificate(
			rand.Reader,
			issuerTemplate,
			issuerTemplate,
			&issuerKey.PublicKey,
			issuerKey,
		)
	if err != nil {
		t.Fatal(err)
	}

	issuer, err :=
		x509.ParseCertificate(
			issuerDER,
		)
	if err != nil {
		t.Fatal(err)
	}

	leaf :=
		&x509.Certificate{
			SerialNumber: big.NewInt(
				200,
			),
		}

	crlDER, err :=
		x509.CreateRevocationList(
			rand.Reader,
			&x509.RevocationList{
				Number: big.NewInt(
					2,
				),
				ThisUpdate: now.Add(
					-time.Minute,
				),
				NextUpdate: now.Add(
					time.Hour,
				),
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{
						SerialNumber: new(
							big.Int,
						).Set(
							leaf.SerialNumber,
						),
						RevocationTime: now.Add(
							-30 *
								time.Second,
						),
					},
				},
			},
			issuer,
			issuerKey,
		)
	if err != nil {
		t.Fatal(err)
	}

	if _, err :=
		validateApproval1TransportCRL(
			crlDER,
			issuer,
			leaf,
			now,
		); err == nil {
		t.Fatal(
			"revoked transport certificate was unexpectedly accepted",
		)
	}
}
