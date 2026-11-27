// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportcrl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseLDAPDistributionPoint(
	t *testing.T,
) {
	t.Parallel()

	const raw = "ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint"

	source, err := ParseLDAPDistributionPoint(
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

func TestSelectDistributionPointDeduplicatesIdenticalSource(
	t *testing.T,
) {
	t.Parallel()

	const want = "https://ca.iss.local/CertEnroll/FI-Transport-CA.crl"

	got, err := SelectDistributionPoint(
		[]string{
			want,
			want,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Fatalf(
			"distribution point=%q want=%q",
			got,
			want,
		)
	}
}

func TestSelectDistributionPointRejectsAmbiguousSources(
	t *testing.T,
) {
	t.Parallel()

	_, err := SelectDistributionPoint(
		[]string{
			"http://ca1.iss.local/one.crl",
			"https://ca2.iss.local/two.crl",
		},
	)

	if err == nil {
		t.Fatal(
			"ambiguous CRL sources were unexpectedly accepted",
		)
	}
}

func TestSupportedDistributionPointRejectsLDAPWithoutCRLAttribute(
	t *testing.T,
) {
	t.Parallel()

	if SupportedDistributionPoint(
		"ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?cACertificate?base?objectClass=certificationAuthority",
	) {
		t.Fatal(
			"LDAP AIA URL was incorrectly accepted",
		)
	}
}

func TestValidateDER(
	t *testing.T,
) {
	t.Parallel()

	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	leaf := &x509.Certificate{
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
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ValidateDER(
		crlDER,
		issuer,
		leaf,
		now,
	); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDERRejectsExpiredCRL(
	t *testing.T,
) {
	t.Parallel()

	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			101,
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
					-2 * time.Hour,
				),
				NextUpdate: now.Add(
					-time.Hour,
				),
			},
			issuer,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ValidateDER(
		crlDER,
		issuer,
		leaf,
		now,
	)

	if err == nil {
		t.Fatal(
			"expired CRL was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"expired",
	) {
		t.Fatalf(
			"error=%q want expiry failure",
			err,
		)
	}
}

func TestValidateDERRejectsSignedDeltaCRL(
	t *testing.T,
) {
	t.Parallel()

	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			150,
		),
	}

	baseCRLNumberDER, err := asn1.Marshal(
		big.NewInt(
			40,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	crlDER, err :=
		x509.CreateRevocationList(
			rand.Reader,
			&x509.RevocationList{
				Number: big.NewInt(
					41,
				),
				ThisUpdate: now.Add(
					-time.Minute,
				),
				NextUpdate: now.Add(
					time.Hour,
				),
				ExtraExtensions: []pkix.Extension{
					{
						Id: asn1.ObjectIdentifier{
							2,
							5,
							29,
							27,
						},
						Value: baseCRLNumberDER,
					},
				},
			},
			issuer,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err :=
		x509.ParseRevocationList(
			crlDER,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err := parsed.CheckSignatureFrom(
		issuer,
	); err != nil {
		t.Fatalf(
			"signed delta fixture signature verification failed: %v",
			err,
		)
	}

	foundDeltaIndicator := false

	for _, extension := range parsed.Extensions {
		if extension.Id.Equal(
			asn1.ObjectIdentifier{
				2,
				5,
				29,
				27,
			},
		) {
			foundDeltaIndicator = true
			break
		}
	}

	if !foundDeltaIndicator {
		t.Fatal(
			"signed delta fixture does not contain delta CRL indicator",
		)
	}

	_, err = ValidateDER(
		crlDER,
		issuer,
		leaf,
		now,
	)

	if err == nil {
		t.Fatal(
			"signed delta CRL was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not support delta CRLs",
	) {
		t.Fatalf(
			"error=%q want delta-CRL rejection",
			err,
		)
	}
}
func TestValidateDERRejectsRevokedLeaf(
	t *testing.T,
) {
	t.Parallel()

	now := time.Now().
		UTC().
		Truncate(
			time.Second,
		)

	issuer, key :=
		newTransportCRLTestIssuer(
			t,
			now,
		)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(
			200,
		),
	}

	crlDER, err :=
		x509.CreateRevocationList(
			rand.Reader,
			&x509.RevocationList{
				Number: big.NewInt(
					3,
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
							-30 * time.Second,
						),
					},
				},
			},
			issuer,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ValidateDER(
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

func newTransportCRLTestIssuer(
	t *testing.T,
	now time.Time,
) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

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
			CommonName: "FI Transport CRL Test CA",
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

	der, err := x509.CreateCertificate(
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
			der,
		)
	if err != nil {
		t.Fatal(err)
	}

	return certificate, key
}
