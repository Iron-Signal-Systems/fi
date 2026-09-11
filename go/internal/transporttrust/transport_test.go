// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Test types.

type transportTestPKI struct {
	crl       *x509.RevocationList
	issuer    *x509.Certificate
	issuerKey *rsa.PrivateKey
	leaf      *x509.Certificate
	now       time.Time
	root      *x509.Certificate
	source    SourceAuthorization
}

// Tests.

func TestVerifyTransportCertificate(t *testing.T) {
	pki := newTransportTestPKI(t, true)

	outcome, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err != nil {
		t.Fatalf("VerifyTransportCertificate() error = %v", err)
	}

	if outcome != AuthorizationAuthorized {
		t.Fatalf(
			"VerifyTransportCertificate() = %q, want %q",
			outcome,
			AuthorizationAuthorized,
		)
	}
}

func TestVerifyTransportCertificateRejectsCRLSignedByWrongIssuer(t *testing.T) {
	pki := newTransportTestPKI(t, true)
	other := newTransportTestPKI(t, true)

	badCRL := createTestCRL(
		t,
		other.issuer,
		other.issuerKey,
		pki.now.Add(-time.Minute),
		pki.now.Add(time.Hour),
		nil,
	)

	_, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		pki.issuer,
		badCRL,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyTransportCertificate() error = nil, want CRL signature rejection",
		)
	}

	if !strings.Contains(err.Error(), "CRL") {
		t.Fatalf(
			"VerifyTransportCertificate() error = %q, want CRL rejection",
			err,
		)
	}
}

func TestVerifyTransportCertificateRejectsExpiredCRL(t *testing.T) {
	pki := newTransportTestPKI(t, true)

	expiredCRL := createTestCRL(
		t,
		pki.issuer,
		pki.issuerKey,
		pki.now.Add(-2*time.Hour),
		pki.now.Add(-time.Hour),
		nil,
	)

	_, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		pki.issuer,
		expiredCRL,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyTransportCertificate() error = nil, want expired-CRL rejection",
		)
	}

	if !strings.Contains(err.Error(), "transport CRL is expired") {
		t.Fatalf(
			"VerifyTransportCertificate() error = %q, want expired-CRL rejection",
			err,
		)
	}
}

func TestVerifyTransportCertificateRejectsFutureCRL(t *testing.T) {
	pki := newTransportTestPKI(t, true)

	futureCRL := createTestCRL(
		t,
		pki.issuer,
		pki.issuerKey,
		pki.now.Add(time.Hour),
		pki.now.Add(2*time.Hour),
		nil,
	)

	_, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		pki.issuer,
		futureCRL,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyTransportCertificate() error = nil, want future-CRL rejection",
		)
	}

	if !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf(
			"VerifyTransportCertificate() error = %q, want future-CRL rejection",
			err,
		)
	}
}

func TestVerifyTransportCertificateRejectsMissingClientAuth(t *testing.T) {
	pki := newTransportTestPKI(t, false)

	_, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyTransportCertificate() error = nil, want clientAuth rejection",
		)
	}

	if !strings.Contains(
		err.Error(),
		"chain or client-auth validation failed",
	) {
		t.Fatalf(
			"VerifyTransportCertificate() error = %q, want clientAuth rejection",
			err,
		)
	}
}

func TestVerifyTransportCertificateRejectsMissingDigitalSignature(t *testing.T) {
	pki := newTransportTestPKI(t, true)

	pki.leaf.KeyUsage = x509.KeyUsageKeyEncipherment

	_, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyTransportCertificate() error = nil, want digital-signature rejection",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not permit digital signatures",
	) {
		t.Fatalf(
			"VerifyTransportCertificate() error = %q, want digital-signature rejection",
			err,
		)
	}
}

func TestVerifyTransportCertificateRejectsRevokedCertificate(t *testing.T) {
	pki := newTransportTestPKI(t, true)

	revokedCRL := createTestCRL(
		t,
		pki.issuer,
		pki.issuerKey,
		pki.now.Add(-time.Minute),
		pki.now.Add(time.Hour),
		[]x509.RevocationListEntry{
			{
				SerialNumber:   pki.leaf.SerialNumber,
				RevocationTime: pki.now.Add(-30 * time.Second),
			},
		},
	)

	_, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		pki.issuer,
		revokedCRL,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyTransportCertificate() error = nil, want revocation rejection",
		)
	}

	if !strings.Contains(err.Error(), "is revoked") {
		t.Fatalf(
			"VerifyTransportCertificate() error = %q, want revocation rejection",
			err,
		)
	}
}

func TestVerifyTransportCertificateRejectsSourceMismatch(t *testing.T) {
	pki := newTransportTestPKI(t, true)

	pki.source.Transport.CommonName = "other-server.iss.local"

	outcome, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyTransportCertificate() error = nil, want source rejection",
		)
	}

	if outcome != AuthorizationIdentityMismatch {
		t.Fatalf(
			"VerifyTransportCertificate() = %q, want %q",
			outcome,
			AuthorizationIdentityMismatch,
		)
	}
}

func TestVerifyTransportCertificateRejectsWrongIssuer(t *testing.T) {
	pki := newTransportTestPKI(t, true)
	other := newTransportTestPKI(t, true)

	_, err := VerifyTransportCertificate(
		pki.leaf,
		nil,
		pki.root,
		other.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyTransportCertificate() error = nil, want issuer rejection",
		)
	}

	if !strings.Contains(err.Error(), "expected FI transport issuer") {
		t.Fatalf(
			"VerifyTransportCertificate() error = %q, want issuer rejection",
			err,
		)
	}
}

// Test helpers.

func certificateSHA256(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}

func createTestCRL(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *rsa.PrivateKey,
	thisUpdate time.Time,
	nextUpdate time.Time,
	revoked []x509.RevocationListEntry,
) *x509.RevocationList {
	t.Helper()

	template := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revoked,
	}

	der, err := x509.CreateRevocationList(
		rand.Reader,
		template,
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

func newTransportTestPKI(
	t *testing.T,
	clientAuth bool,
) transportTestPKI {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Second)

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "FI Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04},
	}

	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatalf("create root certificate: %v", err)
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "FI Test Transport Issuing CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x05, 0x06, 0x07, 0x08},
	}

	issuerDER, err := x509.CreateCertificate(
		rand.Reader,
		issuerTemplate,
		root,
		&issuerKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatalf("create issuer certificate: %v", err)
	}

	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer certificate: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	extendedKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
	}
	if !clientAuth {
		extendedKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		}
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName: "iss-fs-01.iss.local",
			OrganizationalUnit: []string{
				"FI Shipper Transport",
			},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: extendedKeyUsage,
	}

	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		issuer,
		&leafKey.PublicKey,
		issuerKey,
	)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	crl := createTestCRL(
		t,
		issuer,
		issuerKey,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		nil,
	)

	source := SourceAuthorization{
		Enabled:  true,
		SourceID: "iss-fs-01.iss.local",
		Transport: CertificateIdentity{
			CertificateSHA256:  certificateSHA256(leaf),
			CommonName:         "iss-fs-01.iss.local",
			IssuingCASHA256:    certificateSHA256(issuer),
			OrganizationalUnit: "FI Shipper Transport",
		},
	}

	return transportTestPKI{
		crl:       crl,
		issuer:    issuer,
		issuerKey: issuerKey,
		leaf:      leaf,
		now:       now,
		root:      root,
		source:    source,
	}
}
