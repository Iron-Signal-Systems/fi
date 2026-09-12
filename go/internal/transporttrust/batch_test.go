// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto"
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

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
)

// Test types.

type batchSigningTestPKI struct {
	crl       *x509.RevocationList
	issuer    *x509.Certificate
	issuerKey *rsa.PrivateKey
	leaf      *x509.Certificate
	leafKey   *rsa.PrivateKey
	now       time.Time
	root      *x509.Certificate
	source    SourceAuthorization
}

// Tests.

func TestVerifyBatchSigningCertificate(t *testing.T) {
	pki := newBatchSigningTestPKI(t)

	outcome, err := VerifyBatchSigningCertificate(
		pki.leaf,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err != nil {
		t.Fatalf("VerifyBatchSigningCertificate() error = %v", err)
	}

	if outcome != AuthorizationAuthorized {
		t.Fatalf(
			"VerifyBatchSigningCertificate() = %q, want %q",
			outcome,
			AuthorizationAuthorized,
		)
	}
}

func TestVerifyBatchSigningCertificateRejectsCA(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	candidate := *pki.leaf
	candidate.IsCA = true

	_, err := VerifyBatchSigningCertificate(
		&candidate,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyBatchSigningCertificate() error = nil, want CA rejection",
		)
	}

	if !strings.Contains(err.Error(), "must not be a CA") {
		t.Fatalf(
			"VerifyBatchSigningCertificate() error = %q, want CA rejection",
			err,
		)
	}
}

func TestVerifyBatchSigningCertificateRejectsExpiredCRL(t *testing.T) {
	pki := newBatchSigningTestPKI(t)

	expiredCRL := createBatchSigningTestCRL(
		t,
		pki.issuer,
		pki.issuerKey,
		pki.now.Add(-2*time.Hour),
		pki.now.Add(-time.Hour),
		nil,
	)

	_, err := VerifyBatchSigningCertificate(
		pki.leaf,
		pki.root,
		pki.issuer,
		expiredCRL,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyBatchSigningCertificate() error = nil, want expired-CRL rejection",
		)
	}

	if !strings.Contains(err.Error(), "batch-signing CRL is expired") {
		t.Fatalf(
			"VerifyBatchSigningCertificate() error = %q, want expired-CRL rejection",
			err,
		)
	}
}

func TestVerifyBatchSigningCertificateRejectsCRLSignedByWrongIssuer(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	other := newBatchSigningTestPKI(t)

	badCRL := createBatchSigningTestCRL(
		t,
		other.issuer,
		other.issuerKey,
		pki.now.Add(-time.Minute),
		pki.now.Add(time.Hour),
		nil,
	)

	_, err := VerifyBatchSigningCertificate(
		pki.leaf,
		pki.root,
		pki.issuer,
		badCRL,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyBatchSigningCertificate() error = nil, want CRL signature rejection",
		)
	}

	if !strings.Contains(err.Error(), "CRL signature validation failed") {
		t.Fatalf(
			"VerifyBatchSigningCertificate() error = %q, want CRL signature rejection",
			err,
		)
	}
}

func TestVerifyBatchSigningCertificateRejectsDisabledSource(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	pki.source.Enabled = false

	outcome, err := VerifyBatchSigningCertificate(
		pki.leaf,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyBatchSigningCertificate() error = nil, want disabled-source rejection",
		)
	}

	if outcome != AuthorizationDisabled {
		t.Fatalf(
			"VerifyBatchSigningCertificate() = %q, want %q",
			outcome,
			AuthorizationDisabled,
		)
	}
}

func TestVerifyBatchSigningCertificateRejectsFutureCRL(t *testing.T) {
	pki := newBatchSigningTestPKI(t)

	futureCRL := createBatchSigningTestCRL(
		t,
		pki.issuer,
		pki.issuerKey,
		pki.now.Add(time.Hour),
		pki.now.Add(2*time.Hour),
		nil,
	)

	_, err := VerifyBatchSigningCertificate(
		pki.leaf,
		pki.root,
		pki.issuer,
		futureCRL,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyBatchSigningCertificate() error = nil, want future-CRL rejection",
		)
	}

	if !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf(
			"VerifyBatchSigningCertificate() error = %q, want future-CRL rejection",
			err,
		)
	}
}

func TestVerifyBatchSigningCertificateRejectsMissingDigitalSignature(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	candidate := *pki.leaf
	candidate.KeyUsage = x509.KeyUsageKeyEncipherment

	_, err := VerifyBatchSigningCertificate(
		&candidate,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyBatchSigningCertificate() error = nil, want digital-signature rejection",
		)
	}

	if !strings.Contains(err.Error(), "does not permit digital signatures") {
		t.Fatalf(
			"VerifyBatchSigningCertificate() error = %q, want digital-signature rejection",
			err,
		)
	}
}

func TestVerifyBatchSigningCertificateRejectsRevokedCertificate(t *testing.T) {
	pki := newBatchSigningTestPKI(t)

	revokedCRL := createBatchSigningTestCRL(
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

	_, err := VerifyBatchSigningCertificate(
		pki.leaf,
		pki.root,
		pki.issuer,
		revokedCRL,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyBatchSigningCertificate() error = nil, want revocation rejection",
		)
	}

	if !strings.Contains(err.Error(), "is revoked") {
		t.Fatalf(
			"VerifyBatchSigningCertificate() error = %q, want revocation rejection",
			err,
		)
	}
}

func TestVerifyBatchSigningCertificateRejectsOrganizationalUnit(t *testing.T) {
	pki := newBatchSigningTestPKI(t)

	tests := []struct {
		name               string
		organizationalUnit []string
	}{
		{
			name:               "missing organizational unit",
			organizationalUnit: nil,
		},
		{
			name: "wrong organizational unit",
			organizationalUnit: []string{
				TransportOrganizationalUnit,
			},
		},
		{
			name: "multiple organizational units",
			organizationalUnit: []string{
				BatchSigningOrganizationalUnit,
				TransportOrganizationalUnit,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := *pki.leaf
			candidate.Subject = pki.leaf.Subject
			candidate.Subject.OrganizationalUnit = test.organizationalUnit

			_, err := VerifyBatchSigningCertificate(
				&candidate,
				pki.root,
				pki.issuer,
				pki.crl,
				pki.source,
				pki.now,
			)
			if err == nil {
				t.Fatal(
					"VerifyBatchSigningCertificate() error = nil, want organizational-unit rejection",
				)
			}
		})
	}
}

func TestVerifyBatchSigningCertificateRejectsWrongIssuer(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	other := newBatchSigningTestPKI(t)

	_, err := VerifyBatchSigningCertificate(
		pki.leaf,
		pki.root,
		other.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal(
			"VerifyBatchSigningCertificate() error = nil, want issuer rejection",
		)
	}

	if !strings.Contains(err.Error(), "expected FI batch-signing issuer") {
		t.Fatalf(
			"VerifyBatchSigningCertificate() error = %q, want issuer rejection",
			err,
		)
	}
}

func TestVerifySignedBatch(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	descriptor := validBatchSigningDescriptor()
	signature := signBatchDescriptor(t, descriptor, pki.leafKey)

	outcome, err := VerifySignedBatch(
		descriptor,
		signature,
		pki.leaf,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err != nil {
		t.Fatalf("VerifySignedBatch() error = %v", err)
	}

	if outcome != AuthorizationAuthorized {
		t.Fatalf(
			"VerifySignedBatch() = %q, want %q",
			outcome,
			AuthorizationAuthorized,
		)
	}
}

func TestVerifySignedBatchRejectsCertificateMismatch(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	descriptor := validBatchSigningDescriptor()
	signature := signBatchDescriptor(t, descriptor, pki.leafKey)
	pki.source.BatchSigning.CertificateSHA256 = strings.Repeat("0", 64)

	outcome, err := VerifySignedBatch(
		descriptor,
		signature,
		pki.leaf,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal("VerifySignedBatch() error = nil, want certificate rejection")
	}

	if outcome != AuthorizationCertificateMismatch {
		t.Fatalf(
			"VerifySignedBatch() = %q, want %q",
			outcome,
			AuthorizationCertificateMismatch,
		)
	}
}

func TestVerifySignedBatchRejectsMissingSignature(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	descriptor := validBatchSigningDescriptor()

	_, err := VerifySignedBatch(
		descriptor,
		nil,
		pki.leaf,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal("VerifySignedBatch() error = nil, want missing-signature rejection")
	}

	if !strings.Contains(err.Error(), "batch signature is required") {
		t.Fatalf(
			"VerifySignedBatch() error = %q, want missing-signature rejection",
			err,
		)
	}
}

func TestVerifySignedBatchRejectsSourceMismatch(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	descriptor := validBatchSigningDescriptor()
	descriptor.SourceID = "other-source.iss.local"
	signature := signBatchDescriptor(t, descriptor, pki.leafKey)

	outcome, err := VerifySignedBatch(
		descriptor,
		signature,
		pki.leaf,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal("VerifySignedBatch() error = nil, want source rejection")
	}

	if outcome != AuthorizationIdentityMismatch {
		t.Fatalf(
			"VerifySignedBatch() = %q, want %q",
			outcome,
			AuthorizationIdentityMismatch,
		)
	}
}

func TestVerifySignedBatchRejectsTamperedDescriptor(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	descriptor := validBatchSigningDescriptor()
	signature := signBatchDescriptor(t, descriptor, pki.leafKey)

	descriptor.BatchID = "batch-0002"

	_, err := VerifySignedBatch(
		descriptor,
		signature,
		pki.leaf,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal("VerifySignedBatch() error = nil, want signature rejection")
	}

	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf(
			"VerifySignedBatch() error = %q, want signature rejection",
			err,
		)
	}
}

func TestVerifySignedBatchRejectsWrongSignatureKey(t *testing.T) {
	pki := newBatchSigningTestPKI(t)
	other := newBatchSigningTestPKI(t)
	descriptor := validBatchSigningDescriptor()
	signature := signBatchDescriptor(t, descriptor, other.leafKey)

	_, err := VerifySignedBatch(
		descriptor,
		signature,
		pki.leaf,
		pki.root,
		pki.issuer,
		pki.crl,
		pki.source,
		pki.now,
	)
	if err == nil {
		t.Fatal("VerifySignedBatch() error = nil, want signature rejection")
	}

	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf(
			"VerifySignedBatch() error = %q, want signature rejection",
			err,
		)
	}
}

// Test helpers.

func batchSigningCertificateSHA256(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}

func createBatchSigningTestCRL(
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

func newBatchSigningTestPKI(t *testing.T) batchSigningTestPKI {
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
			CommonName: "FI Test Batch Signing Issuing CA",
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

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName: "iss-fs-01.iss.local",
			OrganizationalUnit: []string{
				BatchSigningOrganizationalUnit,
			},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
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

	crl := createBatchSigningTestCRL(
		t,
		issuer,
		issuerKey,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		nil,
	)

	source := SourceAuthorization{
		BatchSigning: CertificateIdentity{
			CertificateSHA256:  batchSigningCertificateSHA256(leaf),
			CommonName:         "iss-fs-01.iss.local",
			IssuingCASHA256:    batchSigningCertificateSHA256(issuer),
			OrganizationalUnit: BatchSigningOrganizationalUnit,
		},
		Enabled:  true,
		SourceID: "iss-fs-01.iss.local",
	}

	return batchSigningTestPKI{
		crl:       crl,
		issuer:    issuer,
		issuerKey: issuerKey,
		leaf:      leaf,
		leafKey:   leafKey,
		now:       now,
		root:      root,
		source:    source,
	}
}

func signBatchDescriptor(
	t *testing.T,
	descriptor transportbatch.Descriptor,
	key *rsa.PrivateKey,
) []byte {
	t.Helper()

	input, err := descriptor.SignatureInput()
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}

	digest := sha256.Sum256(input)
	signature, err := rsa.SignPSS(
		rand.Reader,
		key,
		crypto.SHA256,
		digest[:],
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
	if err != nil {
		t.Fatalf("rsa.SignPSS() error = %v", err)
	}

	return signature
}

func validBatchSigningDescriptor() transportbatch.Descriptor {
	return transportbatch.Descriptor{
		Version:     transportbatch.DescriptorVersion,
		SourceID:    "iss-fs-01.iss.local",
		BatchID:     "batch-0001",
		RecordCount: 7,
		DataBytes:   4096,
		DataSHA256: "0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef",
		ManifestSHA256: "abcdef0123456789abcdef0123456789" +
			"abcdef0123456789abcdef0123456789",
	}
}
