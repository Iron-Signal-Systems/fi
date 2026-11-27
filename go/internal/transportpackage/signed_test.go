// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportpackage

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

// Tests.

func TestNewSignedBatch(t *testing.T) {
	key, certificate := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)
	descriptor := validSignedPackageDescriptor()

	value, err := NewSignedBatch(descriptor, certificate, key)
	if err != nil {
		t.Fatalf("NewSignedBatch() error = %v", err)
	}
	if value.Version != SignedBatchVersion {
		t.Fatalf("Version = %q, want %q", value.Version, SignedBatchVersion)
	}
	if value.Descriptor != descriptor {
		t.Fatalf("Descriptor = %#v, want %#v", value.Descriptor, descriptor)
	}
	if len(value.Signature) == 0 {
		t.Fatal("Signature is empty")
	}
	if len(value.BatchSigningCertificateDER) == 0 {
		t.Fatal("BatchSigningCertificateDER is empty")
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	input, err := descriptor.SignatureInput()
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input)
	if err := rsa.VerifyPSS(
		&key.PublicKey,
		crypto.SHA256,
		digest[:],
		value.Signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	); err != nil {
		t.Fatalf("rsa.VerifyPSS() error = %v", err)
	}
}

func TestNewSignedBatchCopiesCertificateDER(t *testing.T) {
	key, certificate := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)
	original := append([]byte(nil), certificate.Raw...)

	value, err := NewSignedBatch(validSignedPackageDescriptor(), certificate, key)
	if err != nil {
		t.Fatalf("NewSignedBatch() error = %v", err)
	}

	certificate.Raw[0] ^= 0xff
	if string(value.BatchSigningCertificateDER) != string(original) {
		t.Fatal("signed batch certificate DER changed after caller mutation")
	}
}

func TestNewSignedBatchRejectsCA(t *testing.T) {
	key, certificate := newBatchSigningIdentityWithOptions(
		t,
		"iss-fs-01.iss.local",
		[]string{transporttrust.BatchSigningOrganizationalUnit},
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
		true,
	)

	_, err := NewSignedBatch(validSignedPackageDescriptor(), certificate, key)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want CA rejection")
	}
	if !strings.Contains(err.Error(), "must not be a CA") {
		t.Fatalf("NewSignedBatch() error = %q, want CA rejection", err)
	}
}

func TestNewSignedBatchRejectsInvalidDescriptor(t *testing.T) {
	key, certificate := newBatchSigningIdentity(
		t,
		"iss-fs-01.iss.local",
		transporttrust.BatchSigningOrganizationalUnit,
	)
	descriptor := validSignedPackageDescriptor()
	descriptor.BatchID = ""

	if _, err := NewSignedBatch(descriptor, certificate, key); err == nil {
		t.Fatal("NewSignedBatch() error = nil, want invalid descriptor rejection")
	}
}

func TestNewSignedBatchRejectsMissingCertificateDER(t *testing.T) {
	key, _ := newBatchSigningIdentity(
		t,
		"iss-fs-01.iss.local",
		transporttrust.BatchSigningOrganizationalUnit,
	)
	certificate := &x509.Certificate{}

	if _, err := NewSignedBatch(
		validSignedPackageDescriptor(),
		certificate,
		key,
	); err == nil {
		t.Fatal("NewSignedBatch() error = nil, want missing certificate DER rejection")
	}
}

func TestNewSignedBatchRejectsMissingDigitalSignatureUsage(t *testing.T) {
	key, certificate := newBatchSigningIdentityWithOptions(
		t,
		"iss-fs-01.iss.local",
		[]string{transporttrust.BatchSigningOrganizationalUnit},
		x509.KeyUsageKeyEncipherment,
		false,
	)

	_, err := NewSignedBatch(validSignedPackageDescriptor(), certificate, key)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want key-usage rejection")
	}
	if !strings.Contains(err.Error(), "does not permit digital signatures") {
		t.Fatalf("NewSignedBatch() error = %q, want key-usage rejection", err)
	}
}

func TestNewSignedBatchRejectsMultipleOrganizationalUnits(t *testing.T) {
	key, certificate := newBatchSigningIdentityWithOptions(
		t,
		"iss-fs-01.iss.local",
		[]string{
			transporttrust.BatchSigningOrganizationalUnit,
			"Unexpected Role",
		},
		x509.KeyUsageDigitalSignature,
		false,
	)

	_, err := NewSignedBatch(validSignedPackageDescriptor(), certificate, key)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want OU-count rejection")
	}
	if !strings.Contains(err.Error(), "exactly one organizational unit") {
		t.Fatalf("NewSignedBatch() error = %q, want OU-count rejection", err)
	}
}

func TestNewSignedBatchRejectsNonRSACertificate(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	certificate := newBatchSigningEd25519Certificate(
		t,
		"iss-fs-01.iss.local",
		publicKey,
		privateKey,
	)
	_, err = NewSignedBatch(
		validSignedPackageDescriptor(),
		certificate,
		privateKey,
	)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want non-RSA certificate rejection")
	}
	if !strings.Contains(err.Error(), "certificate public key must be RSA") {
		t.Fatalf("NewSignedBatch() error = %q, want RSA certificate rejection", err)
	}
}

func TestNewSignedBatchRejectsNonRSASigner(t *testing.T) {
	_, certificate := newBatchSigningIdentity(
		t,
		"iss-fs-01.iss.local",
		transporttrust.BatchSigningOrganizationalUnit,
	)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	_, err = NewSignedBatch(
		validSignedPackageDescriptor(),
		certificate,
		privateKey,
	)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want non-RSA signer rejection")
	}
	if !strings.Contains(err.Error(), "batch signer public key must be RSA") {
		t.Fatalf("NewSignedBatch() error = %q, want RSA signer rejection", err)
	}
}

func TestNewSignedBatchRejectsOversizedCertificateDER(t *testing.T) {
	key, _ := newBatchSigningIdentity(
		t,
		"iss-fs-01.iss.local",
		transporttrust.BatchSigningOrganizationalUnit,
	)
	certificate := &x509.Certificate{
		Raw: make([]byte, MaxBatchSigningCertificateDERBytes+1),
	}

	_, err := NewSignedBatch(
		validSignedPackageDescriptor(),
		certificate,
		key,
	)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want oversized certificate rejection")
	}
	if !strings.Contains(err.Error(), "certificate DER exceeds") {
		t.Fatalf(
			"NewSignedBatch() error = %q, want oversized certificate rejection",
			err,
		)
	}
}

func TestNewSignedBatchRejectsCertificateSourceMismatch(t *testing.T) {
	key, certificate := newBatchSigningIdentity(t, "other-source.iss.local", transporttrust.BatchSigningOrganizationalUnit)

	_, err := NewSignedBatch(validSignedPackageDescriptor(), certificate, key)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want source mismatch rejection")
	}
	if !strings.Contains(err.Error(), "does not match source ID") {
		t.Fatalf("NewSignedBatch() error = %q, want source mismatch rejection", err)
	}
}

func TestNewSignedBatchRejectsCertificateRole(t *testing.T) {
	key, certificate := newBatchSigningIdentity(t, "iss-fs-01.iss.local", "Wrong Role")

	_, err := NewSignedBatch(validSignedPackageDescriptor(), certificate, key)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want certificate role rejection")
	}
	if !strings.Contains(err.Error(), "organizational unit must be") {
		t.Fatalf("NewSignedBatch() error = %q, want role rejection", err)
	}
}

func TestNewSignedBatchRejectsNilCertificate(t *testing.T) {
	key, _ := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)

	if _, err := NewSignedBatch(validSignedPackageDescriptor(), nil, key); err == nil {
		t.Fatal("NewSignedBatch() error = nil, want nil certificate rejection")
	}
}

func TestNewSignedBatchRejectsNilSigner(t *testing.T) {
	_, certificate := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)

	if _, err := NewSignedBatch(validSignedPackageDescriptor(), certificate, nil); err == nil {
		t.Fatal("NewSignedBatch() error = nil, want nil signer rejection")
	}
}

func TestNewSignedBatchRejectsSignerCertificateMismatch(t *testing.T) {
	_, certificate := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)
	otherKey, _ := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)

	_, err := NewSignedBatch(validSignedPackageDescriptor(), certificate, otherKey)
	if err == nil {
		t.Fatal("NewSignedBatch() error = nil, want signer/certificate mismatch rejection")
	}
	if !strings.Contains(err.Error(), "does not match batch-signing certificate") {
		t.Fatalf("NewSignedBatch() error = %q, want key mismatch rejection", err)
	}
}

func TestSignedBatchValidateRejectsMalformedCertificate(t *testing.T) {
	value := SignedBatch{
		Version:                    SignedBatchVersion,
		Descriptor:                 validSignedPackageDescriptor(),
		Signature:                  []byte{1},
		BatchSigningCertificateDER: []byte{1, 2, 3},
	}

	if err := value.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want malformed certificate rejection")
	}
}

func TestSignedBatchValidateRejectsMissingCertificate(t *testing.T) {
	value := SignedBatch{
		Version:    SignedBatchVersion,
		Descriptor: validSignedPackageDescriptor(),
		Signature:  []byte{1},
	}

	if err := value.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want missing certificate rejection")
	}
}

func TestSignedBatchValidateRejectsOversizedCertificate(t *testing.T) {
	value := SignedBatch{
		Version:                    SignedBatchVersion,
		Descriptor:                 validSignedPackageDescriptor(),
		Signature:                  []byte{1},
		BatchSigningCertificateDER: make([]byte, MaxBatchSigningCertificateDERBytes+1),
	}

	if err := value.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want oversized certificate rejection")
	}
}

func TestSignedBatchValidateRejectsMissingSignature(t *testing.T) {
	_, certificate := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)
	value := SignedBatch{
		Version:                    SignedBatchVersion,
		Descriptor:                 validSignedPackageDescriptor(),
		BatchSigningCertificateDER: append([]byte(nil), certificate.Raw...),
	}

	if err := value.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want missing signature rejection")
	}
}

func TestSignedBatchValidateRejectsOversizedSignature(t *testing.T) {
	_, certificate := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)
	value := SignedBatch{
		Version:                    SignedBatchVersion,
		Descriptor:                 validSignedPackageDescriptor(),
		Signature:                  make([]byte, MaxBatchSignatureBytes+1),
		BatchSigningCertificateDER: append([]byte(nil), certificate.Raw...),
	}

	if err := value.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want oversized signature rejection")
	}
}

func TestSignedBatchValidateRejectsVersion(t *testing.T) {
	_, certificate := newBatchSigningIdentity(t, "iss-fs-01.iss.local", transporttrust.BatchSigningOrganizationalUnit)
	value := SignedBatch{
		Version:                    "fi-signed-batch/9.9",
		Descriptor:                 validSignedPackageDescriptor(),
		Signature:                  []byte{1},
		BatchSigningCertificateDER: append([]byte(nil), certificate.Raw...),
	}

	if err := value.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want version rejection")
	}
}

// Test helpers.

func newBatchSigningEd25519Certificate(
	t *testing.T,
	commonName string,
	publicKey ed25519.PublicKey,
	privateKey ed25519.PrivateKey,
) *x509.Certificate {
	t.Helper()

	now := time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		Subject: pkix.Name{
			CommonName: commonName,
			OrganizationalUnit: []string{
				transporttrust.BatchSigningOrganizationalUnit,
			},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		publicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	return certificate
}

func newBatchSigningIdentity(
	t *testing.T,
	commonName string,
	organizationalUnit string,
) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	return newBatchSigningIdentityWithOptions(
		t,
		commonName,
		[]string{organizationalUnit},
		x509.KeyUsageDigitalSignature,
		false,
	)
}

func newBatchSigningIdentityWithOptions(
	t *testing.T,
	commonName string,
	organizationalUnits []string,
	keyUsage x509.KeyUsage,
	isCA bool,
) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	now := time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: organizationalUnits,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              keyUsage,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
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

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	return key, certificate
}

func validSignedPackageDescriptor() transportbatch.Descriptor {
	return transportbatch.Descriptor{
		Version:     transportbatch.DescriptorVersion,
		SourceID:    "iss-fs-01.iss.local",
		BatchID:     "20260912T180000.000000000Z-0011223344556677",
		RecordCount: 7,
		DataBytes:   4096,
		DataSHA256: "0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef",
		ManifestSHA256: "abcdef0123456789abcdef0123456789" +
			"abcdef0123456789abcdef0123456789",
	}
}
