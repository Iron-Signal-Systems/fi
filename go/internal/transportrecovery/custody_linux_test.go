//go:build linux

package transportrecovery

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestRecoveryDurableCustodyNewDuplicateAndConflict(t *testing.T) {
	sourceID := "iss-fs-01.iss.local"
	root, issuer, leaf, leafKey, crl, source := testRecoveryTrust(t, sourceID)

	spoolDir := t.TempDir()
	stageA := t.TempDir()
	stageB := t.TempDir()
	custodyDir := t.TempDir()
	if err := os.Chmod(custodyDir, 0o700); err != nil {
		t.Fatal(err)
	}

	paths := []string{
		writeTestPublishedBatch(t, spoolDir, "20260915T000001.000000000Z-0000000000000001", []byte("{\"a\":1}\n{\"a\":2}\n")),
		writeTestPublishedBatch(t, spoolDir, "20260915T000002.000000000Z-0000000000000002", []byte("{\"b\":1}\n{\"b\":2}\n")),
	}
	index, _, err := BuildIndex(paths)
	if err != nil {
		t.Fatal(err)
	}

	recoveryID := "20260915T000100.000000000Z-0011223344556677"
	preparedA, err := PrepareFrame(PrepareConfig{
		BatchSigner:             leafKey,
		BatchSigningCertificate: leaf,
		Index:                   index,
		MaxEncodedBytes:         64 << 20,
		RecoveryID:              recoveryID,
		SourceID:                sourceID,
		StageDir:                stageA,
	})
	if err != nil {
		t.Fatal(err)
	}
	frameA, err := os.ReadFile(preparedA.FramePath)
	if err != nil {
		t.Fatal(err)
	}

	config := CustodyConfig{
		BatchCRL:          crl,
		BatchIssuer:       issuer,
		CurrentTime:       time.Now(),
		MaxCanonicalBytes: 64 << 20,
		MaxEncodedBytes:   64 << 20,
		MaxMembers:        100,
		Root:              root,
		RootDir:           custodyDir,
		Source:            source,
	}

	first, err := ReceiveToDurableCustody(bytes.NewReader(frameA), config)
	if err != nil {
		t.Fatal(err)
	}
	if first.Disposition != CustodyDispositionNew {
		t.Fatalf("first custody disposition = %q, want NEW", first.Disposition)
	}
	ack, err := AcknowledgementFromCustody(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcknowledgementMatches(ack, preparedA.Descriptor, preparedA.FrameBytes, preparedA.FrameSHA256); err != nil {
		t.Fatal(err)
	}

	second, err := ReceiveToDurableCustody(bytes.NewReader(frameA), config)
	if err != nil {
		t.Fatal(err)
	}
	if second.Disposition != CustodyDispositionDuplicate {
		t.Fatalf("second custody disposition = %q, want DUPLICATE", second.Disposition)
	}

	// Re-signing the same recovery identity can produce a different valid
	// RSA-PSS frame. FI must not overwrite the exact durable custody object.
	preparedB, err := PrepareFrame(PrepareConfig{
		BatchSigner:             leafKey,
		BatchSigningCertificate: leaf,
		Index:                   index,
		MaxEncodedBytes:         64 << 20,
		RecoveryID:              recoveryID,
		SourceID:                sourceID,
		StageDir:                stageB,
	})
	if err != nil {
		t.Fatal(err)
	}
	frameB, err := os.ReadFile(preparedB.FramePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(frameA, frameB) {
		t.Skip("RSA-PSS happened to produce identical frame bytes; conflict path not exercised")
	}
	if _, err := ReceiveToDurableCustody(bytes.NewReader(frameB), config); !errors.Is(err, ErrRecoveryCustodyConflict) {
		t.Fatalf("expected recovery custody conflict, got %v", err)
	}

	if filepath.Ext(first.FramePath) != ".firb" {
		t.Fatalf("recovery custody path extension = %q, want .firb", filepath.Ext(first.FramePath))
	}
}

func testRecoveryTrust(
	t *testing.T,
	sourceID string,
) (*x509.Certificate, *x509.Certificate, *x509.Certificate, *rsa.PrivateKey, *x509.RevocationList, transporttrust.SourceAuthorization) {
	t.Helper()
	now := time.Now().UTC()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "FI Root Test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	root := createTestCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1002),
		Subject:               pkix.Name{CommonName: "FI Batch Signing Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{5, 6, 7, 8},
	}
	issuer := createTestCertificate(t, issuerTemplate, root, &issuerKey.PublicKey, rootKey)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1003),
		Subject: pkix.Name{
			CommonName:         sourceID,
			OrganizationalUnit: []string{transporttrust.BatchSigningOrganizationalUnit},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(6 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	leaf := createTestCertificate(t, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
	}, issuer, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	source := transporttrust.SourceAuthorization{
		Enabled:  true,
		SourceID: sourceID,
		BatchSigning: transporttrust.CertificateIdentity{
			CertificateSHA256:  certificateSHA256(leaf),
			CommonName:         sourceID,
			IssuingCASHA256:    certificateSHA256(issuer),
			OrganizationalUnit: transporttrust.BatchSigningOrganizationalUnit,
		},
	}
	return root, issuer, leaf, leafKey, crl, source
}

func createTestCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey *rsa.PublicKey,
	signer *rsa.PrivateKey,
) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func certificateSHA256(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}
