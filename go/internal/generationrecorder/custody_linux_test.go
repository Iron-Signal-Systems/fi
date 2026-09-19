// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package generationrecorder

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestRecordCustodyDurablyNewAndAlreadyRecorded(
	t *testing.T,
) {
	fixture := newCustodyRecorderFixture(t, false)

	first, err := RecordCustodyDurably(
		fixture.custody,
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err != nil {
		t.Fatal(err)
	}

	if first.Disposition != RecordedDispositionNew {
		t.Fatalf(
			"first disposition = %q, want NEW",
			first.Disposition,
		)
	}

	if first.Receipt.TransferSHA256 != fixture.custody.Transfer.TransferSHA256 ||
		first.Receipt.TransferBytes != fixture.custody.Transfer.TransferBytes {
		t.Fatal("recorder receipt did not bind exact custody transfer identity")
	}

	if first.Semantic.BatchCount != 1 || first.Semantic.RecordCount != 2 {
		t.Fatalf(
			"semantic result = batches %d records %d, want 1/2",
			first.Semantic.BatchCount,
			first.Semantic.RecordCount,
		)
	}

	second, err := RecordCustodyDurably(
		fixture.custody,
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err != nil {
		t.Fatal(err)
	}

	if second.Disposition != RecordedDispositionAlreadyRecorded {
		t.Fatalf(
			"second disposition = %q, want ALREADY_RECORDED",
			second.Disposition,
		)
	}

	if second.ReceiptSHA256 != first.ReceiptSHA256 ||
		second.ReceiptPath != first.ReceiptPath {
		t.Fatal("exact custody retry changed durable recorder receipt identity")
	}
}

func TestRecordCustodyDurablyRejectsSemanticFailureWithoutReceipt(
	t *testing.T,
) {
	fixture := newCustodyRecorderFixture(t, true)

	_, err := RecordCustodyDurably(
		fixture.custody,
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err == nil {
		t.Fatal("generation with invalid collector manifest semantics was recorded")
	}

	assertRecordedRootEmpty(t, fixture.recorderConfig.RootDir)
}

func TestRecordCustodyDurablyRevalidatesSigningTrust(
	t *testing.T,
) {
	fixture := newCustodyRecorderFixture(t, false)

	fixture.custodyConfig.Receive.Source.BatchSigning.CertificateSHA256 =
		strings.Repeat("0", 64)

	_, err := RecordCustodyDurably(
		fixture.custody,
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err == nil {
		t.Fatal("custody object outside current enrolled signing identity was recorded")
	}

	assertRecordedRootEmpty(t, fixture.recorderConfig.RootDir)
}

func TestRecordCustodyDurablyRejectsMutatedCustodyWithoutReceipt(
	t *testing.T,
) {
	fixture := newCustodyRecorderFixture(t, false)

	if err := os.Chmod(fixture.custody.CustodyPath, 0o600); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(
		fixture.custody.CustodyPath,
		os.O_WRONLY,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := file.WriteAt([]byte{0xff}, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(fixture.custody.CustodyPath, 0o400); err != nil {
		t.Fatal(err)
	}

	_, err = RecordCustodyDurably(
		fixture.custody,
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err == nil {
		t.Fatal("mutated durable custody object was recorded")
	}

	assertRecordedRootEmpty(t, fixture.recorderConfig.RootDir)
}

type custodyRecorderFixture struct {
	custody        transportgeneration.CustodyResult
	custodyConfig  transportgeneration.CustodyConfig
	recorderConfig DurableConfig
}

func newCustodyRecorderFixture(
	t *testing.T,
	invalidManifest bool,
) custodyRecorderFixture {
	t.Helper()

	const sourceID = "iss-fs-01.iss.local"

	root, issuer, leaf, leafKey, crl, source :=
		newCustodyRecorderTrust(t, sourceID)

	frozen := filepath.Join(
		t.TempDir(),
		"frozen",
	)

	if err := os.Mkdir(frozen, 0o700); err != nil {
		t.Fatal(err)
	}

	overrideSHA256 := ""
	if invalidManifest {
		overrideSHA256 = strings.Repeat("0", 64)
	}

	writeRecorderBatch(
		t,
		frozen,
		"20260918T170000.000000000Z-0011223344556677",
		[]byte("{\"record\":1}\n{\"record\":2}\n"),
		overrideSHA256,
	)

	sealedRoot := filepath.Join(
		t.TempDir(),
		"sealed",
	)

	if err := os.Mkdir(sealedRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	published, err := transportgeneration.CreateSealedGeneration(
		context.Background(),
		transportgeneration.CreateConfig{
			BatchSigner:             leafKey,
			BatchSigningCertificate: leaf,
			FrozenDir:               frozen,
			GenerationID:            "20260918T170500.000000000Z-0123456789abcdef",
			SealedRoot:              sealedRoot,
			SourceID:                sourceID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	offer, err := transportgeneration.OfferFromPublished(published)
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	if _, err := transportgeneration.WritePublishedGeneration(
		&wire,
		published,
	); err != nil {
		t.Fatal(err)
	}

	receiveConfig := transportgeneration.ReceiveConfig{
		BatchCRL:          crl,
		BatchIssuer:       issuer,
		CurrentTime:       time.Now(),
		MaxCanonicalBytes: 64 << 20,
		MaxEncodedBytes:   64 << 20,
		Root:              root,
		Source:            source,
	}

	custodyRoot := filepath.Join(
		t.TempDir(),
		"custody",
	)

	if err := os.Mkdir(custodyRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	custodyConfig := transportgeneration.CustodyConfig{
		Receive: receiveConfig,
		RootDir: custodyRoot,
	}

	custody, err := transportgeneration.ReceiveToDurableCustody(
		bytes.NewReader(wire.Bytes()),
		offer,
		custodyConfig,
	)
	if err != nil {
		t.Fatal(err)
	}

	recordedRoot := filepath.Join(
		t.TempDir(),
		"recorded",
	)

	if err := os.Mkdir(recordedRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	return custodyRecorderFixture{
		custody:       custody,
		custodyConfig: custodyConfig,
		recorderConfig: DurableConfig{
			RootDir: recordedRoot,
			Semantic: Config{
				MaxManifestBytes: 1 << 20,
			},
		},
	}
}

func newCustodyRecorderTrust(
	t *testing.T,
	sourceID string,
) (
	*x509.Certificate,
	*x509.Certificate,
	*x509.Certificate,
	*rsa.PrivateKey,
	*x509.RevocationList,
	transporttrust.SourceAuthorization,
) {
	t.Helper()

	now := time.Now().UTC()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3001),
		Subject: pkix.Name{
			CommonName: "FI Recorder Root Test",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{11, 12, 13, 14},
	}

	root := createCustodyRecorderCertificate(
		t,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3002),
		Subject: pkix.Name{
			CommonName: "FI Recorder Batch Signing Test CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{15, 16, 17, 18},
	}

	issuer := createCustodyRecorderCertificate(
		t,
		issuerTemplate,
		root,
		&issuerKey.PublicKey,
		rootKey,
	)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3003),
		Subject: pkix.Name{
			CommonName: sourceID,
			OrganizationalUnit: []string{
				transporttrust.BatchSigningOrganizationalUnit,
			},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(6 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	leaf := createCustodyRecorderCertificate(
		t,
		leafTemplate,
		issuer,
		&leafKey.PublicKey,
		issuerKey,
	)

	crlDER, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(time.Hour),
		},
		issuer,
		issuerKey,
	)
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
			CertificateSHA256:  custodyRecorderCertificateSHA256(leaf),
			CommonName:         sourceID,
			IssuingCASHA256:    custodyRecorderCertificateSHA256(issuer),
			OrganizationalUnit: transporttrust.BatchSigningOrganizationalUnit,
		},
	}

	return root, issuer, leaf, leafKey, crl, source
}

func createCustodyRecorderCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey *rsa.PublicKey,
	signer *rsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		parent,
		publicKey,
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return certificate
}

func custodyRecorderCertificateSHA256(
	certificate *x509.Certificate,
) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}
