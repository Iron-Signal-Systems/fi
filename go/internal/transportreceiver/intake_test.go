// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportreceiver

import (
	"bytes"
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
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportwire"
)

// Test types.

type intakeTestFixture struct {
	batchIssuer    *x509.Certificate
	batchIssuerKey *rsa.PrivateKey
	config         IntakeConfig
	data           []byte
	leaf           *x509.Certificate
	leafKey        *rsa.PrivateKey
	manifest       []byte
	now            time.Time
	signedBatch    transportpackage.SignedBatch
}

// Tests.

func TestReadValidatedBatch(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	reader := bytes.NewReader(append(frame, []byte("NEXT")...))
	var received bytes.Buffer

	result, err := ReadValidatedBatch(reader, &received, fixture.config)
	if err != nil {
		t.Fatalf("ReadValidatedBatch() error = %v", err)
	}
	if !bytes.Equal(received.Bytes(), fixture.data) {
		t.Fatalf("received data = %q, want %q", received.Bytes(), fixture.data)
	}
	if !bytes.Equal(result.Manifest, fixture.manifest) {
		t.Fatalf("Manifest = %q, want %q", result.Manifest, fixture.manifest)
	}
	if result.DataBytes != uint64(len(fixture.data)) {
		t.Fatalf("DataBytes = %d, want %d", result.DataBytes, len(fixture.data))
	}
	dataDigest := sha256.Sum256(fixture.data)
	if result.DataSHA256 != hex.EncodeToString(dataDigest[:]) {
		t.Fatalf("DataSHA256 = %q, want data digest", result.DataSHA256)
	}
	if result.Header.SignedBatch.Descriptor.BatchID !=
		fixture.signedBatch.Descriptor.BatchID {
		t.Fatalf(
			"BatchID = %q, want %q",
			result.Header.SignedBatch.Descriptor.BatchID,
			fixture.signedBatch.Descriptor.BatchID,
		)
	}

	remaining := make([]byte, len("NEXT"))
	if _, err := reader.Read(remaining); err != nil {
		t.Fatalf("read following bytes: %v", err)
	}
	if string(remaining) != "NEXT" {
		t.Fatalf("remaining bytes = %q, want NEXT", remaining)
	}
}

func TestReadValidatedBatchRejectsBatchLargerThanReceiverLimit(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	fixture.config.MaxDataBytes = uint64(len(fixture.data) - 1)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	var received bytes.Buffer

	_, err := ReadValidatedBatch(bytes.NewReader(frame), &received, fixture.config)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want receiver-limit rejection")
	}
	if !strings.Contains(err.Error(), "exceeds receiver limit") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want receiver-limit rejection",
			err,
		)
	}
	if received.Len() != 0 {
		t.Fatalf("received %d data bytes before receiver-limit rejection", received.Len())
	}
}

func TestReadValidatedBatchRejectsCertificateEnrollmentMismatch(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	fixture.config.Source.BatchSigning.CertificateSHA256 = strings.Repeat("0", 64)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want enrollment rejection")
	}
	if !strings.Contains(err.Error(), "CERTIFICATE_MISMATCH") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want certificate mismatch",
			err,
		)
	}
}

func TestReadValidatedBatchRejectsDataHashMismatch(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	badData := append([]byte(nil), fixture.data...)
	badData[0] ^= 0x01
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		badData,
	)
	var received bytes.Buffer

	_, err := ReadValidatedBatch(bytes.NewReader(frame), &received, fixture.config)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want data-hash rejection")
	}
	if !strings.Contains(err.Error(), "data SHA-256") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want data-hash rejection",
			err,
		)
	}
	if !bytes.Equal(received.Bytes(), badData) {
		t.Fatal("provisional writer did not receive the exact framed data bytes")
	}
}

func TestReadValidatedBatchRejectsManifestHashMismatch(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	badManifest := append([]byte(nil), fixture.manifest...)
	badManifest[0] ^= 0x01
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		badManifest,
		fixture.data,
	)
	var received bytes.Buffer

	_, err := ReadValidatedBatch(bytes.NewReader(frame), &received, fixture.config)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want manifest-hash rejection")
	}
	if !strings.Contains(err.Error(), "manifest SHA-256") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want manifest-hash rejection",
			err,
		)
	}
	if received.Len() != 0 {
		t.Fatalf("received %d data bytes before manifest rejection", received.Len())
	}
}

func TestReadValidatedBatchRejectsRevokedBatchSigningCertificate(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	fixture.config.BatchCRL = createIntakeTestCRL(
		t,
		fixture.batchIssuer,
		fixture.batchIssuerKey,
		fixture.now,
		[]x509.RevocationListEntry{
			{
				SerialNumber:   fixture.leaf.SerialNumber,
				RevocationTime: fixture.now.Add(-time.Minute),
			},
		},
	)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want revoked-certificate rejection")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want revoked-certificate rejection",
			err,
		)
	}
}

func TestReadValidatedBatchRejectsShortData(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data[:len(fixture.data)-1],
	)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want short-data rejection")
	}
	if !strings.Contains(err.Error(), "read FI batch data payload") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want short-data rejection",
			err,
		)
	}
}

func TestReadValidatedBatchRejectsShortManifest(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	var encoded bytes.Buffer
	if err := transportwire.WriteHeader(
		&encoded,
		fixture.signedBatch,
		fixture.manifest,
	); err != nil {
		t.Fatalf("transportwire.WriteHeader() error = %v", err)
	}
	encoded.Write(fixture.manifest[:len(fixture.manifest)-1])

	_, err := ReadValidatedBatch(
		bytes.NewReader(encoded.Bytes()),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want short-manifest rejection")
	}
	if !strings.Contains(err.Error(), "read published FI batch manifest payload") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want short-manifest rejection",
			err,
		)
	}
}

func TestReadValidatedBatchRejectsSourceMismatch(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	fixture.config.Source.SourceID = "iss-fs-02.iss.local"
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want source mismatch")
	}
	if !strings.Contains(err.Error(), "does not match enrolled source ID") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want source mismatch",
			err,
		)
	}
}

func TestReadValidatedBatchRejectsTamperedSignature(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	bad := fixture.signedBatch
	bad.Signature = append([]byte(nil), fixture.signedBatch.Signature...)
	bad.Signature[0] ^= 0x01
	frame := encodeIntakeTestFrame(t, bad, fixture.manifest, fixture.data)

	_, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		&bytes.Buffer{},
		fixture.config,
	)
	if err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want signature rejection")
	}
	if !strings.Contains(err.Error(), "batch signature verification failed") {
		t.Fatalf(
			"ReadValidatedBatch() error = %q, want signature rejection",
			err,
		)
	}
}

func TestReadValidatedBatchRejectsInvalidArguments(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)

	if _, err := ReadValidatedBatch(nil, &bytes.Buffer{}, fixture.config); err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want nil-reader rejection")
	}
	if _, err := ReadValidatedBatch(
		bytes.NewReader(frame),
		nil,
		fixture.config,
	); err == nil {
		t.Fatal("ReadValidatedBatch() error = nil, want nil-writer rejection")
	}
}

func TestValidateIntakeConfig(t *testing.T) {
	valid := newIntakeTestFixture(t).config

	tests := []struct {
		name    string
		mutate  func(*IntakeConfig)
		wantErr string
	}{
		{
			name: "valid",
		},
		{
			name: "missing batch CRL",
			mutate: func(config *IntakeConfig) {
				config.BatchCRL = nil
			},
			wantErr: "batch-signing CRL is required",
		},
		{
			name: "missing batch issuer",
			mutate: func(config *IntakeConfig) {
				config.BatchIssuer = nil
			},
			wantErr: "batch-signing issuing certificate is required",
		},
		{
			name: "missing current time",
			mutate: func(config *IntakeConfig) {
				config.CurrentTime = time.Time{}
			},
			wantErr: "current time is required",
		},
		{
			name: "missing maximum data bytes",
			mutate: func(config *IntakeConfig) {
				config.MaxDataBytes = 0
			},
			wantErr: "maximum batch data byte count must be greater than zero",
		},
		{
			name: "missing root",
			mutate: func(config *IntakeConfig) {
				config.Root = nil
			},
			wantErr: "FI root certificate is required",
		},
		{
			name: "missing source",
			mutate: func(config *IntakeConfig) {
				config.Source.SourceID = ""
			},
			wantErr: "FI source authorization is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			if test.mutate != nil {
				test.mutate(&config)
			}

			err := validateIntakeConfig(config)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateIntakeConfig() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf(
					"validateIntakeConfig() error = nil, want %q",
					test.wantErr,
				)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"validateIntakeConfig() error = %q, want containing %q",
					err,
					test.wantErr,
				)
			}
		})
	}
}

// Test helpers.

func createIntakeTestCRL(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *rsa.PrivateKey,
	now time.Time,
	revoked []x509.RevocationListEntry,
) *x509.RevocationList {
	t.Helper()

	der, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:                    big.NewInt(1),
			ThisUpdate:                now.Add(-time.Hour),
			NextUpdate:                now.Add(time.Hour),
			RevokedCertificateEntries: revoked,
		},
		issuer,
		issuerKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateRevocationList() error = %v", err)
	}

	value, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("x509.ParseRevocationList() error = %v", err)
	}
	return value
}

func createIntakeTestCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey *rsa.PublicKey,
	parentKey *rsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		parent,
		publicKey,
		parentKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	value, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return value
}

func encodeIntakeTestFrame(
	t *testing.T,
	signedBatch transportpackage.SignedBatch,
	manifest []byte,
	data []byte,
) []byte {
	t.Helper()

	// Header construction intentionally uses the original manifest whose digest
	// is signed. Tests can then replace only the payload bytes to exercise intake
	// hash rejection without weakening the wire-header contract.
	manifestForHeader := manifest
	if signedBatch.Descriptor.ManifestSHA256 != digestHex(manifestForHeader) {
		fixtureManifest := []byte(`{"batch":"manifest"}` + "\n")
		if signedBatch.Descriptor.ManifestSHA256 != digestHex(fixtureManifest) {
			t.Fatal("test signed batch manifest digest does not match known fixture")
		}
		manifestForHeader = fixtureManifest
	}

	var encoded bytes.Buffer
	if err := transportwire.WriteHeader(
		&encoded,
		signedBatch,
		manifestForHeader,
	); err != nil {
		t.Fatalf("transportwire.WriteHeader() error = %v", err)
	}
	encoded.Write(manifest)
	encoded.Write(data)
	return encoded.Bytes()
}

func newIntakeTestFixture(t *testing.T) intakeTestFixture {
	t.Helper()

	now := time.Date(2026, 9, 12, 19, 30, 0, 0, time.UTC)
	const sourceID = "iss-fs-01.iss.local"

	rootKey := newIntakeTestRSAKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "FI Root CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x01, 0x01, 0x01},
	}
	root := createIntakeTestCertificate(
		t,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)

	issuerKey := newIntakeTestRSAKey(t)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject: pkix.Name{
			CommonName: "FI Batch Signing Issuing CA",
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x02, 0x02, 0x02},
	}
	issuer := createIntakeTestCertificate(
		t,
		issuerTemplate,
		root,
		&issuerKey.PublicKey,
		rootKey,
	)

	leafKey := newIntakeTestRSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(300),
		Subject: pkix.Name{
			CommonName:         sourceID,
			OrganizationalUnit: []string{transporttrust.BatchSigningOrganizationalUnit},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	leaf := createIntakeTestCertificate(
		t,
		leafTemplate,
		issuer,
		&leafKey.PublicKey,
		issuerKey,
	)

	identity, err := transporttrust.IdentityFromCertificate(leaf, issuer)
	if err != nil {
		t.Fatalf("transporttrust.IdentityFromCertificate() error = %v", err)
	}

	manifest := []byte(`{"batch":"manifest"}` + "\n")
	data := []byte("{\"record\":1}\n{\"record\":2}\n")
	manifestDigest := sha256.Sum256(manifest)
	dataDigest := sha256.Sum256(data)
	descriptor := transportbatch.Descriptor{
		Version:        transportbatch.DescriptorVersion,
		SourceID:       sourceID,
		BatchID:        "20260912T193000.000000000Z-0011223344556677",
		RecordCount:    2,
		DataBytes:      uint64(len(data)),
		DataSHA256:     hex.EncodeToString(dataDigest[:]),
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
	}

	signedBatch, err := transportpackage.NewSignedBatch(
		descriptor,
		leaf,
		leafKey,
	)
	if err != nil {
		t.Fatalf("transportpackage.NewSignedBatch() error = %v", err)
	}

	crl := createIntakeTestCRL(t, issuer, issuerKey, now, nil)
	return intakeTestFixture{
		batchIssuer:    issuer,
		batchIssuerKey: issuerKey,
		config: IntakeConfig{
			BatchCRL:     crl,
			BatchIssuer:  issuer,
			CurrentTime:  now,
			MaxDataBytes: 1024 * 1024,
			Root:         root,
			Source: transporttrust.SourceAuthorization{
				BatchSigning: identity,
				Enabled:      true,
				SourceID:     sourceID,
			},
		},
		data:        data,
		leaf:        leaf,
		leafKey:     leafKey,
		manifest:    manifest,
		now:         now,
		signedBatch: signedBatch,
	}
}

func newIntakeTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
