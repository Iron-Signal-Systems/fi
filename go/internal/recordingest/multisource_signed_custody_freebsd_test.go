// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package recordingest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportreceiver"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

type m1SignedSource struct {
	GenerationID string
	ReceiptPath  string
	SourceID     string
	Trust        generationTrustBundle
}

func m1MakeCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	key *rsa.PublicKey,
	signer *rsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	raw, err := x509.CreateCertificate(
		rand.Reader, template, parent, key, signer,
	)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}

	return certificate
}

func m1MakeSignedTrust(
	t *testing.T,
	sourceID string,
) (generationTrustBundle, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	now := time.Now().UTC()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(5001),
		Subject: pkix.Name{
			CommonName: "FI M1 Isolated Root Test",
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{21, 22, 23, 24},
	}

	root := m1MakeCertificate(
		t, rootTemplate, rootTemplate,
		&rootKey.PublicKey, rootKey,
	)

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(5002),
		Subject: pkix.Name{
			CommonName: "FI M1 Isolated Batch Signing CA",
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{25, 26, 27, 28},
	}

	issuer := m1MakeCertificate(
		t, issuerTemplate, root,
		&issuerKey.PublicKey, rootKey,
	)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	templateOID := asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 311, 21, 8, 100, 2,
	}
	informationOID := asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 311, 21, 7,
	}

	templateInformation, err := asn1.Marshal(struct {
		TemplateID   asn1.ObjectIdentifier
		MajorVersion int
		MinorVersion int `asn1:"optional"`
	}{
		TemplateID:   templateOID,
		MajorVersion: 100,
		MinorVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(5003),
		Subject: pkix.Name{
			CommonName: sourceID,
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(6 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    informationOID,
				Value: templateInformation,
			},
		},
	}

	leaf := m1MakeCertificate(
		t, leafTemplate, issuer,
		&leafKey.PublicKey, issuerKey,
	)

	crlRaw, err := x509.CreateRevocationList(
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

	crl, err := x509.ParseRevocationList(crlRaw)
	if err != nil {
		t.Fatal(err)
	}

	digest := func(cert *x509.Certificate) string {
		value := sha256.Sum256(cert.Raw)
		return hex.EncodeToString(value[:])
	}

	return generationTrustBundle{
		Root:        root,
		BatchIssuer: issuer,
		BatchCRL:    crl,
		Source: transporttrust.SourceAuthorization{
			Enabled:  true,
			SourceID: sourceID,
			BatchSigning: transporttrust.CertificateIdentity{
				CertificateSHA256: digest(leaf),
				CommonName:        sourceID,
				IssuingCASHA256:   digest(issuer),
				TemplateOID:       templateOID.String(),
			},
		},
	}, leafKey, leaf
}

// m1WriteSignedGeneration preserves the one-record correctness fixture.
// The variable-record helper below is used only by isolated performance tests.
func m1WriteSignedGeneration(
	t *testing.T,
	root string,
	sourceID string,
) m1SignedSource {
	t.Helper()
	payload := json.RawMessage(
		`{"source":"M1-Isolated-Ingest","error":"synthetic controlled test record"}`,
	)
	record := spool.Record{
		Version:    spool.RecordVersion,
		RecordKind: "SupportingSourceCollectionError",
		ScopeID:    "m1-" + sourceID,
		WrittenAt:  time.Now().UTC().Format(time.RFC3339Nano),
		Payload:    payload,
	}
	return m1WriteSignedGenerationRecords(t, root, sourceID, []spool.Record{record})
}

// m1WriteSignedGenerationRecords runs the same authenticated signing,
// receiver, custody and recorded-generation workflow for bounded test input.
// Never supply production evidence or a production custody root here.
func m1WriteSignedGenerationRecords(
	t *testing.T,
	root string,
	sourceID string,
	input []spool.Record,
) m1SignedSource {
	t.Helper()
	if len(input) == 0 || len(input) > 16384 {
		t.Fatal("isolated signed generation requires 1..16384 records")
	}

	trust, signer, certificate := m1MakeSignedTrust(
		t, sourceID,
	)

	sourceRoot := filepath.Join(root, sourceID)
	frozen := filepath.Join(sourceRoot, "frozen")
	sealed := filepath.Join(sourceRoot, "sealed")

	for _, dir := range []string{frozen, sealed} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}

	// Validate each exact LF-terminated record before sealing the batch.
	// A single batch preserves source order, and the manifest count must match.
	var raw []byte
	for i, record := range input {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal isolated record %d: %v", i, err)
		}
		line = append(line, '\n')
		if _, err := PrepareSourceRecord(line); err != nil {
			t.Fatalf("invalid isolated record %d: %v", i, err)
		}
		raw = append(raw, line...)
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	suffix := hex.EncodeToString(nonce)
	batchID := time.Now().UTC().Format(
		"20060102T150405.000000000Z",
	) + "-" + suffix

	dataName := "batch-" + batchID + ".jsonl"
	manifestName := "batch-" + batchID + ".manifest.json"

	if err := os.WriteFile(
		filepath.Join(frozen, dataName),
		raw, 0600,
	); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(raw)

	manifest := spool.Manifest{
		Version:         spool.ManifestVersion,
		BatchID:         batchID,
		TargetBatchSize: 262144,
		RecordCount:     len(input),
		DataBytes:       int64(len(raw)),
		DataSHA256:      hex.EncodeToString(digest[:]),
		DataFile:        dataName,
		Collector: spool.CollectorIdentity{
			ExecutablePath: `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a" +
				"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
		},
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
	}

	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = append(manifestRaw, '\n')

	if err := os.WriteFile(
		filepath.Join(frozen, manifestName),
		manifestRaw, 0600,
	); err != nil {
		t.Fatal(err)
	}

	generationID := time.Now().UTC().Format(
		"20060102T150405.000000000Z",
	) + "-" + suffix

	published, err := transportgeneration.CreateSealedGeneration(
		context.Background(),
		transportgeneration.CreateConfig{
			BatchSigner:             signer,
			BatchSigningCertificate: certificate,
			FrozenDir:               frozen,
			GenerationID:            generationID,
			SealedRoot:              sealed,
			SourceID:                sourceID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	offer, err := transportgeneration.OfferFromPublished(
		published,
	)
	if err != nil {
		t.Fatal(err)
	}

	var transaction bytes.Buffer

	if err := transportgeneration.WriteOffer(
		&transaction, offer,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := transportgeneration.WritePublishedGeneration(
		&transaction,
		published,
	); err != nil {
		t.Fatal(err)
	}

	custodyRoot := filepath.Join(root, "custody")
	recordedRoot := filepath.Join(root, "recorded")
	readyRoot := filepath.Join(root, "ready")

	receive := transportreceiver.GenerationReceiveConfig{
		Custody: transportgeneration.CustodyConfig{
			RootDir: custodyRoot,
			Receive: transportgeneration.ReceiveConfig{
				BatchCRL:          trust.BatchCRL,
				BatchIssuer:       trust.BatchIssuer,
				CurrentTime:       time.Now().UTC(),
				MaxCanonicalBytes: 64 << 20,
				MaxEncodedBytes:   64 << 20,
				Root:              trust.Root,
				Source:            trust.Source,
			},
		},
		ReadyRoot: readyRoot,
		Recorder: generationrecorder.DurableConfig{
			RootDir:          recordedRoot,
			SourceNamespaces: true,
			Semantic: generationrecorder.Config{
				MaxManifestBytes: 1 << 20,
			},
		},
	}

	var output bytes.Buffer

	result, err := transportreceiver.ReceiveGenerationAndAcknowledge(
		&transaction,
		&output,
		receive,
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Recorder.Disposition !=
		generationrecorder.RecordedDispositionNew {
		t.Fatalf("unexpected recorder disposition: %q",
			result.Recorder.Disposition)
	}

	if result.ReadyWarning != "" {
		t.Fatalf("READY warning: %s", result.ReadyWarning)
	}

	decision, err := transportgeneration.ReadDecision(
		&output,
	)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgement, err :=
		transportgeneration.ReadAcknowledgement(&output)
	if err != nil {
		t.Fatal(err)
	}

	if !decision.Accepted ||
		acknowledgement.Outcome !=
			transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatal("signed generation was not acknowledged")
	}

	expectedPath := filepath.Join(
		recordedRoot,
		"sources",
		sourceID,
		generationrecorder.RecordedReceiptObjectName(
			sourceID, generationID,
		),
	)

	if result.Recorder.ReceiptPath != expectedPath {
		t.Fatalf("unexpected receipt path: %q",
			result.Recorder.ReceiptPath)
	}

	return m1SignedSource{
		GenerationID: generationID,
		ReceiptPath:  expectedPath,
		SourceID:     sourceID,
		Trust:        trust,
	}
}

func TestM1TwoSourceSignedCustodyAndLoad(t *testing.T) {
	root := t.TempDir()

	for _, directory := range []string{
		"custody", "recorded", "ready",
	} {
		if err := os.Mkdir(
			filepath.Join(root, directory), 0700,
		); err != nil {
			t.Fatal(err)
		}
	}

	parent := filepath.Join(root, "recorded", "sources")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}

	sourceIDs := []string{
		"iss-fs-2019.iss.local",
		"iss-fs-22.iss.local",
	}

	for _, source := range sourceIDs {
		if err := os.Mkdir(
			filepath.Join(parent, source), 0700,
		); err != nil {
			t.Fatal(err)
		}
	}

	for _, sourceID := range sourceIDs {
		signed := m1WriteSignedGeneration(
			t, root, sourceID,
		)

		config := GenerationLoadConfig{
			CustodyRoot:       filepath.Join(root, "custody"),
			RecordedRoot:      filepath.Join(root, "recorded"),
			SourceNamespaces:  true,
			SourceID:          sourceID,
			MaxCanonicalBytes: 64 << 20,
			MaxEncodedBytes:   64 << 20,
			MaxManifestBytes:  1 << 20,
		}

		prepared, err := loadRecordedGenerationWithTrust(
			config,
			signed.GenerationID,
			func(requested string) (
				generationTrustBundle, error,
			) {
				if requested != sourceID {
					t.Fatalf(
						"trust source=%q want=%q",
						requested, sourceID,
					)
				}
				return signed.Trust, nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		if len(prepared.Batches) != 1 ||
			prepared.Receipt.RecordCount != 1 ||
			prepared.Receipt.Descriptor.SourceID != sourceID {
			t.Fatal("loaded generation semantics incorrect")
		}

		data, err := os.ReadFile(
			prepared.Batches[0].DataPath,
		)
		if err != nil {
			t.Fatal(err)
		}

		record, err := PrepareSourceRecord(data)
		if err != nil {
			t.Fatal(err)
		}

		if record.Record.RecordKind !=
			"SupportingSourceCollectionError" {
			t.Fatal("loaded unexpected FI source record")
		}

		if err := prepared.Close(); err != nil {
			t.Fatal(err)
		}

		t.Logf(
			"PASS: source=%s signed custody, ACK, receipt and load",
			sourceID,
		)
	}

	t.Log("PASS: Both sources independently validated")
}
