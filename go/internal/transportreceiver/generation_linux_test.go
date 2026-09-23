// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestReceiveGenerationAndAcknowledgeNewThenAlreadyRecorded(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)

	var firstOutput bytes.Buffer
	first, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		&firstOutput,
		fixture.config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if first.Custody.Disposition != transportgeneration.CustodyDispositionNew {
		t.Fatalf(
			"first custody disposition = %q, want NEW",
			first.Custody.Disposition,
		)
	}

	if first.Recorder.Disposition != generationrecorder.RecordedDispositionNew {
		t.Fatalf(
			"first recorder disposition = %q, want NEW",
			first.Recorder.Disposition,
		)
	}

	if first.ReadyWarning != "" || first.ReadyPath == "" {
		t.Fatalf(
			"first ready state path=%q warning=%q, want published without warning",
			first.ReadyPath,
			first.ReadyWarning,
		)
	}

	assertGenerationReadyCount(t, fixture.config.ReadyRoot, 1)

	decision, acknowledgement := readGenerationTransactionOutput(
		t,
		firstOutput.Bytes(),
	)

	if !decision.Accepted || decision.Reason != "" {
		t.Fatalf("first decision = %#v, want accepted", decision)
	}

	if acknowledgement.Outcome != transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatalf(
			"first acknowledgement outcome = %q, want recorded",
			acknowledgement.Outcome,
		)
	}

	if err := transportgeneration.AcknowledgementMatches(
		acknowledgement,
		fixture.transfer,
	); err != nil {
		t.Fatal(err)
	}

	var secondOutput bytes.Buffer
	second, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		&secondOutput,
		fixture.config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if second.Custody.Disposition != transportgeneration.CustodyDispositionDuplicate {
		t.Fatalf(
			"second custody disposition = %q, want DUPLICATE",
			second.Custody.Disposition,
		)
	}

	if second.Recorder.Disposition != generationrecorder.RecordedDispositionAlreadyRecorded {
		t.Fatalf(
			"second recorder disposition = %q, want ALREADY_RECORDED",
			second.Recorder.Disposition,
		)
	}

	if second.ReadyWarning != "" || second.ReadyPath == "" {
		t.Fatalf(
			"second ready state path=%q warning=%q, want idempotent publication without warning",
			second.ReadyPath,
			second.ReadyWarning,
		)
	}

	assertGenerationReadyCount(t, fixture.config.ReadyRoot, 1)

	_, acknowledgement = readGenerationTransactionOutput(
		t,
		secondOutput.Bytes(),
	)

	if acknowledgement.Outcome != transportgeneration.AcknowledgementOutcomeAlreadyRecorded {
		t.Fatalf(
			"second acknowledgement outcome = %q, want already_recorded",
			acknowledgement.Outcome,
		)
	}

	if err := transportgeneration.AcknowledgementMatches(
		acknowledgement,
		fixture.transfer,
	); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveGenerationAndAcknowledgeRecorderFailureWritesNoAcknowledgement(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, true)

	var output bytes.Buffer
	result, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		&output,
		fixture.config,
	)
	if err == nil {
		t.Fatal("semantically invalid generation was acknowledged")
	}

	if result.Custody.CustodyPath == "" {
		t.Fatal("semantic failure occurred before durable custody")
	}

	if result.Recorder.ReceiptPath != "" {
		t.Fatal("semantic failure published recorder receipt")
	}

	reader := bytes.NewReader(output.Bytes())
	decision, readErr := transportgeneration.ReadDecision(reader)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if !decision.Accepted {
		t.Fatal("valid transport offer was rejected before semantic validation")
	}

	if reader.Len() != 0 {
		t.Fatalf(
			"semantic failure wrote %d bytes after accepted decision; want no acknowledgement",
			reader.Len(),
		)
	}

	assertGenerationTransactionRecorderRootEmpty(
		t,
		fixture.config.Recorder.RootDir,
	)
	assertGenerationReadyCount(t, fixture.config.ReadyRoot, 0)
}

func TestReceiveGenerationAndAcknowledgeRejectsSourceBeforeTransfer(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)

	fixture.config.Custody.Receive.Source.SourceID = "different-source.example"

	var input bytes.Buffer
	if err := transportgeneration.WriteOffer(&input, fixture.offer); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	result, err := ReceiveGenerationAndAcknowledge(
		&input,
		&output,
		fixture.config,
	)
	if err == nil || !errors.Is(err, ErrGenerationOfferRejected) {
		t.Fatalf("source mismatch error = %v, want offer rejection", err)
	}

	if result.Custody.CustodyPath != "" || result.Recorder.ReceiptPath != "" {
		t.Fatal("rejected source crossed custody or recorder boundary")
	}

	reader := bytes.NewReader(output.Bytes())
	decision, readErr := transportgeneration.ReadDecision(reader)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if decision.Accepted || decision.Reason != "SOURCE_ID_MISMATCH" {
		t.Fatalf("source mismatch decision = %#v", decision)
	}

	if reader.Len() != 0 {
		t.Fatal("source rejection wrote bytes beyond decision")
	}

	assertGenerationTransactionDirectoryEmpty(
		t,
		fixture.config.Custody.RootDir,
	)
	assertGenerationTransactionRecorderRootEmpty(
		t,
		fixture.config.Recorder.RootDir,
	)
	assertGenerationReadyCount(t, fixture.config.ReadyRoot, 0)
}

func TestReceiveGenerationAndAcknowledgeRejectsOfferAboveCanonicalLimit(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)

	if fixture.offer.Descriptor.CanonicalBytes < 2 {
		t.Fatal("fixture canonical generation unexpectedly too small")
	}

	fixture.config.Custody.Receive.MaxCanonicalBytes =
		fixture.offer.Descriptor.CanonicalBytes - 1

	var input bytes.Buffer
	if err := transportgeneration.WriteOffer(&input, fixture.offer); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	_, err := ReceiveGenerationAndAcknowledge(
		&input,
		&output,
		fixture.config,
	)
	if err == nil || !errors.Is(err, ErrGenerationOfferRejected) {
		t.Fatalf("oversized offer error = %v, want offer rejection", err)
	}

	reader := bytes.NewReader(output.Bytes())
	decision, readErr := transportgeneration.ReadDecision(reader)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if decision.Accepted || decision.Reason != "CANONICAL_BYTES_EXCEED_LIMIT" {
		t.Fatalf("canonical-limit decision = %#v", decision)
	}

	if reader.Len() != 0 {
		t.Fatal("canonical-limit rejection wrote bytes beyond decision")
	}
}

func TestReceiveGenerationAndAcknowledgeReadyFailureStillAcknowledges(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)
	fixture.config.ReadyRoot = filepath.Join(t.TempDir(), "missing")

	var output bytes.Buffer
	result, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		&output,
		fixture.config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.ReadyPath != "" || result.ReadyWarning == "" {
		t.Fatalf(
			"ready failure path=%q warning=%q, want warning-only publication failure",
			result.ReadyPath,
			result.ReadyWarning,
		)
	}
	if result.Recorder.Disposition != generationrecorder.RecordedDispositionNew {
		t.Fatalf(
			"recorder disposition = %q, want NEW",
			result.Recorder.Disposition,
		)
	}

	_, acknowledgement := readGenerationTransactionOutput(
		t,
		output.Bytes(),
	)
	if acknowledgement.Outcome !=
		transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatalf(
			"ready publication failure acknowledgement = %q, want recorded",
			acknowledgement.Outcome,
		)
	}
}

func TestPublishGenerationReadyFailureIsWarningOnly(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)

	recorded := generationrecorder.DurableResult{
		ReceiptPath: filepath.Join(
			fixture.config.Recorder.RootDir,
			"generation-test.record.json",
		),
	}

	path, warning := publishGenerationReady(
		filepath.Join(t.TempDir(), "missing"),
		recorded,
	)
	if path != "" || warning == "" {
		t.Fatalf(
			"ready failure path=%q warning=%q, want empty path and warning",
			path,
			warning,
		)
	}
}

func TestReceiveGenerationAndAcknowledgeWriteFailurePreservesRecordedState(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)

	accepted, err := transportgeneration.NewDecision(
		fixture.offer,
		true,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	var encodedDecision bytes.Buffer
	if err := transportgeneration.WriteDecision(
		&encodedDecision,
		accepted,
	); err != nil {
		t.Fatal(err)
	}

	writer := &generationFailAfterWriter{
		remaining: encodedDecision.Len(),
	}

	first, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		writer,
		fixture.config,
	)
	if err == nil {
		t.Fatal("forced acknowledgement write failure returned success")
	}

	if first.Custody.CustodyPath == "" || first.Recorder.ReceiptPath == "" {
		t.Fatal("acknowledgement write failure lost durable transaction state")
	}

	if first.Acknowledgement.Outcome != transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatalf(
			"failed-write acknowledgement outcome = %q, want recorded",
			first.Acknowledgement.Outcome,
		)
	}

	if _, statErr := os.Stat(first.Custody.CustodyPath); statErr != nil {
		t.Fatalf("durable custody missing after acknowledgement failure: %v", statErr)
	}

	if _, statErr := os.Stat(first.Recorder.ReceiptPath); statErr != nil {
		t.Fatalf("recorder receipt missing after acknowledgement failure: %v", statErr)
	}

	var retryOutput bytes.Buffer
	retry, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		&retryOutput,
		fixture.config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if retry.Custody.Disposition != transportgeneration.CustodyDispositionDuplicate ||
		retry.Recorder.Disposition != generationrecorder.RecordedDispositionAlreadyRecorded ||
		retry.Acknowledgement.Outcome != transportgeneration.AcknowledgementOutcomeAlreadyRecorded {
		t.Fatalf(
			"retry dispositions = custody %q recorder %q ack %q",
			retry.Custody.Disposition,
			retry.Recorder.Disposition,
			retry.Acknowledgement.Outcome,
		)
	}
}

type generationTransactionFixture struct {
	config           GenerationReceiveConfig
	offer            transportgeneration.Offer
	transactionBytes []byte
	transfer         transportgeneration.TransferResult
}

func newGenerationTransactionFixture(
	t *testing.T,
	invalidManifest bool,
) generationTransactionFixture {
	t.Helper()

	const sourceID = "iss-fs-01.iss.local"

	root, issuer, leaf, leafKey, crl, source :=
		newGenerationTransactionTrust(t, sourceID)

	frozen := filepath.Join(t.TempDir(), "frozen")
	if err := os.Mkdir(frozen, 0o700); err != nil {
		t.Fatal(err)
	}

	overrideSHA256 := ""
	if invalidManifest {
		overrideSHA256 = strings.Repeat("0", 64)
	}

	writeGenerationTransactionBatch(
		t,
		frozen,
		"20260918T180000.000000000Z-0011223344556677",
		[]byte("{\"record\":1}\n{\"record\":2}\n"),
		overrideSHA256,
	)

	sealedRoot := filepath.Join(t.TempDir(), "sealed")
	if err := os.Mkdir(sealedRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	published, err := transportgeneration.CreateSealedGeneration(
		context.Background(),
		transportgeneration.CreateConfig{
			BatchSigner:             leafKey,
			BatchSigningCertificate: leaf,
			FrozenDir:               frozen,
			GenerationID:            "20260918T180500.000000000Z-0123456789abcdef",
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

	var transferBytes bytes.Buffer
	transfer, err := transportgeneration.WritePublishedGeneration(
		&transferBytes,
		published,
	)
	if err != nil {
		t.Fatal(err)
	}

	var transaction bytes.Buffer
	if err := transportgeneration.WriteOffer(&transaction, offer); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Write(transferBytes.Bytes()); err != nil {
		t.Fatal(err)
	}

	custodyRoot := filepath.Join(t.TempDir(), "custody")
	if err := os.Mkdir(custodyRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	recordedRoot := filepath.Join(t.TempDir(), "recorded")
	if err := os.Mkdir(recordedRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	readyRoot := filepath.Join(t.TempDir(), "ready")
	if err := os.Mkdir(readyRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	return generationTransactionFixture{
		config: GenerationReceiveConfig{
			Custody: transportgeneration.CustodyConfig{
				Receive: transportgeneration.ReceiveConfig{
					BatchCRL:          crl,
					BatchIssuer:       issuer,
					CurrentTime:       time.Now(),
					MaxCanonicalBytes: 64 << 20,
					MaxEncodedBytes:   64 << 20,
					Root:              root,
					Source:            source,
				},
				RootDir: custodyRoot,
			},
			ReadyRoot: readyRoot,
			Recorder: generationrecorder.DurableConfig{
				RootDir: recordedRoot,
				Semantic: generationrecorder.Config{
					MaxManifestBytes: 1 << 20,
				},
			},
		},
		offer:            offer,
		transactionBytes: transaction.Bytes(),
		transfer:         transfer,
	}
}

func readGenerationTransactionOutput(
	t *testing.T,
	raw []byte,
) (
	transportgeneration.Decision,
	transportgeneration.Acknowledgement,
) {
	t.Helper()

	reader := bytes.NewReader(raw)
	decision, err := transportgeneration.ReadDecision(reader)
	if err != nil {
		t.Fatal(err)
	}

	acknowledgement, err := transportgeneration.ReadAcknowledgement(reader)
	if err != nil {
		t.Fatal(err)
	}

	if reader.Len() != 0 {
		t.Fatalf("transaction output contains %d trailing bytes", reader.Len())
	}

	return decision, acknowledgement
}

func writeGenerationTransactionBatch(
	t *testing.T,
	dir string,
	batchID string,
	data []byte,
	overrideSHA256 string,
) {
	t.Helper()

	digest := sha256.Sum256(data)
	dataSHA256 := hex.EncodeToString(digest[:])
	if overrideSHA256 != "" {
		dataSHA256 = overrideSHA256
	}

	dataName := "batch-" + batchID + ".jsonl"
	if err := os.WriteFile(
		filepath.Join(dir, dataName),
		data,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	manifest := spool.Manifest{
		Version:         spool.ManifestVersion,
		BatchID:         batchID,
		TargetBatchSize: 262144,
		RecordCount:     bytes.Count(data, []byte{'\n'}),
		DataBytes:       int64(len(data)),
		DataSHA256:      dataSHA256,
		DataFile:        dataName,
		Collector: spool.CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: strings.Repeat("1a", 32),
		},
		CreatedAt:   "2026-09-18T18:00:00Z",
		CompletedAt: "2026-09-18T18:00:01Z",
	}

	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')

	if err := os.WriteFile(
		filepath.Join(dir, "batch-"+batchID+".manifest.json"),
		raw,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func newGenerationTransactionTrust(
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
		SerialNumber: big.NewInt(5001),
		Subject: pkix.Name{
			CommonName: "FI Generation Transaction Root Test",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{21, 22, 23, 24},
	}

	root := createGenerationTransactionCertificate(
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
		SerialNumber: big.NewInt(5002),
		Subject: pkix.Name{
			CommonName: "FI Generation Transaction Batch Signing Test CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{25, 26, 27, 28},
	}

	issuer := createGenerationTransactionCertificate(
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
		SerialNumber: big.NewInt(5003),
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

	leaf := createGenerationTransactionCertificate(
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
			CertificateSHA256:  generationTransactionCertificateSHA256(leaf),
			CommonName:         sourceID,
			IssuingCASHA256:    generationTransactionCertificateSHA256(issuer),
			OrganizationalUnit: transporttrust.BatchSigningOrganizationalUnit,
		},
	}

	return root, issuer, leaf, leafKey, crl, source
}

func createGenerationTransactionCertificate(
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

func generationTransactionCertificateSHA256(
	certificate *x509.Certificate,
) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}

func assertGenerationTransactionDirectoryEmpty(
	t *testing.T,
	path string,
) {
	t.Helper()

	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 0 {
		t.Fatalf("directory %s contains %d entries, want empty", path, len(entries))
	}
}

func assertGenerationReadyCount(
	t *testing.T,
	root string,
	want int,
) {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != want {
		t.Fatalf(
			"generation ready entry count = %d, want %d",
			len(entries),
			want,
		)
	}
}

func assertGenerationTransactionRecorderRootEmpty(
	t *testing.T,
	path string,
) {
	t.Helper()
	assertGenerationTransactionDirectoryEmpty(t, path)
}

type generationFailAfterWriter struct {
	remaining int
	written   bytes.Buffer
}

func (writer *generationFailAfterWriter) Write(value []byte) (int, error) {
	if writer.remaining == 0 {
		return 0, errors.New("forced generation acknowledgement write failure")
	}

	if len(value) <= writer.remaining {
		n, _ := writer.written.Write(value)
		writer.remaining -= n
		return n, nil
	}

	n, _ := writer.written.Write(value[:writer.remaining])
	writer.remaining = 0
	return n, errors.New("forced generation acknowledgement write failure")
}

var _ io.Writer = (*generationFailAfterWriter)(nil)
