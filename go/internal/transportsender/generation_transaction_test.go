// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

type scriptedGenerationStream struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func (stream *scriptedGenerationStream) Read(value []byte) (int, error) {
	return stream.reader.Read(value)
}

func (stream *scriptedGenerationStream) Write(value []byte) (int, error) {
	return stream.writer.Write(value)
}

func TestSendAndRetireTransportGenerationRecorded(t *testing.T) {
	generation := createQueuedTransportGenerationFixture(t, "20260918T150000.000000000Z-aaaaaaaaaaaaaaaa")
	transfer := exactTransportGenerationResult(t, generation)

	offer, err := transportgeneration.OfferFromPublished(generation.Published)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := transportgeneration.NewDecision(offer, true, "")
	if err != nil {
		t.Fatal(err)
	}
	acknowledgement, err := transportgeneration.NewAcknowledgement(
		transportgeneration.AcknowledgementOutcomeRecorded,
		transfer,
	)
	if err != nil {
		t.Fatal(err)
	}

	stream := newScriptedGenerationStream(t, decision, &acknowledgement)

	result, err := SendAndRetireTransportGeneration(stream, generation)
	if err != nil {
		t.Fatal(err)
	}

	if result.Acknowledgement.Outcome != transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatalf("ack outcome = %q", result.Acknowledgement.Outcome)
	}
	if result.Transfer.TransferSHA256 != transfer.TransferSHA256 {
		t.Fatal("transaction transfer identity changed")
	}
	if result.Retirement.Disposition != GenerationRetirementDispositionRetired {
		t.Fatalf("retirement disposition = %q", result.Retirement.Disposition)
	}

	if _, err := os.Lstat(generation.GenerationDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active generation still exists after retirement: %v", err)
	}
	if info, err := os.Lstat(result.Retirement.RetiredPath); err != nil || !info.IsDir() {
		t.Fatalf("retirement tombstone missing or invalid: %v", err)
	}

	next, found, err := NextTransportGeneration(
		filepath.Dir(generation.GenerationDir),
		generation.Published.Signed.Descriptor.SourceID,
	)
	_ = next
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("retired generation remained visible in active generation queue")
	}

	written := bytes.NewReader(stream.writer.Bytes())
	writtenOffer, err := transportgeneration.ReadOffer(written)
	if err != nil {
		t.Fatal(err)
	}
	if writtenOffer.Descriptor != offer.Descriptor {
		t.Fatal("wire offer descriptor changed")
	}
	magic := make([]byte, len(transportgeneration.TransferMagic))
	if _, err := io.ReadFull(written, magic); err != nil {
		t.Fatal(err)
	}
	if string(magic) != transportgeneration.TransferMagic {
		t.Fatalf("post-offer wire magic = %q", string(magic))
	}
}

func TestSendAndRetireTransportGenerationAlreadyRecorded(t *testing.T) {
	generation := createQueuedTransportGenerationFixture(t, "20260918T151000.000000000Z-bbbbbbbbbbbbbbbb")
	transfer := exactTransportGenerationResult(t, generation)
	offer, _ := transportgeneration.OfferFromPublished(generation.Published)
	decision, _ := transportgeneration.NewDecision(offer, true, "")
	acknowledgement, _ := transportgeneration.NewAcknowledgement(
		transportgeneration.AcknowledgementOutcomeAlreadyRecorded,
		transfer,
	)

	result, err := SendAndRetireTransportGeneration(
		newScriptedGenerationStream(t, decision, &acknowledgement),
		generation,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Acknowledgement.Outcome != transportgeneration.AcknowledgementOutcomeAlreadyRecorded {
		t.Fatalf("ack outcome = %q", result.Acknowledgement.Outcome)
	}
	if result.Retirement.Disposition != GenerationRetirementDispositionRetired {
		t.Fatalf("retirement disposition = %q", result.Retirement.Disposition)
	}
}

func TestSendAndRetireTransportGenerationRejectsBeforeTransfer(t *testing.T) {
	generation := createQueuedTransportGenerationFixture(t, "20260918T152000.000000000Z-cccccccccccccccc")
	offer, _ := transportgeneration.OfferFromPublished(generation.Published)
	decision, err := transportgeneration.NewDecision(offer, false, "GENERATION_DISABLED")
	if err != nil {
		t.Fatal(err)
	}

	stream := newScriptedGenerationStream(t, decision, nil)
	if _, err := SendAndRetireTransportGeneration(stream, generation); err == nil {
		t.Fatal("receiver rejection returned nil error")
	}

	assertGenerationStillActive(t, generation)

	written := bytes.NewReader(stream.writer.Bytes())
	if _, err := transportgeneration.ReadOffer(written); err != nil {
		t.Fatal(err)
	}
	trailing, err := io.ReadAll(written)
	if err != nil {
		t.Fatal(err)
	}
	if len(trailing) != 0 {
		t.Fatalf("receiver rejection still sent %d transfer bytes", len(trailing))
	}
}

func TestSendAndRetireTransportGenerationLostAcknowledgementIsRetryable(t *testing.T) {
	generation := createQueuedTransportGenerationFixture(t, "20260918T153000.000000000Z-dddddddddddddddd")
	offer, _ := transportgeneration.OfferFromPublished(generation.Published)
	decision, _ := transportgeneration.NewDecision(offer, true, "")

	stream := newScriptedGenerationStream(t, decision, nil)
	_, err := SendAndRetireTransportGeneration(stream, generation)
	if err == nil {
		t.Fatal("lost acknowledgement returned nil error")
	}
	if !errors.Is(err, ErrRetryableTransport) {
		t.Fatalf("lost acknowledgement error = %v, want ErrRetryableTransport", err)
	}

	assertGenerationStillActive(t, generation)
}

func TestSendAndRetireTransportGenerationMismatchedAcknowledgementDoesNotRetire(t *testing.T) {
	generation := createQueuedTransportGenerationFixture(t, "20260918T154000.000000000Z-eeeeeeeeeeeeeeee")
	transfer := exactTransportGenerationResult(t, generation)
	offer, _ := transportgeneration.OfferFromPublished(generation.Published)
	decision, _ := transportgeneration.NewDecision(offer, true, "")
	acknowledgement, _ := transportgeneration.NewAcknowledgement(
		transportgeneration.AcknowledgementOutcomeRecorded,
		transfer,
	)
	acknowledgement.TransferSHA256 = strings.Repeat("0", 64)

	stream := newScriptedGenerationStream(t, decision, &acknowledgement)
	if _, err := SendAndRetireTransportGeneration(stream, generation); err == nil {
		t.Fatal("mismatched acknowledgement returned nil error")
	}

	assertGenerationStillActive(t, generation)
}

func TestRetireTransportGenerationResumesExistingTombstone(t *testing.T) {
	generation := createQueuedTransportGenerationFixture(t, "20260918T155000.000000000Z-ffffffffffffffff")
	transfer := exactTransportGenerationResult(t, generation)
	acknowledgement, err := transportgeneration.NewAcknowledgement(
		transportgeneration.AcknowledgementOutcomeRecorded,
		transfer,
	)
	if err != nil {
		t.Fatal(err)
	}

	var encoded bytes.Buffer
	if err := transportgeneration.WriteAcknowledgement(&encoded, acknowledgement); err != nil {
		t.Fatal(err)
	}
	authorization, err := VerifyGenerationAcknowledgement(&encoded, transfer)
	if err != nil {
		t.Fatal(err)
	}

	first, err := RetireTransportGeneration(generation, authorization)
	if err != nil {
		t.Fatal(err)
	}
	if first.Disposition != GenerationRetirementDispositionRetired {
		t.Fatalf("first disposition = %q", first.Disposition)
	}

	second, err := RetireTransportGeneration(generation, authorization)
	if err != nil {
		t.Fatal(err)
	}
	if second.Disposition != GenerationRetirementDispositionAlreadyRetired {
		t.Fatalf("second disposition = %q", second.Disposition)
	}
	if second.RetiredPath != first.RetiredPath {
		t.Fatal("retirement tombstone identity changed on resume")
	}
}

func createQueuedTransportGenerationFixture(t *testing.T, generationID string) TransportGeneration {
	t.Helper()

	const sourceID = "iss-fs-01.iss.local"
	stageRoot := t.TempDir()
	key, certificate := testTransportGenerationSigningIdentity(t, sourceID)
	createTransportGenerationFixture(t, stageRoot, sourceID, generationID, key, certificate)

	generation, found, err := NextTransportGeneration(stageRoot, sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("transport generation was not found")
	}
	return generation
}

func exactTransportGenerationResult(t *testing.T, generation TransportGeneration) transportgeneration.TransferResult {
	t.Helper()

	result, err := transportgeneration.WritePublishedGeneration(io.Discard, generation.Published)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func newScriptedGenerationStream(
	t *testing.T,
	decision transportgeneration.Decision,
	acknowledgement *transportgeneration.Acknowledgement,
) *scriptedGenerationStream {
	t.Helper()

	var responses bytes.Buffer
	if err := transportgeneration.WriteDecision(&responses, decision); err != nil {
		t.Fatal(err)
	}
	if acknowledgement != nil {
		if err := transportgeneration.WriteAcknowledgement(&responses, *acknowledgement); err != nil {
			t.Fatal(err)
		}
	}

	return &scriptedGenerationStream{reader: bytes.NewReader(responses.Bytes())}
}

func assertGenerationStillActive(t *testing.T, generation TransportGeneration) {
	t.Helper()

	info, err := os.Lstat(generation.GenerationDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("active generation path is not a directory")
	}
}
