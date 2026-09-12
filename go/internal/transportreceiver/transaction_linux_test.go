// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
)

// Test types.

type custodyGateWriter struct {
	buffer    bytes.Buffer
	checked   bool
	framePath string
	wantFrame []byte
}

func (writer *custodyGateWriter) Write(value []byte) (int, error) {
	if !writer.checked {
		stored, err := os.ReadFile(writer.framePath)
		if err != nil {
			return 0, errors.New(
				"acknowledgement write began before durable custody object was readable",
			)
		}
		if !bytes.Equal(stored, writer.wantFrame) {
			return 0, errors.New(
				"acknowledgement write began before exact frame reached durable custody",
			)
		}
		info, err := os.Stat(writer.framePath)
		if err != nil {
			return 0, err
		}
		if info.Mode().Perm() != 0o400 {
			return 0, errors.New(
				"acknowledgement write began before custody object became read-only",
			)
		}
		writer.checked = true
	}

	return writer.buffer.Write(value)
}

type failingAcknowledgementWriter struct {
	remaining int
}

func (writer *failingAcknowledgementWriter) Write(value []byte) (int, error) {
	if writer.remaining <= 0 {
		return 0, errors.New("forced acknowledgement write failure")
	}
	if len(value) > writer.remaining {
		written := writer.remaining
		writer.remaining = 0
		return written, errors.New("forced acknowledgement write failure")
	}

	writer.remaining -= len(value)
	return len(value), nil
}

// Tests.

func TestAcknowledgementFromCustodyRejectsUnsupportedDisposition(t *testing.T) {
	_, err := acknowledgementFromCustody(DurableCustodyResult{
		Disposition: CustodyDisposition("UNKNOWN"),
	})
	if err == nil {
		t.Fatal("acknowledgementFromCustody() error = nil, want disposition rejection")
	}
	if !strings.Contains(err.Error(), "unsupported FI custody disposition") {
		t.Fatalf(
			"acknowledgementFromCustody() error = %q, want disposition rejection",
			err,
		)
	}
}

func TestReceiveAndAcknowledgeDoesNotAcknowledgeCustodyConflict(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	root := t.TempDir()
	descriptor := fixture.signedBatch.Descriptor
	framePath := filepath.Join(
		root,
		custodyObjectName(descriptor.SourceID, descriptor.BatchID),
	)
	conflicting := []byte("different durable custody bytes")
	if err := os.WriteFile(framePath, conflicting, 0o400); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	var acknowledgement bytes.Buffer

	_, err := ReceiveAndAcknowledge(
		bytes.NewReader(frame),
		&acknowledgement,
		CustodyConfig{
			Intake:  fixture.config,
			RootDir: root,
		},
	)
	if err == nil {
		t.Fatal("ReceiveAndAcknowledge() error = nil, want custody conflict")
	}
	if !errors.Is(err, ErrCustodyConflict) {
		t.Fatalf("ReceiveAndAcknowledge() error = %v, want ErrCustodyConflict", err)
	}
	if acknowledgement.Len() != 0 {
		t.Fatalf(
			"acknowledgement writer received %d bytes for custody conflict",
			acknowledgement.Len(),
		)
	}

	stored, err := os.ReadFile(framePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, conflicting) {
		t.Fatal("conflicting durable custody object was changed")
	}
}

func TestReceiveAndAcknowledgeDuplicateRetry(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	root := t.TempDir()
	config := CustodyConfig{
		Intake:  fixture.config,
		RootDir: root,
	}
	var firstAck bytes.Buffer

	first, err := ReceiveAndAcknowledge(
		bytes.NewReader(frame),
		&firstAck,
		config,
	)
	if err != nil {
		t.Fatalf("first ReceiveAndAcknowledge() error = %v", err)
	}
	if first.Custody.Disposition != CustodyDispositionNew {
		t.Fatalf(
			"first custody disposition = %q, want %q",
			first.Custody.Disposition,
			CustodyDispositionNew,
		)
	}
	if first.Acknowledgement.Outcome != transportack.OutcomeDurableNew {
		t.Fatalf(
			"first acknowledgement outcome = %q, want %q",
			first.Acknowledgement.Outcome,
			transportack.OutcomeDurableNew,
		)
	}

	var retryAck bytes.Buffer
	retry, err := ReceiveAndAcknowledge(
		bytes.NewReader(frame),
		&retryAck,
		config,
	)
	if err != nil {
		t.Fatalf("retry ReceiveAndAcknowledge() error = %v", err)
	}
	if retry.Custody.Disposition != CustodyDispositionDuplicate {
		t.Fatalf(
			"retry custody disposition = %q, want %q",
			retry.Custody.Disposition,
			CustodyDispositionDuplicate,
		)
	}
	if retry.Acknowledgement.Outcome != transportack.OutcomeDurableDuplicate {
		t.Fatalf(
			"retry acknowledgement outcome = %q, want %q",
			retry.Acknowledgement.Outcome,
			transportack.OutcomeDurableDuplicate,
		)
	}
	assertAcknowledgementMatchesCustody(t, retry.Acknowledgement, retry.Custody)

	decoded, err := transportack.ReadAcknowledgement(bytes.NewReader(retryAck.Bytes()))
	if err != nil {
		t.Fatalf("transportack.ReadAcknowledgement() error = %v", err)
	}
	if decoded != retry.Acknowledgement {
		t.Fatalf("decoded acknowledgement = %#v, want %#v", decoded, retry.Acknowledgement)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("custody root contains %d entries after retry, want 1", len(entries))
	}
}

func TestReceiveAndAcknowledgeNewCustodyBeforeAckWrite(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	root := t.TempDir()
	descriptor := fixture.signedBatch.Descriptor
	framePath := filepath.Join(
		root,
		custodyObjectName(descriptor.SourceID, descriptor.BatchID),
	)
	writer := &custodyGateWriter{
		framePath: framePath,
		wantFrame: frame,
	}

	result, err := ReceiveAndAcknowledge(
		bytes.NewReader(frame),
		writer,
		CustodyConfig{
			Intake:  fixture.config,
			RootDir: root,
		},
	)
	if err != nil {
		t.Fatalf("ReceiveAndAcknowledge() error = %v", err)
	}
	if !writer.checked {
		t.Fatal("acknowledgement writer did not verify durable custody ordering")
	}
	if result.Custody.Disposition != CustodyDispositionNew {
		t.Fatalf(
			"custody disposition = %q, want %q",
			result.Custody.Disposition,
			CustodyDispositionNew,
		)
	}
	if result.Acknowledgement.Outcome != transportack.OutcomeDurableNew {
		t.Fatalf(
			"acknowledgement outcome = %q, want %q",
			result.Acknowledgement.Outcome,
			transportack.OutcomeDurableNew,
		)
	}
	assertAcknowledgementMatchesCustody(t, result.Acknowledgement, result.Custody)

	decoded, err := transportack.ReadAcknowledgement(
		bytes.NewReader(writer.buffer.Bytes()),
	)
	if err != nil {
		t.Fatalf("transportack.ReadAcknowledgement() error = %v", err)
	}
	if decoded != result.Acknowledgement {
		t.Fatalf("decoded acknowledgement = %#v, want %#v", decoded, result.Acknowledgement)
	}
}

func TestReceiveAndAcknowledgePreservesCustodyAfterAckWriteFailure(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	root := t.TempDir()
	config := CustodyConfig{
		Intake:  fixture.config,
		RootDir: root,
	}
	writer := &failingAcknowledgementWriter{remaining: 32}

	first, err := ReceiveAndAcknowledge(
		bytes.NewReader(frame),
		writer,
		config,
	)
	if err == nil {
		t.Fatal("ReceiveAndAcknowledge() error = nil, want acknowledgement write failure")
	}
	if !strings.Contains(err.Error(), "forced acknowledgement write failure") {
		t.Fatalf(
			"ReceiveAndAcknowledge() error = %q, want forced write failure",
			err,
		)
	}
	if first.Custody.Disposition != CustodyDispositionNew {
		t.Fatalf(
			"custody disposition after write failure = %q, want %q",
			first.Custody.Disposition,
			CustodyDispositionNew,
		)
	}
	if first.Acknowledgement.Outcome != transportack.OutcomeDurableNew {
		t.Fatalf(
			"acknowledgement outcome after write failure = %q, want %q",
			first.Acknowledgement.Outcome,
			transportack.OutcomeDurableNew,
		)
	}
	stored, err := os.ReadFile(first.Custody.FramePath)
	if err != nil {
		t.Fatalf("read durable custody after acknowledgement failure: %v", err)
	}
	if !bytes.Equal(stored, frame) {
		t.Fatal("durable custody changed after acknowledgement write failure")
	}

	var retryAck bytes.Buffer
	retry, err := ReceiveAndAcknowledge(
		bytes.NewReader(frame),
		&retryAck,
		config,
	)
	if err != nil {
		t.Fatalf("retry ReceiveAndAcknowledge() error = %v", err)
	}
	if retry.Custody.Disposition != CustodyDispositionDuplicate {
		t.Fatalf(
			"retry custody disposition = %q, want %q",
			retry.Custody.Disposition,
			CustodyDispositionDuplicate,
		)
	}
	if retry.Acknowledgement.Outcome != transportack.OutcomeDurableDuplicate {
		t.Fatalf(
			"retry acknowledgement outcome = %q, want %q",
			retry.Acknowledgement.Outcome,
			transportack.OutcomeDurableDuplicate,
		)
	}
}

func TestReceiveAndAcknowledgeRejectsNilAcknowledgementWriterBeforeIntake(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	reader := bytes.NewReader(frame)
	root := t.TempDir()

	_, err := ReceiveAndAcknowledge(
		reader,
		nil,
		CustodyConfig{
			Intake:  fixture.config,
			RootDir: root,
		},
	)
	if err == nil {
		t.Fatal("ReceiveAndAcknowledge() error = nil, want nil-writer rejection")
	}
	if !strings.Contains(err.Error(), "acknowledgement writer is required") {
		t.Fatalf("ReceiveAndAcknowledge() error = %q, want nil-writer rejection", err)
	}
	if reader.Len() != len(frame) {
		t.Fatalf("reader consumed %d bytes before nil-writer rejection", len(frame)-reader.Len())
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("custody root contains %d entries after nil-writer rejection", len(entries))
	}
}

func TestReceiveAndAcknowledgeRejectsNilReader(t *testing.T) {
	var acknowledgement bytes.Buffer

	_, err := ReceiveAndAcknowledge(
		nil,
		&acknowledgement,
		CustodyConfig{},
	)
	if err == nil {
		t.Fatal("ReceiveAndAcknowledge() error = nil, want nil-reader rejection")
	}
	if !strings.Contains(err.Error(), "batch reader is required") {
		t.Fatalf("ReceiveAndAcknowledge() error = %q, want nil-reader rejection", err)
	}
	if acknowledgement.Len() != 0 {
		t.Fatalf("acknowledgement writer received %d bytes", acknowledgement.Len())
	}
}

// Test helpers.

func assertAcknowledgementMatchesCustody(
	t *testing.T,
	acknowledgement transportack.Acknowledgement,
	custody DurableCustodyResult,
) {
	t.Helper()

	if acknowledgement.SourceID != custody.SourceID {
		t.Fatalf("acknowledgement SourceID = %q, want %q", acknowledgement.SourceID, custody.SourceID)
	}
	if acknowledgement.BatchID != custody.BatchID {
		t.Fatalf("acknowledgement BatchID = %q, want %q", acknowledgement.BatchID, custody.BatchID)
	}
	if acknowledgement.DataBytes != custody.DataBytes {
		t.Fatalf("acknowledgement DataBytes = %d, want %d", acknowledgement.DataBytes, custody.DataBytes)
	}
	if acknowledgement.DataSHA256 != custody.DataSHA256 {
		t.Fatalf("acknowledgement DataSHA256 = %q, want %q", acknowledgement.DataSHA256, custody.DataSHA256)
	}
	if acknowledgement.ManifestSHA256 != custody.ManifestSHA256 {
		t.Fatalf(
			"acknowledgement ManifestSHA256 = %q, want %q",
			acknowledgement.ManifestSHA256,
			custody.ManifestSHA256,
		)
	}
	if acknowledgement.FrameBytes != custody.FrameBytes {
		t.Fatalf("acknowledgement FrameBytes = %d, want %d", acknowledgement.FrameBytes, custody.FrameBytes)
	}
	if acknowledgement.FrameSHA256 != custody.FrameSHA256 {
		t.Fatalf("acknowledgement FrameSHA256 = %q, want %q", acknowledgement.FrameSHA256, custody.FrameSHA256)
	}
}
