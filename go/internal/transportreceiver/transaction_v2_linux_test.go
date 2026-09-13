// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
)

func TestReceiveAndAcknowledgeV2DuplicateRetry(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)
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
		t.Fatalf("first custody disposition = %q, want NEW", first.Custody.Disposition)
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
		t.Fatalf("retry custody disposition = %q, want DUPLICATE", retry.Custody.Disposition)
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
}

func TestReceiveAndAcknowledgeV2NewCustodyBeforeAckWrite(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)
	root := t.TempDir()
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
		t.Fatal("acknowledgement writer did not verify FIWB0002 durable custody ordering")
	}
	if result.Custody.Disposition != CustodyDispositionNew {
		t.Fatalf("custody disposition = %q, want NEW", result.Custody.Disposition)
	}
	if result.Acknowledgement.Outcome != transportack.OutcomeDurableNew {
		t.Fatalf(
			"acknowledgement outcome = %q, want %q",
			result.Acknowledgement.Outcome,
			transportack.OutcomeDurableNew,
		)
	}
	assertAcknowledgementMatchesCustody(t, result.Acknowledgement, result.Custody)

	stored, err := os.ReadFile(result.Custody.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, frame) {
		t.Fatal("acknowledgement followed custody that was not the exact FIWB0002 frame")
	}
}

func TestReceiveAndAcknowledgeV2PreservesCustodyAfterAckWriteFailure(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	encoded := encodeIntakeTestZstd(t, fixture.data)
	descriptor := intakeTestDescriptorV2(fixture, fixture.data, encoded)
	frame := encodeIntakeTestFrameV2(t, fixture, descriptor, encoded)
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
		t.Fatalf("custody disposition after write failure = %q, want NEW", first.Custody.Disposition)
	}

	stored, err := os.ReadFile(first.Custody.FramePath)
	if err != nil {
		t.Fatalf("read durable FIWB0002 custody after acknowledgement failure: %v", err)
	}
	if !bytes.Equal(stored, frame) {
		t.Fatal("durable FIWB0002 custody changed after acknowledgement write failure")
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
		t.Fatalf("retry custody disposition = %q, want DUPLICATE", retry.Custody.Disposition)
	}
	if retry.Acknowledgement.Outcome != transportack.OutcomeDurableDuplicate {
		t.Fatalf(
			"retry acknowledgement outcome = %q, want %q",
			retry.Acknowledgement.Outcome,
			transportack.OutcomeDurableDuplicate,
		)
	}
}
