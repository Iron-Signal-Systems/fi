// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package transportreceiver

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func provisionReceiverSourceNamespace(
	t *testing.T,
	root string,
	sourceID string,
) string {
	t.Helper()

	parent := filepath.Join(root, "sources")

	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}

	sourceRoot, err := generationrecorder.RecordedSourceDirectory(
		root,
		sourceID,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(sourceRoot, 0700); err != nil {
		t.Fatal(err)
	}

	return sourceRoot
}

func TestM1ReceiverNamespacedGenerationTransactionAndRestart(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)

	sourceID := fixture.config.Custody.Receive.Source.SourceID

	sourceRoot := provisionReceiverSourceNamespace(
		t,
		fixture.config.Recorder.RootDir,
		sourceID,
	)

	listener := listenerGenerationConfigFromFixture(t, fixture)
	listener.GenerationSourceNamespaces = true

	config := generationReceiveConfigFromListener(
		listener,
		fixture.config.Custody.Receive.CurrentTime,
	)

	if !config.Recorder.SourceNamespaces {
		t.Fatal("receiver did not propagate source namespace setting")
	}

	var firstOutput bytes.Buffer

	first, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		&firstOutput,
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if first.Recorder.Disposition !=
		generationrecorder.RecordedDispositionNew {
		t.Fatalf(
			"first recorder disposition=%q",
			first.Recorder.Disposition,
		)
	}

	if first.ReadyWarning != "" || first.ReadyPath == "" {
		t.Fatalf(
			"READY publication path=%q warning=%q",
			first.ReadyPath,
			first.ReadyWarning,
		)
	}

	expected := filepath.Join(
		sourceRoot,
		generationrecorder.RecordedReceiptObjectName(
			sourceID,
			fixture.transfer.Descriptor.GenerationID,
		),
	)

	if first.Recorder.ReceiptPath != expected {
		t.Fatalf(
			"receipt=%q want=%q",
			first.Recorder.ReceiptPath,
			expected,
		)
	}

	info, err := os.Lstat(expected)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0400 {
		t.Fatal("namespaced receipt is not immutable 0400")
	}

	flat := filepath.Join(
		fixture.config.Recorder.RootDir,
		filepath.Base(expected),
	)

	if _, err := os.Lstat(flat); !os.IsNotExist(err) {
		t.Fatalf("unexpected flat receipt publication: %v", err)
	}

	decision, ack := readGenerationTransactionOutput(
		t,
		firstOutput.Bytes(),
	)

	if !decision.Accepted ||
		ack.Outcome !=
			transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatal("namespaced generation was not acknowledged")
	}

	var secondOutput bytes.Buffer

	second, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		&secondOutput,
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if second.Recorder.Disposition !=
		generationrecorder.RecordedDispositionAlreadyRecorded {
		t.Fatal("exact retry did not reuse immutable receipt")
	}

	if second.Recorder.ReceiptSHA256 !=
		first.Recorder.ReceiptSHA256 {
		t.Fatal("receipt digest changed on retry")
	}

	_, duplicateAck := readGenerationTransactionOutput(
		t,
		secondOutput.Bytes(),
	)

	if duplicateAck.Outcome !=
		transportgeneration.AcknowledgementOutcomeAlreadyRecorded {
		t.Fatal("duplicate generation acknowledgement incorrect")
	}

	recovered, err := RecoverGenerationStartup(
		listener,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}

	if recovered.Discovered != 1 ||
		recovered.AlreadyRecorded != 1 ||
		recovered.RecordedNew != 0 {
		t.Fatalf(
			"namespaced restart recovery=%+v",
			recovered,
		)
	}

	t.Log("PASS: Receiver published immutable namespaced receipt")
	t.Log("PASS: Generation acknowledged after durable recording")
	t.Log("PASS: Exact retry reused receipt")
	t.Log("PASS: Startup recovery preserved namespaced identity")
}

func TestM1ReceiverNamespacedMissingDirectoryFailsClosed(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)

	listener := listenerGenerationConfigFromFixture(t, fixture)
	listener.GenerationSourceNamespaces = true

	config := generationReceiveConfigFromListener(
		listener,
		fixture.config.Custody.Receive.CurrentTime,
	)

	var output bytes.Buffer

	result, err := ReceiveGenerationAndAcknowledge(
		bytes.NewReader(fixture.transactionBytes),
		&output,
		config,
	)

	if err == nil {
		t.Fatal("missing authoritative namespace accepted")
	}

	reader := bytes.NewReader(output.Bytes())

	decision, err := transportgeneration.ReadDecision(reader)
	if err != nil {
		t.Fatal(err)
	}

	if !decision.Accepted {
		t.Fatal("test generation offer was unexpectedly rejected")
	}

	if reader.Len() != 0 {
		t.Fatal("receiver emitted data after failed recording")
	}

	if result.Custody.CustodyPath == "" {
		t.Fatal("failed recording did not retain custody identity")
	}

	if _, err := os.Lstat(result.Custody.CustodyPath); err != nil {
		t.Fatal("durable custody was not retained")
	}

	entries, err := os.ReadDir(
		fixture.config.Recorder.RootDir,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 0 {
		t.Fatal("failed recording published an unexpected receipt")
	}

	t.Log("PASS: Missing namespace blocks acknowledgement")
	t.Log("PASS: Durable custody retained for recovery")
}

func TestM1ReceiverNamespaceRequiresGenerationEnablement(
	t *testing.T,
) {
	config := validTestConfig(t)

	config.GenerationSourceNamespaces = true

	if err := validateGenerationListenerConfig(config); err == nil {
		t.Fatal("namespaced mode accepted without generation enablement")
	}
}
