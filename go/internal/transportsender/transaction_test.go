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

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
)

// Test types.

type transactionTestStream struct {
	acknowledgement    *bytes.Reader
	expectedBeforeRead []byte
	failAfter          int
	readCalls          int
	written            bytes.Buffer
}

func (stream *transactionTestStream) Read(value []byte) (int, error) {
	stream.readCalls++
	if stream.expectedBeforeRead != nil &&
		!bytes.Equal(stream.written.Bytes(), stream.expectedBeforeRead) {
		return 0, errors.New("acknowledgement read before exact frame was fully written")
	}
	return stream.acknowledgement.Read(value)
}

func (stream *transactionTestStream) Write(value []byte) (int, error) {
	if stream.failAfter >= 0 {
		remaining := stream.failAfter - stream.written.Len()
		if remaining <= 0 {
			return 0, errors.New("forced transport write failure")
		}
		if len(value) > remaining {
			written, _ := stream.written.Write(value[:remaining])
			return written, errors.New("forced transport write failure")
		}
	}
	return stream.written.Write(value)
}

// Tests.

func TestSendAndRetirePreparedFrameDurableDuplicate(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)
	frame := readTransactionFile(t, outbound.FramePath)
	acknowledgement := acknowledgementForSentFrame(
		t,
		outbound.Sent,
		transportack.OutcomeDurableDuplicate,
	)
	stream := newTransactionTestStream(
		encodeAcknowledgement(t, acknowledgement),
		frame,
	)

	result, err := SendAndRetirePreparedFrame(
		stream,
		outbound,
		fixture.config.ManifestPath,
	)
	if err != nil {
		t.Fatalf("SendAndRetirePreparedFrame() error = %v", err)
	}
	if !bytes.Equal(stream.written.Bytes(), frame) {
		t.Fatal("transport stream did not receive the exact staged frame")
	}
	if result.Retirement.Disposition != RetirementDispositionComplete {
		t.Fatalf(
			"retirement disposition = %q, want %q",
			result.Retirement.Disposition,
			RetirementDispositionComplete,
		)
	}
	got, err := result.Authorization.Acknowledgement()
	if err != nil {
		t.Fatalf("Authorization.Acknowledgement() error = %v", err)
	}
	if got.Outcome != transportack.OutcomeDurableDuplicate {
		t.Fatalf(
			"acknowledgement outcome = %q, want %q",
			got.Outcome,
			transportack.OutcomeDurableDuplicate,
		)
	}
	assertTransactionSpoolRetired(t, fixture.config.ManifestPath, outbound.Sent.Descriptor.BatchID)
	if _, err := os.Stat(outbound.FramePath); err != nil {
		t.Fatalf("durable staged frame was removed by transaction: %v", err)
	}
}

func TestSendAndRetirePreparedFrameDurableNew(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)
	frame := readTransactionFile(t, outbound.FramePath)
	acknowledgement := acknowledgementForSentFrame(
		t,
		outbound.Sent,
		transportack.OutcomeDurableNew,
	)
	stream := newTransactionTestStream(
		encodeAcknowledgement(t, acknowledgement),
		frame,
	)

	result, err := SendAndRetirePreparedFrame(
		stream,
		outbound,
		fixture.config.ManifestPath,
	)
	if err != nil {
		t.Fatalf("SendAndRetirePreparedFrame() error = %v", err)
	}
	if stream.readCalls == 0 {
		t.Fatal("transaction never read the durable acknowledgement")
	}
	if result.Sent != outbound.Sent {
		t.Fatalf("transaction sent facts = %#v, want %#v", result.Sent, outbound.Sent)
	}
	assertTransactionSpoolRetired(t, fixture.config.ManifestPath, outbound.Sent.Descriptor.BatchID)
}

func TestSendAndRetirePreparedFrameDoesNotRetireAfterAcknowledgementMismatch(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)
	frame := readTransactionFile(t, outbound.FramePath)
	acknowledgement := acknowledgementForSentFrame(
		t,
		outbound.Sent,
		transportack.OutcomeDurableNew,
	)
	acknowledgement.FrameSHA256 = strings.Repeat("0", 64)
	stream := newTransactionTestStream(
		encodeAcknowledgement(t, acknowledgement),
		frame,
	)

	result, err := SendAndRetirePreparedFrame(
		stream,
		outbound,
		fixture.config.ManifestPath,
	)
	if err == nil {
		t.Fatal("SendAndRetirePreparedFrame() error = nil, want acknowledgement mismatch")
	}
	if !strings.Contains(err.Error(), "frame SHA-256") {
		t.Fatalf("transaction error = %q, want frame SHA-256 mismatch", err)
	}
	if _, authErr := result.Authorization.Acknowledgement(); authErr == nil {
		t.Fatal("acknowledgement mismatch produced retirement authorization")
	}
	assertTransactionSpoolPresent(t, fixture.config.ManifestPath, outbound.Sent.Descriptor.BatchID)
}

func TestSendAndRetirePreparedFrameDoesNotReadAcknowledgementAfterWriteFailure(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)
	frame := readTransactionFile(t, outbound.FramePath)
	acknowledgement := acknowledgementForSentFrame(
		t,
		outbound.Sent,
		transportack.OutcomeDurableNew,
	)
	stream := newTransactionTestStream(
		encodeAcknowledgement(t, acknowledgement),
		nil,
	)
	stream.failAfter = len(frame) / 2

	_, err := SendAndRetirePreparedFrame(
		stream,
		outbound,
		fixture.config.ManifestPath,
	)
	if err == nil {
		t.Fatal("SendAndRetirePreparedFrame() error = nil, want write failure")
	}
	if !strings.Contains(err.Error(), "forced transport write failure") {
		t.Fatalf("transaction error = %q, want forced write failure", err)
	}
	if stream.readCalls != 0 {
		t.Fatalf("acknowledgement reads = %d after frame write failure, want 0", stream.readCalls)
	}
	assertTransactionSpoolPresent(t, fixture.config.ManifestPath, outbound.Sent.Descriptor.BatchID)
}

func TestSendAndRetirePreparedFrameRejectsTamperedStageBeforeNetworkUse(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)
	frame := readTransactionFile(t, outbound.FramePath)
	frame[0] ^= 0xff
	if err := os.Chmod(outbound.FramePath, 0o600); err != nil {
		t.Fatalf("os.Chmod() writable error = %v", err)
	}
	if err := os.WriteFile(outbound.FramePath, frame, 0o600); err != nil {
		t.Fatalf("os.WriteFile() tampered stage error = %v", err)
	}
	if err := os.Chmod(outbound.FramePath, 0o400); err != nil {
		t.Fatalf("os.Chmod() read-only error = %v", err)
	}

	acknowledgement := acknowledgementForSentFrame(
		t,
		outbound.Sent,
		transportack.OutcomeDurableNew,
	)
	stream := newTransactionTestStream(encodeAcknowledgement(t, acknowledgement), nil)

	_, err := SendAndRetirePreparedFrame(
		stream,
		outbound,
		fixture.config.ManifestPath,
	)
	if err == nil {
		t.Fatal("SendAndRetirePreparedFrame() error = nil, want staged-frame rejection")
	}
	if stream.written.Len() != 0 || stream.readCalls != 0 {
		t.Fatalf(
			"network used before staged-frame rejection: wrote=%d readCalls=%d",
			stream.written.Len(),
			stream.readCalls,
		)
	}
	assertTransactionSpoolPresent(t, fixture.config.ManifestPath, outbound.Sent.Descriptor.BatchID)
}

func TestSendAndRetirePreparedFrameReturnsAuthorizationWhenLocalRetirementFails(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)
	frame := readTransactionFile(t, outbound.FramePath)
	manifest := readTransactionFile(t, fixture.config.ManifestPath)
	manifest[0] ^= 0x01
	if err := os.WriteFile(fixture.config.ManifestPath, manifest, 0o600); err != nil {
		t.Fatalf("os.WriteFile() tampered manifest error = %v", err)
	}

	acknowledgement := acknowledgementForSentFrame(
		t,
		outbound.Sent,
		transportack.OutcomeDurableNew,
	)
	stream := newTransactionTestStream(
		encodeAcknowledgement(t, acknowledgement),
		frame,
	)

	result, err := SendAndRetirePreparedFrame(
		stream,
		outbound,
		fixture.config.ManifestPath,
	)
	if err == nil {
		t.Fatal("SendAndRetirePreparedFrame() error = nil, want local retirement failure")
	}
	if !strings.Contains(err.Error(), "manifest SHA-256") {
		t.Fatalf("transaction error = %q, want manifest SHA-256 mismatch", err)
	}
	got, authErr := result.Authorization.Acknowledgement()
	if authErr != nil {
		t.Fatalf("durable acknowledgement authorization was lost: %v", authErr)
	}
	if got != acknowledgement {
		t.Fatalf("authorization acknowledgement = %#v, want %#v", got, acknowledgement)
	}
	assertTransactionSpoolPresent(t, fixture.config.ManifestPath, outbound.Sent.Descriptor.BatchID)
}

func TestSendAndRetirePreparedFrameValidatesBeforeNetworkUse(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)
	acknowledgement := acknowledgementForSentFrame(
		t,
		outbound.Sent,
		transportack.OutcomeDurableNew,
	)
	stream := newTransactionTestStream(encodeAcknowledgement(t, acknowledgement), nil)
	outbound.Disposition = OutboundFrameDisposition("UNKNOWN")

	_, err := SendAndRetirePreparedFrame(
		stream,
		outbound,
		fixture.config.ManifestPath,
	)
	if err == nil {
		t.Fatal("SendAndRetirePreparedFrame() error = nil, want disposition rejection")
	}
	if stream.written.Len() != 0 || stream.readCalls != 0 {
		t.Fatalf(
			"network used before transaction validation: wrote=%d readCalls=%d",
			stream.written.Len(),
			stream.readCalls,
		)
	}
}

func TestSendAndRetirePreparedFrameRejectsNilStream(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)

	_, err := SendAndRetirePreparedFrame(nil, outbound, fixture.config.ManifestPath)
	if err == nil || !strings.Contains(err.Error(), "transport stream is required") {
		t.Fatalf("nil-stream error = %v", err)
	}
}

// Test helpers.

func assertTransactionSpoolPresent(t *testing.T, manifestPath string, batchID string) {
	t.Helper()
	dataPath, err := outboundPublishedDataPath(manifestPath, batchID)
	if err != nil {
		t.Fatalf("outboundPublishedDataPath() error = %v", err)
	}
	for _, path := range []string{manifestPath, dataPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected source spool path %q to remain: %v", path, err)
		}
	}
}

func assertTransactionSpoolRetired(t *testing.T, manifestPath string, batchID string) {
	t.Helper()
	dataPath, err := outboundPublishedDataPath(manifestPath, batchID)
	if err != nil {
		t.Fatalf("outboundPublishedDataPath() error = %v", err)
	}
	for _, path := range []string{manifestPath, dataPath} {
		_, err := os.Stat(path)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retired source spool path %q still exists or stat failed: %v", path, err)
		}
	}
}

func newTransactionTestStream(
	acknowledgement []byte,
	expectedBeforeRead []byte,
) *transactionTestStream {
	return &transactionTestStream{
		acknowledgement:    bytes.NewReader(acknowledgement),
		expectedBeforeRead: append([]byte(nil), expectedBeforeRead...),
		failAfter:          -1,
	}
}

func prepareTransactionOutbound(t *testing.T, fixture outboundStageFixture) OutboundFrame {
	t.Helper()
	outbound, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("PrepareOutboundFrame() error = %v", err)
	}
	return outbound
}

func readTransactionFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", path, err)
	}
	return value
}

var _ io.ReadWriter = (*transactionTestStream)(nil)
