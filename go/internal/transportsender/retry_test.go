// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestRetryableTransportErrorClassification(t *testing.T) {
	if retryableTransportWriteError(io.EOF) {
		t.Fatal("retryableTransportWriteError(io.EOF) = true, want false")
	}
	if !retryableAcknowledgementReadError(io.EOF) {
		t.Fatal("retryableAcknowledgementReadError(io.EOF) = false, want true")
	}
	if !retryableTransportWriteError(context.DeadlineExceeded) {
		t.Fatal("retryableTransportWriteError(context deadline) = false, want true")
	}
	if retryableAcknowledgementReadError(errors.New("invalid acknowledgement")) {
		t.Fatal("retryableAcknowledgementReadError(local validation) = true, want false")
	}
}

func TestSendAndRetirePreparedFrameMarksLostAcknowledgementRetryable(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	outbound := prepareTransactionOutbound(t, fixture)
	frame := readTransactionFile(t, outbound.FramePath)
	stream := newTransactionTestStream(nil, frame)

	_, err := SendAndRetirePreparedFrame(
		stream,
		outbound,
		fixture.config.ManifestPath,
	)
	if err == nil {
		t.Fatal("SendAndRetirePreparedFrame() error = nil, want lost acknowledgement")
	}
	if !errors.Is(err, ErrRetryableTransport) {
		t.Fatalf("lost acknowledgement error = %v, want ErrRetryableTransport", err)
	}
	assertTransactionSpoolPresent(t, fixture.config.ManifestPath, outbound.Sent.Descriptor.BatchID)
}
