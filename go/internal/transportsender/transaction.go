// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// TransportTransactionResult captures the source-side state reached by one
// exact-frame transport transaction.
//
// Authorization is populated only after a complete durable receiver
// acknowledgement matches the exact staged frame. If local spool retirement
// then fails, the valid authorization remains in the result so the caller can
// distinguish downstream custody from local cleanup failure.
type TransportTransactionResult struct {
	Authorization RetirementAuthorization
	Retirement    RetirementResult
	Sent          SentFrame
}

// SendAndRetirePreparedFrame sends one already-staged exact FI frame, verifies
// the durable receiver acknowledgement on the same duplex stream, and only then
// invokes the local Phase 1 spool retirement gate.
//
// The caller is responsible for establishing the authenticated FI transport
// connection. This function deliberately accepts one io.ReadWriter rather than
// separate reader and writer values so the acknowledgement is consumed from the
// same transport stream that carried the frame.
//
// The staged frame is never rebuilt or re-signed here. Any send or
// acknowledgement failure leaves local Phase 1 custody in place and the exact
// staged frame available for retry.
func SendAndRetirePreparedFrame(
	stream io.ReadWriter,
	outbound OutboundFrame,
	manifestPath string,
) (TransportTransactionResult, error) {
	if stream == nil {
		return TransportTransactionResult{}, errors.New("FI transport stream is required")
	}
	if err := validateTransportTransaction(outbound, manifestPath); err != nil {
		return TransportTransactionResult{}, err
	}

	result := TransportTransactionResult{Sent: outbound.Sent}
	if err := sendPreparedOutboundFrame(stream, outbound); err != nil {
		wrapped := fmt.Errorf("send exact FI outbound frame: %w", err)
		if retryableTransportWriteError(err) {
			return result, fmt.Errorf("%w: %w", ErrRetryableTransport, wrapped)
		}
		return result, wrapped
	}

	authorization, err := VerifyDurableAcknowledgement(stream, outbound.Sent)
	if err != nil {
		wrapped := fmt.Errorf(
			"verify FI durable receiver acknowledgement: %w",
			err,
		)
		if retryableAcknowledgementReadError(err) {
			return result, fmt.Errorf("%w: %w", ErrRetryableTransport, wrapped)
		}
		return result, wrapped
	}
	result.Authorization = authorization

	retirement, err := RetirePublishedBatch(manifestPath, authorization)
	result.Retirement = retirement
	if err != nil {
		return result, fmt.Errorf("retire FI published source batch: %w", err)
	}

	return result, nil
}

func sendPreparedOutboundFrame(writer io.Writer, outbound OutboundFrame) error {
	pathInfo, err := os.Lstat(outbound.FramePath)
	if err != nil {
		return fmt.Errorf("inspect staged FI outbound frame before send: %w", err)
	}
	if !pathInfo.Mode().IsRegular() {
		return errors.New("staged FI outbound frame must be a regular file before send")
	}
	if pathInfo.Mode().Perm()&0o222 != 0 {
		return errors.New("staged FI outbound frame must remain read-only before send")
	}
	if pathInfo.Size() <= 0 || uint64(pathInfo.Size()) != outbound.Sent.FrameBytes {
		return fmt.Errorf(
			"staged FI outbound frame size %d does not match prepared frame size %d",
			pathInfo.Size(),
			outbound.Sent.FrameBytes,
		)
	}
	if outbound.Sent.FrameBytes > maxOutboundCopyDataBytes {
		return fmt.Errorf(
			"staged FI outbound frame byte count %d exceeds supported streaming range",
			outbound.Sent.FrameBytes,
		)
	}

	file, err := os.Open(outbound.FramePath)
	if err != nil {
		return fmt.Errorf("open staged FI outbound frame for send: %w", err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat opened FI outbound frame: %w", err)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return errors.New("staged FI outbound frame changed while being opened for send")
	}

	hasher := sha256.New()
	written, err := io.CopyN(
		io.MultiWriter(writer, hasher),
		file,
		int64(outbound.Sent.FrameBytes),
	)
	if err != nil {
		return fmt.Errorf("stream staged FI outbound frame: %w", err)
	}
	if uint64(written) != outbound.Sent.FrameBytes {
		return fmt.Errorf(
			"streamed FI outbound frame bytes %d do not match prepared byte count %d",
			written,
			outbound.Sent.FrameBytes,
		)
	}

	var trailing [1]byte
	n, readErr := file.Read(trailing[:])
	if n != 0 {
		return errors.New("staged FI outbound frame contains trailing bytes during send")
	}
	if !errors.Is(readErr, io.EOF) {
		if readErr == nil {
			return errors.New("staged FI outbound frame did not terminate at prepared boundary")
		}
		return fmt.Errorf("check staged FI outbound frame end after send: %w", readErr)
	}

	afterOpen, err := file.Stat()
	if err != nil {
		return fmt.Errorf("re-stat sent FI outbound frame: %w", err)
	}
	if !os.SameFile(openedInfo, afterOpen) || afterOpen.Size() != pathInfo.Size() {
		return errors.New("staged FI outbound frame changed during send")
	}
	afterPath, err := os.Lstat(outbound.FramePath)
	if err != nil {
		return fmt.Errorf("re-inspect sent FI outbound frame path: %w", err)
	}
	if !os.SameFile(afterOpen, afterPath) {
		return errors.New("staged FI outbound frame path changed during send")
	}
	if afterPath.Mode().Perm()&0o222 != 0 {
		return errors.New("staged FI outbound frame became writable during send")
	}

	digest := hex.EncodeToString(hasher.Sum(nil))
	if digest != outbound.Sent.FrameSHA256 {
		return errors.New("sent FI outbound frame SHA-256 does not match prepared exact frame")
	}
	return nil
}

func validateTransportTransaction(
	outbound OutboundFrame,
	manifestPath string,
) error {
	if err := outbound.Sent.Validate(); err != nil {
		return fmt.Errorf("validate prepared FI outbound frame facts: %w", err)
	}
	if outbound.FramePath == "" {
		return errors.New("staged FI outbound frame path is required")
	}
	if !filepath.IsAbs(outbound.FramePath) {
		return errors.New("staged FI outbound frame path must be absolute")
	}
	if manifestPath == "" {
		return errors.New("published FI batch manifest path is required")
	}
	if !filepath.IsAbs(manifestPath) {
		return errors.New("published FI batch manifest path must be absolute")
	}

	switch outbound.Disposition {
	case OutboundFrameDispositionExisting:
	case OutboundFrameDispositionNew:
	default:
		return fmt.Errorf(
			"unsupported FI outbound frame disposition %q",
			outbound.Disposition,
		)
	}

	expectedName := outboundFrameObjectName(
		outbound.Sent.Descriptor.SourceID,
		outbound.Sent.Descriptor.BatchID,
	)
	if filepath.Base(filepath.Clean(outbound.FramePath)) != expectedName {
		return fmt.Errorf(
			"staged FI outbound frame filename must be %q",
			expectedName,
		)
	}

	frameDir := filepath.Dir(outbound.FramePath)
	if err := validateOutboundStageDirectoryPath(frameDir); err != nil {
		return fmt.Errorf(
			"validate FI outbound frame directory: %w",
			err,
		)
	}

	if _, err := validateRetirementManifestPath(
		manifestPath,
		outbound.Sent.Descriptor.BatchID,
	); err != nil {
		return fmt.Errorf("validate FI source retirement path before send: %w", err)
	}

	current, err := validateStagedOutboundFrame(
		outbound.FramePath,
		outbound.Sent.Descriptor,
	)
	if err != nil {
		return fmt.Errorf("validate exact staged FI outbound frame before send: %w", err)
	}
	if current != outbound.Sent {
		return errors.New("staged FI outbound frame facts changed after preparation")
	}

	return nil
}
