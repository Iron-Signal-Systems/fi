// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"io"
	"net"
)

// ErrRetryableTransport marks a transport-stream failure that may be retried
// with the same exact staged FI frame. Local validation, trust, staging, and
// retirement failures must not wrap this error.
var ErrRetryableTransport = errors.New("FI transport failure is retryable")

func retryableAcknowledgementReadError(err error) bool {
	return retryableTransportIOError(err, true)
}

func retryableTransportIOError(err error, allowEOF bool) bool {
	if err == nil {
		return false
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return true
	case errors.Is(err, io.ErrClosedPipe):
		return true
	case allowEOF && errors.Is(err, io.EOF):
		return true
	case allowEOF && errors.Is(err, io.ErrUnexpectedEOF):
		return true
	}

	var networkError net.Error
	return errors.As(err, &networkError)
}

func retryableTransportWriteError(err error) bool {
	return retryableTransportIOError(err, false)
}
