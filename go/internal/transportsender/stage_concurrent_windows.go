// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"errors"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"golang.org/x/sys/windows"
)

const (
	concurrentOutboundValidationAttempts = 50
	concurrentOutboundValidationDelay    = 10 * time.Millisecond
)

// validateConcurrentlyPublishedOutboundFrame validates the winner of a Windows
// no-replace publication race.
//
// MoveFileExW can report that the destination already exists before another
// preparer can successfully reopen that just-published file. In that narrow
// loser path, Windows may transiently return ERROR_SHARING_VIOLATION. Retry only
// that operating-system condition for a bounded interval. Descriptor, framing,
// signature, hash, permission, and all other validation failures remain
// immediate hard failures.
func validateConcurrentlyPublishedOutboundFrame(
	path string,
	expected transportbatch.Descriptor,
) (SentFrame, error) {
	var lastErr error

	for attempt := 0; attempt < concurrentOutboundValidationAttempts; attempt++ {
		result, err := validateStagedOutboundFrame(path, expected)
		if err == nil {
			return result, nil
		}
		if !isConcurrentOutboundValidationRetryable(err) {
			return SentFrame{}, err
		}

		lastErr = err
		if attempt+1 < concurrentOutboundValidationAttempts {
			time.Sleep(concurrentOutboundValidationDelay)
		}
	}

	return SentFrame{}, lastErr
}

func isConcurrentOutboundValidationRetryable(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
