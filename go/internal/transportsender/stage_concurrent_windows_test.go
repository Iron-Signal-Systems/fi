// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestConcurrentOutboundValidationRetryableSharingViolation(t *testing.T) {
	err := fmt.Errorf(
		"validate winner: %w",
		&os.PathError{
			Op:   "open",
			Path: "outbound-test.fiwb",
			Err:  windows.ERROR_SHARING_VIOLATION,
		},
	)

	if !isConcurrentOutboundValidationRetryable(err) {
		t.Fatal("sharing violation = non-retryable, want retryable")
	}
}

func TestConcurrentOutboundValidationRetryableRejectsAccessDenied(t *testing.T) {
	err := &os.PathError{
		Op:   "open",
		Path: "outbound-test.fiwb",
		Err:  windows.ERROR_ACCESS_DENIED,
	}

	if isConcurrentOutboundValidationRetryable(err) {
		t.Fatal("access denied = retryable, want hard failure")
	}
}

func TestConcurrentOutboundValidationRetryableRejectsFileNotFound(t *testing.T) {
	err := &os.PathError{
		Op:   "open",
		Path: "outbound-test.fiwb",
		Err:  windows.ERROR_FILE_NOT_FOUND,
	}

	if isConcurrentOutboundValidationRetryable(err) {
		t.Fatal("file not found = retryable, want hard failure")
	}
}
