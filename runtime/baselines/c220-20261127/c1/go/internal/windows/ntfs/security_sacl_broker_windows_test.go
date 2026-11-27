// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnbroker"
)

func TestSACLReaderReasonCodeDefaultsToReadFailure(t *testing.T) {
	if got := saclReaderReasonCode(fmt.Errorf("reader unavailable")); got != saclDescriptorReadFailed {
		t.Fatalf("reason code = %q, want %q", got, saclDescriptorReadFailed)
	}
}

func TestSACLReaderReasonCodeMapsBrokerPrivilegeUnavailable(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", usnbroker.ErrSACLPrivilegeUnavailable)
	if got := saclReaderReasonCode(err); got != saclPrivilegeUnavailable {
		t.Fatalf("reason code = %q, want %q", got, saclPrivilegeUnavailable)
	}
}

func TestSACLReaderReasonCodeMapsNotAllAssigned(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", syscall.Errno(1300))
	if got := saclReaderReasonCode(err); got != saclPrivilegeUnavailable {
		t.Fatalf("reason code = %q, want %q", got, saclPrivilegeUnavailable)
	}
}

func TestSACLReaderReasonCodeMapsPrivilegeNotHeld(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", syscall.Errno(1314))
	if got := saclReaderReasonCode(err); got != saclPrivilegeUnavailable {
		t.Fatalf("reason code = %q, want %q", got, saclPrivilegeUnavailable)
	}
}
