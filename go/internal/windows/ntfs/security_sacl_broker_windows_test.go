// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"fmt"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnbroker"
)

func TestSACLBrokerReasonCodeDefaultsToReadFailure(t *testing.T) {
	if got := saclBrokerReasonCode(fmt.Errorf("broker unavailable")); got != saclDescriptorReadFailed {
		t.Fatalf("reason code = %q, want %q", got, saclDescriptorReadFailed)
	}
}

func TestSACLBrokerReasonCodeMapsPrivilegeUnavailable(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", usnbroker.ErrSACLPrivilegeUnavailable)
	if got := saclBrokerReasonCode(err); got != saclPrivilegeUnavailable {
		t.Fatalf("reason code = %q, want %q", got, saclPrivilegeUnavailable)
	}
}
