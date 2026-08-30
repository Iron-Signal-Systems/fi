// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

func TestSelectUSNObjectForSpoolKeepsHelperContainedAccessDenied(t *testing.T) {
	calledParent := false
	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{
			Status:     usn.ReobservationError,
			ReasonCode: usn.ReobservationReasonContainedObjectAccessDenied,
		},
		nil,
		records.NTFSObjectIdentity{},
		func(records.NTFSObjectIdentity) parentScopeResult {
			calledParent = true
			return parentScopeResult{Status: parentScopeError, Error: "unexpected"}
		},
	)
	if !keep {
		t.Fatal("helper-contained access-denied object was dropped")
	}
	if selection.ScopeBasis != scopeBasisCurrentObjectContainedByHelper {
		t.Fatalf("scope basis = %q, want %q", selection.ScopeBasis, scopeBasisCurrentObjectContainedByHelper)
	}
	if calledParent {
		t.Fatal("helper-contained current object should not require recorded-parent scope fallback")
	}
}
