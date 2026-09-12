// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package receivertrust

import (
	"errors"
	"strings"
	"testing"
)

func TestInspectReadinessAllValid(t *testing.T) {
	state := inspectReadiness(readyInspectionFunctions())

	if !state.Ready {
		t.Fatalf(
			"ReadinessState.Ready = false, want true: %s",
			state.Detail,
		)
	}

	if state.Detail != "" {
		t.Fatalf(
			"ReadinessState.Detail = %q, want empty",
			state.Detail,
		)
	}
}

func TestInspectReadinessPresenceError(t *testing.T) {
	inspectors := readyInspectionFunctions()
	inspectors.inspectPresence = func() (Status, error) {
		return Status{}, errors.New("test presence failure")
	}

	state := inspectReadiness(inspectors)
	if state.Ready {
		t.Fatal("ReadinessState.Ready = true, want false")
	}

	if !strings.Contains(state.Detail, "test presence failure") {
		t.Fatalf(
			"ReadinessState.Detail = %q, want presence error",
			state.Detail,
		)
	}
}

func TestInspectReadinessStopsAtIncompletePresence(t *testing.T) {
	inspectors := readyInspectionFunctions()
	inspectors.inspectPresence = func() (Status, error) {
		return Status{}, nil
	}
	inspectors.inspectParsing = func() ParseStatus {
		t.Fatal("InspectParsing called after incomplete presence")
		return ParseStatus{}
	}

	state := inspectReadiness(inspectors)
	if state.Ready {
		t.Fatal("ReadinessState.Ready = true, want false")
	}
}

func TestInspectReadinessStopsAtIncompleteParsing(t *testing.T) {
	inspectors := readyInspectionFunctions()
	inspectors.inspectParsing = func() ParseStatus {
		return ParseStatus{}
	}
	inspectors.inspectRootCA = func() ValidationState {
		t.Fatal("root validation called after incomplete parsing")
		return ValidationState{}
	}

	state := inspectReadiness(inspectors)
	if state.Ready {
		t.Fatal("ReadinessState.Ready = true, want false")
	}
}

func TestInspectReadinessPropagatesValidationFailure(t *testing.T) {
	inspectors := readyInspectionFunctions()
	inspectors.inspectReceiverRevocation = func() ValidationState {
		return ValidationState{
			Detail: "test receiver revocation failure",
		}
	}

	state := inspectReadiness(inspectors)
	if state.Ready {
		t.Fatal("ReadinessState.Ready = true, want false")
	}

	if !strings.Contains(
		state.Detail,
		"test receiver revocation failure",
	) {
		t.Fatalf(
			"ReadinessState.Detail = %q, want revocation failure",
			state.Detail,
		)
	}
}

func readyInspectionFunctions() readinessInspectionFunctions {
	valid := func() ValidationState {
		return ValidationState{
			Valid: true,
		}
	}

	return readinessInspectionFunctions{
		inspectBatchCRL:    valid,
		inspectBatchIssuer: valid,
		inspectParsing: func() ParseStatus {
			return ParseStatus{
				Complete: true,
			}
		},
		inspectPresence: func() (Status, error) {
			return Status{
				Complete: true,
			}, nil
		},
		inspectReceiverCertificate: valid,
		inspectReceiverHostname:    valid,
		inspectReceiverKey:         valid,
		inspectReceiverRevocation:  valid,
		inspectRootCA:              valid,
		inspectSourceRegistry:      valid,
		inspectTransportCRL:        valid,
		inspectTransportIssuer:     valid,
		inspectTrustCustody:        valid,
	}
}
