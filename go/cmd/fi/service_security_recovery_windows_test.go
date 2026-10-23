// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

func TestServiceWindowsSecurityRecoveryCheckpoint(t *testing.T) {
	tests := []struct {
		name       string
		status     securityevent.Continuity
		reason     string
		checkpoint string
		oldest     string
		newest     string
		want       string
		wantReplay bool
		wantError  bool
	}{
		{name: "retained history", status: securityevent.ContinuityGap, reason: "SecurityLogRecordsOverwritten", checkpoint: "279062606", oldest: "279091843", newest: "279359820", want: "279091842", wantReplay: true},
		{name: "oldest moves during reconciliation", status: securityevent.ContinuityGap, reason: "SecurityLogRecordsOverwritten", checkpoint: "279062606", oldest: "279101843", newest: "279369820", want: "279101842", wantReplay: true},
		{name: "reset or cleared", status: securityevent.ContinuityGap, reason: "SecurityLogResetOrCleared", checkpoint: "279062606", oldest: "1", newest: "200", want: "200"},
		{name: "empty cleared log", status: securityevent.ContinuityGap, reason: "SecurityLogResetOrCleared", checkpoint: "279062606", oldest: "0", newest: "0", want: "0"},
		{name: "no gap", status: securityevent.ContinuityContinuous, reason: "SecurityLogRecordsOverwritten", checkpoint: "50", oldest: "55", newest: "100", wantError: true},
		{name: "invalid oldest", status: securityevent.ContinuityGap, reason: "SecurityLogRecordsOverwritten", checkpoint: "50", oldest: "bad", newest: "100", wantError: true},
		{name: "oldest not after checkpoint", status: securityevent.ContinuityGap, reason: "SecurityLogRecordsOverwritten", checkpoint: "50", oldest: "51", newest: "100", wantError: true},
		{name: "inverted retained range", status: securityevent.ContinuityGap, reason: "SecurityLogRecordsOverwritten", checkpoint: "50", oldest: "200", newest: "100", wantError: true},
		{name: "unknown reason", status: securityevent.ContinuityGap, reason: "NotKnown", checkpoint: "50", oldest: "90", newest: "100", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assessment := securityevent.ContinuityAssessment{
				Status:     test.status,
				ReasonCode: test.reason,
				Checkpoint: securityevent.Checkpoint{LastEventRecordID: test.checkpoint},
				LogState: securityevent.LogState{
					OldestEventRecordID: test.oldest,
					NewestEventRecordID: test.newest,
				},
			}
			got, replay, err := serviceWindowsSecurityRecoveryCheckpoint(assessment)
			if test.wantError {
				if err == nil {
					t.Fatal("expected recovery error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want || replay != test.wantReplay {
				t.Fatalf("recovery checkpoint=(%q, replay=%v), want=(%q, replay=%v)", got, replay, test.want, test.wantReplay)
			}
		})
	}
}
