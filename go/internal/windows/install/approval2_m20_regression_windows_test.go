// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestValidateApproval2RuntimeBinaryDestinations(t *testing.T) {
	programDirectory := `C:\Program Files\FI`

	if err := validateApproval2RuntimeBinaryDestinations(
		[]fileReplacement{
			{
				Destination: `C:\Program Files\FI\fi.exe`,
			},
			{
				Destination: `c:\program files\fi\fi-sender.exe`,
			},
		},
		programDirectory,
	); err != nil {
		t.Fatalf("expected fixed FI destinations to pass: %v", err)
	}

	for _, destination := range []string{
		`C:\Program Files\FI-Other\fi.exe`,
		`C:\Program Files\FI\subdir\fi.exe`,
		`C:\Program Files\FI\..\Other\fi.exe`,
	} {
		if err := validateApproval2RuntimeBinaryDestinations(
			[]fileReplacement{
				{
					Destination: destination,
				},
			},
			programDirectory,
		); err == nil {
			t.Fatalf("expected destination outside the fixed FI program directory to fail: %s", destination)
		}
	}
}

func TestApproval2BrokerReadinessRequiredForMixedRepair(t *testing.T) {
	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionCreate,
				Authority: "SCM",
				Target:    "FIObjReader",
			},
			{
				Action:    planActionReconcile,
				Authority: "RUNTIME",
				Target:    "FIUSNReader",
			},
		},
	}

	if !approval2BrokerReadinessRequired(plan) {
		t.Fatal("expected mixed broker create/runtime repair to require final broker readiness")
	}
}

func TestApproval2BrokerReadinessNotRequiredForNonBrokerMutation(t *testing.T) {
	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionCreate,
				Authority: "SCM",
				Target:    "FICollector",
			},
		},
	}

	if approval2BrokerReadinessRequired(plan) {
		t.Fatal("collector-only SCM mutation must not require broker readiness")
	}
}
