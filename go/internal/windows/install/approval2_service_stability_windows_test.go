// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestApproval2ServiceStabilityRequiredForServiceAffectingMutations(
	t *testing.T,
) {
	t.Parallel()

	for _, test := range []struct {
		authority string
		target    string
	}{
		{
			authority: "PACKAGE",
			target:    "installed FI executables",
		},
		{
			authority: "SCM",
			target:    "FISender",
		},
		{
			authority: "RUNTIME",
			target:    "FICollector",
		},
	} {
		plan := InstallPlan{
			Actions: []PlanAction{
				{
					Action:    planActionReconcile,
					Authority: test.authority,
					Target:    test.target,
				},
			},
		}

		if !approval2ServiceStabilityRequired(
			plan,
		) {
			t.Fatalf(
				"authority=%s target=%s did not require service stability",
				test.authority,
				test.target,
			)
		}
	}
}

func TestApproval2ServiceStabilityNotRequiredForNonServiceMutation(
	t *testing.T,
) {
	t.Parallel()

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "ACL",
				Target:    `C:\ProgramData\FI\state`,
			},
		},
	}

	if approval2ServiceStabilityRequired(
		plan,
	) {
		t.Fatal(
			"ACL-only reconciliation must not incur the service stability window",
		)
	}
}

func TestApproval2ServiceStabilityIgnoresNoChangeServiceActions(
	t *testing.T,
) {
	t.Parallel()

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionNoChange,
				Authority: "RUNTIME",
				Target:    "FISender",
			},
		},
	}

	if approval2ServiceStabilityRequired(
		plan,
	) {
		t.Fatal(
			"NO CHANGE runtime action must not incur the service stability window",
		)
	}
}

func TestWaitForFIServiceStabilityRejectsNonPositiveWindow(
	t *testing.T,
) {
	t.Parallel()

	if err := waitForFIServiceStability(0); err == nil {
		t.Fatal("zero service stability window unexpectedly accepted")
	}
}
