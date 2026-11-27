// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestRequiresApproval2ControllerAcceptsPackageRuntimeOnlyRecovery(
	t *testing.T,
) {
	t.Parallel()

	plan :=
		InstallPlan{
			Actions: []PlanAction{
				{
					Action:    planActionReconcile,
					Authority: "PACKAGE",
					Detail:    "interrupted executable-name migration recovery",
					Target:    "installed FI executables",
				},
				{
					Action:    planActionReconcile,
					Authority: "RUNTIME",
					Detail:    "controlled process-image restart",
					Target:    "FICollector",
				},
			},
		}

	approval1Required, approval2Required :=
		ApprovalRequirements(
			plan,
		)

	if approval1Required {
		t.Fatal(
			"PACKAGE/RUNTIME recovery unexpectedly requires Approval 1",
		)
	}

	if !approval2Required {
		t.Fatal(
			"PACKAGE/RUNTIME recovery did not require Approval 2",
		)
	}

	if !RequiresApproval2Controller(
		plan,
	) {
		t.Fatal(
			"PACKAGE/RUNTIME-only recovery was not routed to Approval 2 controller",
		)
	}
}

func TestRequiresApproval2ControllerRejectsApproval1Plan(
	t *testing.T,
) {
	t.Parallel()

	plan :=
		InstallPlan{
			Actions: []PlanAction{
				{
					Action:    planActionReconcile,
					Authority: "PKI",
					Detail:    "Approval 1 mutation",
					Target:    "FI transport PKI",
				},
				{
					Action:    planActionReconcile,
					Authority: "PACKAGE",
					Detail:    "local mutation",
					Target:    "installed FI executables",
				},
			},
		}

	approval1Required, approval2Required :=
		ApprovalRequirements(
			plan,
		)

	if !approval1Required {
		t.Fatal(
			"PKI plan did not require Approval 1",
		)
	}

	if !approval2Required {
		t.Fatal(
			"mixed PKI/PACKAGE plan did not require Approval 2",
		)
	}

	if RequiresApproval2Controller(
		plan,
	) {
		t.Fatal(
			"mixed Approval-1/2 plan was incorrectly routed as local Approval-2-only repair",
		)
	}
}

func TestRequiresApproval2ControllerRejectsNoMutationPlan(
	t *testing.T,
) {
	t.Parallel()

	plan :=
		InstallPlan{
			Actions: []PlanAction{
				{
					Action:    planActionNoChange,
					Authority: "PACKAGE",
					Detail:    "already converged",
					Target:    "installed FI executables",
				},
			},
		}

	if RequiresApproval2Controller(
		plan,
	) {
		t.Fatal(
			"NO CHANGE plan unexpectedly requires Approval 2 controller",
		)
	}
}
