// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
    "testing"
    "golang.org/x/sys/windows/svc"
    "golang.org/x/sys/windows/svc/mgr"
)

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

func TestApproval2StagedVolumeSourceCollectorOnlyManualStopped(t *testing.T){
    for _,tc:=range []struct{name string;state svc.State;start uint32;allow bool}{
        {"FICollector",svc.Stopped,mgr.StartManual,true},
        {"FISender",svc.Stopped,mgr.StartManual,true},
        {"FICollector",svc.Stopped,mgr.StartAutomatic,false},
        {"FIUSNReader",svc.Stopped,mgr.StartManual,false},
        {"FIObjReader",svc.Stopped,mgr.StartManual,false},
        {"FICRLRefresher",svc.Stopped,mgr.StartManual,false},
        {"FICollector",svc.Running,mgr.StartManual,false},
        {"FICollector",svc.Stopped,mgr.StartDisabled,false},
    }{
        if got:=approval2ManualStagingPermitted(tc.name,tc.state,tc.start);got!=tc.allow{
            t.Fatalf("staged first-run service contract name=%s state=%d start=%d got=%t want=%t",
                tc.name,tc.state,tc.start,got,tc.allow)
        }
    }
}
