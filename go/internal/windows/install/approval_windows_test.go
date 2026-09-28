// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestApprovalRequirementsSeparatesBoundaries(t *testing.T) {
	t.Parallel()
	plan := InstallPlan{Actions: []PlanAction{
		{Action: planActionNoChange, Authority: "AD", Target: "KDS root key"},
		{Action: planActionReconcile, Authority: "ACL", Target: `C:\ProgramData\FI\state`},
	}}
	approval1, approval2 := ApprovalRequirements(plan)
	if approval1 {
		t.Fatal("Approval 1 unexpectedly required for AD NO CHANGE")
	}
	if !approval2 {
		t.Fatal("Approval 2 was not required for ACL RECONCILE")
	}
}

func TestPromptApprovalsBindsTokenToDigest(t *testing.T) {
	t.Parallel()
	report := Report{
		Host:    HostState{BuildNumber: 14393, Computer: "ISS-FS-01"},
		Package: PackageState{ReleaseID: "test-release"},
	}
	plan := InstallPlan{Actions: []PlanAction{
		{Action: planActionReconcile, Authority: "RIGHTS", Target: `ISS\gFI-FS01$`},
	}}
	digest, err := PlanDigest(report, plan)
	if err != nil {
		t.Fatal(err)
	}
	token := approvalToken(approvalBoundaryLocal, digest)
	var output strings.Builder
	state, err := PromptApprovals(strings.NewReader(token+"\n"), &output, report, plan)
	if err != nil {
		t.Fatal(err)
	}
	if state.Approval1Required {
		t.Fatal("Approval 1 unexpectedly required")
	}
	if !state.Approval2Required || !state.Approval2Given {
		t.Fatal("Approval 2 was not captured")
	}
	if state.PlanSHA256 != digest {
		t.Fatalf("plan digest=%s want=%s", state.PlanSHA256, digest)
	}
}

func TestPromptApprovalsRejectsWrongToken(t *testing.T) {
	t.Parallel()
	report := Report{
		Host:    HostState{BuildNumber: 14393, Computer: "ISS-FS-01"},
		Package: PackageState{ReleaseID: "test-release"},
	}
	plan := InstallPlan{Actions: []PlanAction{
		{Action: planActionReconcile, Authority: "ACL", Target: `C:\ProgramData\FI\state`},
	}}
	_, err := PromptApprovals(strings.NewReader("YES\n"), &strings.Builder{}, report, plan)
	if err == nil {
		t.Fatal("wrong approval token was unexpectedly accepted")
	}
}
