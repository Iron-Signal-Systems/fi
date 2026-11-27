// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestApproval2WindowsSecurityControllerMutationCoverage(t *testing.T) {
	cases := []struct {
		name  string
		audit bool
		sacl  bool
	}{
		{name: "audit-and-sacl", audit: true, sacl: true},
		{name: "audit-only", audit: true},
		{name: "sacl-only", sacl: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := stage3CPlan(`C:\FI-Governed-Test`)
			if tc.audit {
				plan.Actions[0].Action = planActionReconcile
			}
			if tc.sacl {
				plan.Actions[len(plan.Actions)-1].Action = planActionReconcile
			} else {
				plan.Actions[len(plan.Actions)-1].Action = planActionNoChange
			}
			if err := validateApproval2ControllerMutationScope(Report{}, plan, approval1PKIHandoff{}); err != nil {
				t.Fatalf("valid Windows Security Approval 2 plan rejected: %v", err)
			}
			if !approval2RemainingLocalRequired(plan) {
				t.Fatal("Windows Security-only approval did not trigger delegated local mutation")
			}
		})
	}
}

func TestApproval2WindowsSecurityControllerRejectsMalformedPlans(t *testing.T) {
	cases := []struct {
		name     string
		modify   func(*InstallPlan)
		contains string
	}{
		{name: "audit-create", modify: func(p *InstallPlan) { p.Actions[0].Action = planActionCreate }, contains: "supports RECONCILE only"},
		{name: "sacl-create", modify: func(p *InstallPlan) { p.Actions[len(p.Actions)-1].Action = planActionCreate }, contains: "supports RECONCILE only"},
		{name: "extra-audit-target", modify: func(p *InstallPlan) {
			p.Actions = append(p.Actions, PlanAction{Action: planActionReconcile, Authority: "WINDOWS AUDIT", Target: "unauthorized audit target"})
		}, contains: "unrecognized Windows audit approval target"},
		{name: "missing-sacl-contract", modify: func(p *InstallPlan) { p.Actions = p.Actions[:len(p.Actions)-1] }, contains: "no governed-root SACL actions"},
		{name: "missing-audit-subcategory", modify: func(p *InstallPlan) { p.Actions = append(p.Actions[:1], p.Actions[2:]...) }, contains: "prerequisite missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := stage3CPlan(`C:\FI-Governed-Test`)
			plan.Actions[0].Action = planActionReconcile
			plan.Actions[len(plan.Actions)-1].Action = planActionReconcile
			tc.modify(&plan)
			err := validateApproval2ControllerMutationScope(Report{}, plan, approval1PKIHandoff{})
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("malformed Windows Security Approval 2 plan accepted or wrong error: %v", err)
			}
		})
	}
}
