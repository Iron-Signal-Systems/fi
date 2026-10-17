// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/auditpolicy"
)

func testAuditReport() Report {
	required := auditpolicy.Required()
	policies := make([]auditpolicy.Observation, 0, len(required))
	for _, item := range required {
		policies = append(policies, auditpolicy.Observation{Subcategory: item, Flags: 0})
	}
	return Report{WindowsAudit: WindowsAuditState{
		Known:      true,
		Precedence: auditpolicy.Precedence{Present: false},
		Policies:   policies,
	}}
}

func TestWindowsAuditPlanReconcilesEveryMissingPrerequisite(t *testing.T) {
	report := testAuditReport()
	var plan InstallPlan
	planWindowsAudit(&plan, report)
	if len(plan.Actions) != 5 {
		t.Fatalf("got %d actions; expected registry plus four policies", len(plan.Actions))
	}
	for _, action := range plan.Actions {
		if action.Authority != "WINDOWS AUDIT" || action.Action != planActionReconcile {
			t.Fatalf("unexpected action %+v", action)
		}
	}
	if !strings.Contains(plan.Actions[0].Target, "SCENoApplyLegacyAuditPolicy") {
		t.Fatalf("precedence target absent: %q", plan.Actions[0].Target)
	}
}

func TestWindowsAuditPlanPreservesAlreadySufficientPolicy(t *testing.T) {
	report := testAuditReport()
	report.WindowsAudit.Precedence = auditpolicy.Precedence{Present: true, Value: 1}
	for i, p := range auditpolicy.Required() {
		report.WindowsAudit.Policies[i].Flags = p.Required | 0x100
	}
	var plan InstallPlan
	planWindowsAudit(&plan, report)
	if len(plan.Actions) != 5 {
		t.Fatalf("got %d actions", len(plan.Actions))
	}
	for _, a := range plan.Actions {
		if a.Action != planActionNoChange {
			t.Fatalf("unnecessary mutation %+v", a)
		}
	}
}

func TestWindowsAuditPlanBlocksIncompleteOrWrongObservation(t *testing.T) {
	report := testAuditReport()
	report.WindowsAudit.Policies = report.WindowsAudit.Policies[:3]
	var plan InstallPlan
	planWindowsAudit(&plan, report)
	if !plan.HasBlockers() {
		t.Fatal("incomplete effective policy did not block installation")
	}
	report = testAuditReport()
	report.WindowsAudit.Policies[0].Subcategory = report.WindowsAudit.Policies[1].Subcategory
	plan = InstallPlan{}
	planWindowsAudit(&plan, report)
	if !plan.HasBlockers() {
		t.Fatal("wrong subcategory identity did not block installation")
	}
	report = testAuditReport()
	report.WindowsAudit.Error = "access denied"
	plan = InstallPlan{}
	planWindowsAudit(&plan, report)
	if !plan.HasBlockers() {
		t.Fatal("failed policy discovery did not block installation")
	}
}
