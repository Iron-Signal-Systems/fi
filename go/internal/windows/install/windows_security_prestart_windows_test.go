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

func stage3CPlan(root string) InstallPlan {
	plan := InstallPlan{Actions: []PlanAction{{Action: planActionNoChange, Authority: "WINDOWS AUDIT", Target: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy`}}}
	for _, r := range auditpolicy.Required() {
		plan.Actions = append(plan.Actions, PlanAction{Action: planActionNoChange, Authority: "WINDOWS AUDIT", Target: r.ID + " " + r.GUID})
	}
	plan.Actions = append(plan.Actions, PlanAction{Action: planActionReconcile, Authority: "WINDOWS SACL", Target: root})
	return plan
}

func stage3CState(root string) windowsSecurityPreStartState {
	state := windowsSecurityPreStartState{precedence: auditpolicy.Precedence{Present: true, Value: 1}, securityLogReadable: true, roots: []fiSACLSnapshot{{path: root, hasChange: true, hasRead: true}}}
	for _, r := range auditpolicy.Required() {
		state.policies = append(state.policies, auditpolicy.Observation{Subcategory: r, Flags: r.Required})
	}
	return state
}

func TestWindowsSecurityPreStartAcceptsFullContract(t *testing.T) {
	plan := stage3CPlan(`C:\Shares`)
	roots, err := approvedWindowsSecurityPreStartRoots(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsSecurityPreStartState(roots, stage3CState(`C:\Shares`)); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSecurityPreStartRejectsPolicyDrift(t *testing.T) {
	roots, err := approvedWindowsSecurityPreStartRoots(stage3CPlan(`C:\Shares`))
	if err != nil {
		t.Fatal(err)
	}
	state := stage3CState(`C:\Shares`)
	state.policies[0].Flags = 0
	if err := validateWindowsSecurityPreStartState(roots, state); err == nil {
		t.Fatal("missing effective audit policy accepted")
	}
}

func TestWindowsSecurityPreStartRejectsMissingSACL(t *testing.T) {
	roots, err := approvedWindowsSecurityPreStartRoots(stage3CPlan(`C:\Shares`))
	if err != nil {
		t.Fatal(err)
	}
	state := stage3CState(`C:\Shares`)
	state.roots[0].hasRead = false
	if err := validateWindowsSecurityPreStartState(roots, state); err == nil {
		t.Fatal("missing descendant SACL accepted")
	}
}

func TestWindowsSecurityPreStartRejectsChannelUnreadable(t *testing.T) {
	roots, err := approvedWindowsSecurityPreStartRoots(stage3CPlan(`C:\Shares`))
	if err != nil {
		t.Fatal(err)
	}
	state := stage3CState(`C:\Shares`)
	state.securityLogReadable = false
	if err := validateWindowsSecurityPreStartState(roots, state); err == nil {
		t.Fatal("unreadable channel accepted")
	}
}

func TestWindowsSecurityPreStartRejectsUnapprovedTarget(t *testing.T) {
	plan := stage3CPlan(`C:\Shares`)
	plan.Actions = append(plan.Actions, PlanAction{Action: planActionReconcile, Authority: "WINDOWS AUDIT", Target: "arbitrary policy"})
	if _, err := approvedWindowsSecurityPreStartRoots(plan); err == nil {
		t.Fatal("arbitrary audit authority accepted")
	}
}

func TestWindowsSecurityPreStartRejectsMissingContract(t *testing.T) {
	plan := stage3CPlan(`C:\Shares`)
	plan.Actions = plan.Actions[1:]
	if _, err := approvedWindowsSecurityPreStartRoots(plan); err == nil {
		t.Fatal("missing precedence accepted")
	}
	plan = stage3CPlan(`C:\Shares`)
	plan.Actions[len(plan.Actions)-1].Action = planActionBlocked
	if _, err := approvedWindowsSecurityPreStartRoots(plan); err == nil {
		t.Fatal("blocked root action accepted")
	}
}

func TestWindowsSecurityPreStartRejectsWrongRoot(t *testing.T) {
	roots, err := approvedWindowsSecurityPreStartRoots(stage3CPlan(`C:\Shares`))
	if err != nil {
		t.Fatal(err)
	}
	state := stage3CState(`C:\Other`)
	if err := validateWindowsSecurityPreStartState(roots, state); err == nil || !strings.Contains(err.Error(), "no SACL observation") {
		t.Fatalf("unexpected root accepted: %v", err)
	}
}
