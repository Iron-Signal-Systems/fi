// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/auditpolicy"
)

// WindowsAuditState is a snapshot of the installer's observed effective policy.
// Unknown is deliberately not the same as an empty (disabled) policy.
type WindowsAuditState struct {
	Known      bool
	Precedence auditpolicy.Precedence
	Policies   []auditpolicy.Observation
	Error      string
}

func discoverWindowsAudit(report *Report) {
	state := WindowsAuditState{Known: true}
	precedence, err := auditpolicy.QueryPrecedence()
	if err != nil {
		state.Error = fmt.Sprintf("advanced audit precedence: %v", err)
		report.WindowsAudit = state
		return
	}
	state.Precedence = precedence
	observations, err := auditpolicy.QueryRequired()
	if err != nil {
		state.Error = fmt.Sprintf("effective advanced audit policy: %v", err)
		report.WindowsAudit = state
		return
	}
	if len(observations) != len(auditpolicy.Required()) {
		state.Error = "effective audit policy returned an incomplete FI subcategory set"
		report.WindowsAudit = state
		return
	}
	state.Policies = observations
	report.WindowsAudit = state
}

// planWindowsAudit exposes each independent proposed host-policy change within
// the same digest-protected Approval 2 transaction as FI's other local state.
func planWindowsAudit(plan *InstallPlan, report Report) {
	state := report.WindowsAudit
	if !state.Known {
		// Synthetic test reports predate this discovery field. Production
		// Discover always sets Known=true, including on discovery failure.
		return
	}
	if state.Error != "" {
		plan.Actions = append(plan.Actions, PlanAction{
			Action: planActionBlocked, Authority: "WINDOWS AUDIT",
			Target: "Windows effective audit policy",
			Detail: "audit-policy discovery unavailable: " + state.Error,
		})
		return
	}
	precedenceAction := planActionNoChange
	if !state.Precedence.Present || state.Precedence.Value != 1 {
		precedenceAction = planActionReconcile
	}
	plan.Actions = append(plan.Actions, PlanAction{
		Action: precedenceAction, Authority: "WINDOWS AUDIT",
		Target: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy`,
		Detail: fmt.Sprintf("PERSISTENT HOST SECURITY PREREQUISITE (retained if FI install fails); force advanced subcategory precedence=1; current present=%t value=%d", state.Precedence.Present, state.Precedence.Value),
	})
	required := auditpolicy.Required()
	if len(state.Policies) != len(required) {
		plan.Actions = append(plan.Actions, PlanAction{
			Action: planActionBlocked, Authority: "WINDOWS AUDIT",
			Target: "FI audit subcategories",
			Detail: fmt.Sprintf("unexpected subcategory count %d", len(state.Policies)),
		})
		return
	}
	for i, subcategory := range required {
		actual := state.Policies[i]
		if actual.Subcategory != subcategory {
			plan.Actions = append(plan.Actions, PlanAction{
				Action: planActionBlocked, Authority: "WINDOWS AUDIT",
				Target: subcategory.ID,
				Detail: "observed audit subcategory identity/order mismatch",
			})
			continue
		}
		action := planActionNoChange
		if !auditpolicy.Sufficient(actual.Flags, subcategory.Required) {
			action = planActionReconcile
		}
		plan.Actions = append(plan.Actions, PlanAction{
			Action: action, Authority: "WINDOWS AUDIT",
			Target: subcategory.ID + " " + subcategory.GUID,
			Detail: fmt.Sprintf("PERSISTENT HOST SECURITY PREREQUISITE (retained if FI install fails); effective_flags=%d required_flags=%d; preserve all other flags", actual.Flags, subcategory.Required),
		})
	}
}

// applyApproval2WindowsAudit owns all Windows-policy state transitions until
// the parent Approval 2 transaction commits or requests rollback.
func applyApproval2WindowsAudit() (func() error, error) {
	undoPrecedence, err := auditpolicy.ApplyPrecedence()
	if err != nil {
		return nil, fmt.Errorf("set advanced audit precedence: %w", err)
	}
	undoPolicy, err := auditpolicy.ApplyRequired()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("enable FI required Windows audit policy: %w", err), undoPrecedence())
	}
	rollback := func() error {
		return errors.Join(undoPolicy(), undoPrecedence())
	}
	precedence, err := auditpolicy.QueryPrecedence()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("verify audit precedence: %w", err), rollback())
	}
	if !precedence.Present || precedence.Value != 1 {
		return nil, errors.Join(fmt.Errorf("audit precedence did not converge: %+v", precedence), rollback())
	}
	observed, err := auditpolicy.QueryRequired()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("verify audit subcategories: %w", err), rollback())
	}
	required := auditpolicy.Required()
	if len(observed) != len(required) {
		return nil, errors.Join(fmt.Errorf("audit verification returned %d subcategories; want %d", len(observed), len(required)), rollback())
	}
	for i, category := range required {
		if observed[i].Subcategory != category || !auditpolicy.Sufficient(observed[i].Flags, category.Required) {
			return nil, errors.Join(fmt.Errorf("Windows audit policy did not converge: %s", category.ID), rollback())
		}
	}
	return rollback, nil
}
