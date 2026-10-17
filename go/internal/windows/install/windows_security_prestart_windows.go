// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/auditpolicy"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

// windowsSecurityPreStartState is a separate, read-only installation gate.
// It DOES NOT claim FICollector has processed events or that SOR ingestion
// has completed. Those proofs require Collector/Sender/receiver observation.
type windowsSecurityPreStartState struct {
	precedence          auditpolicy.Precedence
	policies            []auditpolicy.Observation
	securityLogReadable bool
	roots               []fiSACLSnapshot
}

func approvedWindowsSecurityPreStartRoots(plan InstallPlan) ([]string, error) {
	contractTargets := make(map[string]bool)
	for _, required := range auditpolicy.Required() {
		contractTargets[required.ID+" "+required.GUID] = false
	}
	const precedenceTarget = `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy`
	precedenceFound := false
	roots := make([]string, 0)
	for _, action := range plan.Actions {
		switch action.Authority {
		case "WINDOWS AUDIT":
			if !validWindowsSecurityPreStartAction(action.Action) {
				return nil, fmt.Errorf("Windows audit approval contains unresolved %s: %s", action.Action, action.Target)
			}
			if action.Target == precedenceTarget {
				if precedenceFound {
					return nil, errors.New("duplicate Windows audit precedence action")
				}
				precedenceFound = true
				continue
			}
			if _, ok := contractTargets[action.Target]; !ok {
				return nil, fmt.Errorf("unrecognized Windows audit approval target %q", action.Target)
			}
			if contractTargets[action.Target] {
				return nil, fmt.Errorf("duplicate Windows audit subcategory action %q", action.Target)
			}
			contractTargets[action.Target] = true
		case "WINDOWS SACL":
			if !validWindowsSecurityPreStartAction(action.Action) {
				return nil, fmt.Errorf("governed-root SACL approval contains unresolved %s: %s", action.Action, action.Target)
			}
			roots = append(roots, action.Target)
		}
	}
	if !precedenceFound {
		return nil, errors.New("Windows audit precedence was not included in the approved plan")
	}
	for target, found := range contractTargets {
		if !found {
			return nil, fmt.Errorf("Windows audit prerequisite missing from approved plan: %s", target)
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("no governed-root SACL actions in the approved plan")
	}
	return fiSACLRoots(roots)
}

func validWindowsSecurityPreStartAction(action string) bool {
	return action == planActionNoChange || action == planActionReconcile
}

func validateWindowsSecurityPreStartState(roots []string, state windowsSecurityPreStartState) error {
	if !state.precedence.Present || state.precedence.Value != 1 {
		return fmt.Errorf("advanced audit precedence does not equal 1: present=%t value=%d", state.precedence.Present, state.precedence.Value)
	}
	required := auditpolicy.Required()
	if len(state.policies) != len(required) {
		return fmt.Errorf("effective audit subcategory count=%d; need=%d", len(state.policies), len(required))
	}
	for i, contract := range required {
		if state.policies[i].Subcategory != contract {
			return fmt.Errorf("effective audit subcategory identity/order mismatch: %s", contract.ID)
		}
		if !auditpolicy.Sufficient(state.policies[i].Flags, contract.Required) {
			return fmt.Errorf("required audit events cannot be generated: %s needs flags=%d effective=%d", contract.ID, contract.Required, state.policies[i].Flags)
		}
	}
	if !state.securityLogReadable {
		return errors.New("Windows Security channel cannot be read by installer; Collector permissions require separate verification")
	}
	if len(roots) != len(state.roots) {
		return fmt.Errorf("governed-root coverage count=%d; need=%d", len(state.roots), len(roots))
	}
	snapshots := make(map[string]fiSACLSnapshot, len(state.roots))
	for _, snapshot := range state.roots {
		key := strings.ToLower(snapshot.path)
		if _, found := snapshots[key]; found {
			return fmt.Errorf("duplicate governed-root SACL observation %q", snapshot.path)
		}
		snapshots[key] = snapshot
	}
	for _, root := range roots {
		snapshot, found := snapshots[strings.ToLower(root)]
		if !found {
			return fmt.Errorf("no SACL observation for governed root %q", root)
		}
		if !snapshot.hasChange || !snapshot.hasRead {
			return fmt.Errorf("incomplete governed-root SACL %s: change=%t descendant_read=%t", root, snapshot.hasChange, snapshot.hasRead)
		}
	}
	return nil
}

// verifyWindowsSecurityPreStart is invoked AFTER all approved policy/SACL
// mutations, and BEFORE any FI service activation. Discovery failures always
// fail closed, including when no local policy mutation was necessary.
func verifyWindowsSecurityPreStart(plan InstallPlan) error {
	roots, err := approvedWindowsSecurityPreStartRoots(plan)
	if err != nil {
		return err
	}
	precedence, err := auditpolicy.QueryPrecedence()
	if err != nil {
		return fmt.Errorf("read Windows audit precedence: %w", err)
	}
	policies, err := auditpolicy.QueryRequired()
	if err != nil {
		return fmt.Errorf("read effective Windows audit policy: %w", err)
	}
	if _, err := securityevent.QueryLogState(); err != nil {
		return fmt.Errorf("open and read Windows Security event channel: %w", err)
	}
	observations := make([]fiSACLSnapshot, 0, len(roots))
	for _, root := range roots {
		snapshot, err := fiQueryRootSACL(root)
		if err != nil {
			return fmt.Errorf("inspect governed-root SACL %q: %w", root, err)
		}
		observations = append(observations, snapshot)
	}
	return validateWindowsSecurityPreStartState(roots, windowsSecurityPreStartState{
		precedence: precedence, policies: policies, securityLogReadable: true, roots: observations,
	})
}
