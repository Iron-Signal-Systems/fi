// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"strings"
)

// Stale local registrations occur when a gMSA was deleted and recreated in AD
// without removing its previous host-side Netlogon registration. Repair is a
// separately reviewed LOCAL ID action; never infer authorization from name alone.
func approval2HasStaleLocalRegistration(report Report, targets []DesiredFIIdentity) bool {
	for _, identity := range targets {
		state, found := findLocalGMSA(report.GMSAs, identity.SAMAccountName)
		if found && state.State == "stale_registration" {
			return true
		}
	}
	return false
}

func reconcileApproval2StaleLocalRegistrations(
	report Report,
	plan InstallPlan,
	targets []DesiredFIIdentity,
	backend approval2LocalIdentityBackend,
) (func() error, error) {
	// Refresh cannot safely interrupt an existing FI service that may already
	// be running with the old identity. This is limited to reinstall recovery.
	for _, service := range report.Services {
		if service.Presence != presenceAbsent {
			return nil, fmt.Errorf(
				"refuse stale FI gMSA rebind while service %s presence=%s",
				service.Name, service.Presence,
			)
		}
	}

	stale := make([]DesiredFIIdentity, 0, len(targets))
	for _, identity := range targets {
		state, found := findLocalGMSA(report.GMSAs, identity.SAMAccountName)
		if !found {
			return nil, fmt.Errorf("missing authoritative local identity %s", identity.Account)
		}
		present, err := backend.Present(identity.SAMAccountName)
		if err != nil {
			return nil, fmt.Errorf("preflight local identity %s: %w", identity.Account, err)
		}
		wanted := state.State == "stale_registration"
		if state.State != "stale_registration" && state.State != "not_installed" {
			return nil, fmt.Errorf("unapproved local identity state %s for %s", state.State, identity.Account)
		}
		if present != wanted {
			return nil, fmt.Errorf("local Netlogon state drift for %s: expected_present=%t observed_present=%t", identity.Account, wanted, present)
		}
		if wanted {
			stale = append(stale, identity)
		}
	}

	// The old gMSA object no longer exists in AD. Rollback cannot restore its
	// SID; it preserves the host-side installed state for that exact FI name.
	owned := make([]DesiredFIIdentity, 0, len(stale))
	restore := func() error {
		var errs []error
		for i := len(owned) - 1; i >= 0; i-- {
			name := owned[i].SAMAccountName
			present, err := backend.Present(name)
			if err != nil {
				errs = append(errs, fmt.Errorf("inspect local gMSA %s on rollback: %w", name, err))
				continue
			}
			if !present {
				if err := backend.Install(name); err != nil {
					errs = append(errs, fmt.Errorf("restore installed local gMSA %s: %w", name, err))
					continue
				}
				if present, err = backend.Present(name); err != nil || !present {
					errs = append(errs, fmt.Errorf("verify restored local gMSA %s: present=%t error=%v", name, present, err))
				}
			}
		}
		return errors.Join(errs...)
	}

	for _, identity := range stale {
		name := identity.SAMAccountName
		// Own restoration before invoking a native operation that may partially
		// complete. Never remove an identity unless it was in the signed plan.
		owned = append(owned, identity)
		if err := backend.Remove(name); err != nil {
			return nil, errors.Join(fmt.Errorf("unregister stale local gMSA %s: %w", name, err), restore())
		}
		present, err := backend.Present(name)
		if err != nil || present {
			return nil, errors.Join(
				fmt.Errorf("verify stale local gMSA %s removed: present=%t error=%v", name, present, err),
				restore(),
			)
		}
		if err := backend.Install(name); err != nil {
			return nil, errors.Join(fmt.Errorf("register current local gMSA %s: %w", name, err), restore())
		}
		present, err = backend.Present(name)
		if err != nil || !present {
			return nil, errors.Join(
				fmt.Errorf("verify refreshed local gMSA %s installed: present=%t error=%v", name, present, err),
				restore(),
			)
		}
	}

	// Delegate ordinary absent->installed identities to the existing fully
	// characterized transaction, preserving its exact native rollback logic.
	remaining := plan
	remaining.Actions = make([]PlanAction, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		if action.Authority == "LOCAL ID" && planActionMutates(action.Action) {
			keep := true
			for _, identity := range stale {
				if strings.EqualFold(strings.TrimSpace(action.Target), identity.Account) {
					keep = false
					break
				}
			}
			if !keep {
				continue
			}
		}
		remaining.Actions = append(remaining.Actions, action)
	}

	postRefresh := report
	postRefresh.GMSAs = append([]GMSAState(nil), report.GMSAs...)
	for i := range postRefresh.GMSAs {
		for _, identity := range stale {
			if strings.EqualFold(postRefresh.GMSAs[i].SAMAccountName, identity.SAMAccountName) {
				postRefresh.GMSAs[i].State = "installed"
			}
		}
	}

	rollbackNew, err := reconcileApproval2LocalIdentitiesWithBackend(postRefresh, remaining, backend)
	if err != nil {
		return nil, errors.Join(err, restore())
	}
	return func() error { return errors.Join(rollbackNew(), restore()) }, nil
}
