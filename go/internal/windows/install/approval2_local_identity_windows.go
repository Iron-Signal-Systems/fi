// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	serviceAccountFlagLinkToHostOnly     = uintptr(0x00000001)
	serviceAccountFlagUnlinkFromHostOnly = uintptr(0x00000001)
)

var (
	netAddServiceAccountProc = logoncliManagedServiceDLL.NewProc(
		"NetAddServiceAccount",
	)
	netRemoveServiceAccountProc = logoncliManagedServiceDLL.NewProc(
		"NetRemoveServiceAccount",
	)
)

type approval2LocalIdentityBackend interface {
	Install(samAccountName string) error
	Present(samAccountName string) (bool, error)
	Remove(samAccountName string) error
}

type nativeApproval2LocalIdentityBackend struct{}

type approval2LocalIdentityOwnership struct {
	Identity DesiredFIIdentity
}

func (nativeApproval2LocalIdentityBackend) Install(
	samAccountName string,
) error {
	samAccountName, err := serviceAccountSAMName(
		samAccountName,
	)
	if err != nil {
		return err
	}

	accountName, err := syscall.UTF16PtrFromString(
		samAccountName,
	)
	if err != nil {
		return fmt.Errorf(
			"encode managed service account %q: %w",
			samAccountName,
			err,
		)
	}

	status, _, _ := netAddServiceAccountProc.Call(
		0,
		uintptr(unsafe.Pointer(accountName)),
		0,
		serviceAccountFlagLinkToHostOnly,
	)
	runtime.KeepAlive(accountName)

	if status != 0 {
		return lsaStatusError(
			"install local managed service account "+samAccountName,
			status,
		)
	}

	return nil
}

func (nativeApproval2LocalIdentityBackend) Present(
	samAccountName string,
) (bool, error) {
	return localManagedServiceAccountPresent(
		samAccountName,
	)
}

func (nativeApproval2LocalIdentityBackend) Remove(
	samAccountName string,
) error {
	samAccountName, err := serviceAccountSAMName(
		samAccountName,
	)
	if err != nil {
		return err
	}

	accountName, err := syscall.UTF16PtrFromString(
		samAccountName,
	)
	if err != nil {
		return fmt.Errorf(
			"encode managed service account %q: %w",
			samAccountName,
			err,
		)
	}

	status, _, _ := netRemoveServiceAccountProc.Call(
		0,
		uintptr(unsafe.Pointer(accountName)),
		serviceAccountFlagUnlinkFromHostOnly,
	)
	runtime.KeepAlive(accountName)

	if status != 0 {
		return lsaStatusError(
			"remove local managed service account "+samAccountName,
			status,
		)
	}

	return nil
}

func reconcileApproval2LocalIdentities(
	report Report,
	plan InstallPlan,
) (func() error, error) {
	return reconcileApproval2LocalIdentitiesWithBackend(
		report,
		plan,
		nativeApproval2LocalIdentityBackend{},
	)
}

func reconcileApproval2LocalIdentitiesWithBackend(
	report Report,
	plan InstallPlan,
	backend approval2LocalIdentityBackend,
) (func() error, error) {
	if backend == nil {
		return nil, errors.New(
			"Approval 2 local-identity backend is required",
		)
	}

	targets, err := approval2LocalIdentityTargets(
		report,
		plan,
	)
	if err != nil {
		return nil, err
	}

	if len(targets) == 0 {
		return func() error {
			return nil
		}, nil
	}

	// Revalidate every approved local identity before the first mutation. The
	// reviewed report says these exact gMSAs exist in AD but are absent from the
	// local Netlogon store. Any change invalidates the approved boundary.
	for _, identity := range targets {
		present, err := backend.Present(
			identity.SAMAccountName,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"preflight local managed service account %s: %w",
				identity.SAMAccountName,
				err,
			)
		}
		if present {
			return nil, fmt.Errorf(
				"Approval 2 local managed service account %s changed after review: native Netlogon state is already present; no mutation was performed",
				identity.SAMAccountName,
			)
		}
	}

	owned := make(
		[]approval2LocalIdentityOwnership,
		0,
		len(targets),
	)

	rollbackOwned := func() error {
		return rollbackApproval2LocalIdentitiesWithBackend(
			owned,
			backend,
		)
	}

	for _, identity := range targets {
		installErr := backend.Install(
			identity.SAMAccountName,
		)

		present, queryErr := backend.Present(
			identity.SAMAccountName,
		)

		if installErr != nil {
			rollbackErr := rollbackOwned()

			base := fmt.Errorf(
				"install local managed service account %s: %w",
				identity.SAMAccountName,
				installErr,
			)

			switch {
			case queryErr != nil:
				base = errors.Join(
					base,
					fmt.Errorf(
						"post-failure local-state discovery for %s is unavailable; FI retained the current identity because ownership is ambiguous: %w",
						identity.SAMAccountName,
						queryErr,
					),
				)

			case present:
				base = errors.Join(
					base,
					fmt.Errorf(
						"native Netlogon state for %s became present despite the install error; FI retained that identity because ownership is ambiguous",
						identity.SAMAccountName,
					),
				)
			}

			if rollbackErr != nil {
				base = errors.Join(
					base,
					fmt.Errorf(
						"rollback earlier Approval 2 local identities: %w",
						rollbackErr,
					),
				)
			}

			return nil, base
		}

		if queryErr != nil {
			rollbackErr := rollbackOwned()

			base := fmt.Errorf(
				"install local managed service account %s returned success but post-install local-state discovery failed; FI retained that identity because ownership cannot be proven safely: %w",
				identity.SAMAccountName,
				queryErr,
			)

			if rollbackErr != nil {
				base = errors.Join(
					base,
					fmt.Errorf(
						"rollback earlier Approval 2 local identities: %w",
						rollbackErr,
					),
				)
			}

			return nil, base
		}

		if !present {
			rollbackErr := rollbackOwned()

			base := fmt.Errorf(
				"install local managed service account %s returned success but native Netlogon state remains absent",
				identity.SAMAccountName,
			)

			if rollbackErr != nil {
				base = errors.Join(
					base,
					fmt.Errorf(
						"rollback earlier Approval 2 local identities: %w",
						rollbackErr,
					),
				)
			}

			return nil, base
		}

		owned = append(
			owned,
			approval2LocalIdentityOwnership{
				Identity: identity,
			},
		)
	}

	return rollbackOwned, nil
}

func approval2LocalIdentityTargets(
	report Report,
	plan InstallPlan,
) ([]DesiredFIIdentity, error) {
	identityByAccount := make(
		map[string]DesiredFIIdentity,
	)

	for _, identity := range desiredFIIdentityList(
		plan.Identities,
	) {
		key := strings.ToLower(
			strings.TrimSpace(
				identity.Account,
			),
		)

		if key == "" {
			return nil, errors.New(
				"desired FI local identity contains an empty account",
			)
		}

		if _, exists := identityByAccount[key]; exists {
			return nil, fmt.Errorf(
				"duplicate desired FI local identity account %q",
				identity.Account,
			)
		}

		identityByAccount[key] = identity
	}

	targets := make(
		[]DesiredFIIdentity,
		0,
		len(identityByAccount),
	)

	seen := make(
		map[string]struct{},
	)

	for _, action := range plan.Actions {
		if action.Authority != "LOCAL ID" ||
			!planActionMutates(
				action.Action,
			) {
			continue
		}

		if action.Action != planActionReconcile {
			return nil, fmt.Errorf(
				"Approval 2 LOCAL ID action is not a characterized RECONCILE: action=%s target=%s",
				action.Action,
				action.Target,
			)
		}

		key := strings.ToLower(
			strings.TrimSpace(
				action.Target,
			),
		)

		identity, found := identityByAccount[key]
		if !found {
			return nil, fmt.Errorf(
				"Approval 2 LOCAL ID mutation target %q is not one of the exact desired FI gMSA identities",
				action.Target,
			)
		}

		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf(
				"Approval 2 LOCAL ID mutation target %q appears more than once",
				action.Target,
			)
		}

		seen[key] = struct{}{}

		targets = append(
			targets,
			identity,
		)
	}

	if len(targets) == 0 {
		return nil, nil
	}

	if report.Host.BuildNumber != 14393 {
		return nil, fmt.Errorf(
			"Approval 2 local-identity mutation is characterized only for Windows Server 2016 build 14393; observed build=%d",
			report.Host.BuildNumber,
		)
	}

	if !report.Host.Elevated {
		return nil, errors.New(
			"Approval 2 local-identity mutation requires an elevated administrator session",
		)
	}

	if report.Join.Status != "domain" {
		return nil, fmt.Errorf(
			"Approval 2 local-identity mutation requires a domain-joined source; observed status=%s",
			valueOrNotKnown(
				report.Join.Status,
			),
		)
	}

	if !report.AD.ComputerObjectKnown ||
		strings.TrimSpace(
			report.AD.ComputerSID,
		) == "" {
		return nil, errors.New(
			"Active Directory computer object/SID is not authoritative",
		)
	}

	if !report.AD.GMSADiscoveryKnown {
		return nil, errors.New(
			"Active Directory gMSA discovery is not authoritative",
		)
	}

	if plan.HasBlockers() {
		return nil, errors.New(
			"plan contains blockers",
		)
	}

	if plan.HasQuestions() {
		return nil, errors.New(
			"plan still contains unanswered questions",
		)
	}

	for _, identity := range targets {
		local, found := findLocalGMSA(
			report.GMSAs,
			identity.SAMAccountName,
		)
		if !found {
			return nil, fmt.Errorf(
				"authoritative local state for %s is unavailable",
				identity.SAMAccountName,
			)
		}

		if local.State != "not_installed" {
			return nil, fmt.Errorf(
				"Approval 2 LOCAL ID mutation for %s requires reviewed state=not_installed; observed=%s",
				identity.SAMAccountName,
				local.State,
			)
		}

		adState, found := findADGMSA(
			report.AD.GMSAs,
			identity.SAMAccountName,
		)
		if !found {
			return nil, fmt.Errorf(
				"Approval 2 LOCAL ID mutation for %s requires the gMSA to exist authoritatively in Active Directory",
				identity.SAMAccountName,
			)
		}

		if !exactSingleGMSATrustee(
			adState.PasswordRetrievalTrustees,
			report.AD.ComputerSID,
		) {
			return nil, fmt.Errorf(
				"Approval 2 LOCAL ID mutation for %s requires exact one-host password-retrieval authorization for computer SID %s",
				identity.SAMAccountName,
				report.AD.ComputerSID,
			)
		}

		domainDNS := strings.TrimSpace(
			report.Host.DomainDNS,
		)
		if domainDNS == "" ||
			strings.EqualFold(
				domainDNS,
				notKnown,
			) {
			return nil, errors.New(
				"DNS domain is unavailable for Approval 2 gMSA validation",
			)
		}

		expectedDNS := strings.TrimSuffix(
			identity.SAMAccountName,
			"$",
		) + "." + domainDNS

		if !strings.EqualFold(
			strings.TrimSpace(
				adState.DNSHostName,
			),
			expectedDNS,
		) {
			return nil, fmt.Errorf(
				"Approval 2 LOCAL ID mutation for %s requires AD dNSHostName=%q; observed=%q",
				identity.SAMAccountName,
				expectedDNS,
				adState.DNSHostName,
			)
		}
	}

	return targets, nil
}

func rollbackApproval2LocalIdentitiesWithBackend(
	owned []approval2LocalIdentityOwnership,
	backend approval2LocalIdentityBackend,
) error {
	var found []error

	for index := len(owned) - 1; index >= 0; index-- {
		identity := owned[index].Identity

		present, err := backend.Present(
			identity.SAMAccountName,
		)
		if err != nil {
			found = append(
				found,
				fmt.Errorf(
					"discover transaction-owned local managed service account %s before rollback: %w",
					identity.SAMAccountName,
					err,
				),
			)
			continue
		}

		if !present {
			continue
		}

		removeErr := backend.Remove(
			identity.SAMAccountName,
		)

		present, queryErr := backend.Present(
			identity.SAMAccountName,
		)

		if removeErr != nil {
			if queryErr == nil && !present {
				continue
			}

			rollbackErr := fmt.Errorf(
				"remove transaction-owned local managed service account %s: %w",
				identity.SAMAccountName,
				removeErr,
			)

			if queryErr != nil {
				rollbackErr = errors.Join(
					rollbackErr,
					fmt.Errorf(
						"verify rollback local managed service account %s: %w",
						identity.SAMAccountName,
						queryErr,
					),
				)
			}

			found = append(
				found,
				rollbackErr,
			)
			continue
		}

		if queryErr != nil {
			found = append(
				found,
				fmt.Errorf(
					"verify rollback local managed service account %s: %w",
					identity.SAMAccountName,
					queryErr,
				),
			)
			continue
		}

		if present {
			found = append(
				found,
				fmt.Errorf(
					"rollback local managed service account %s did not restore native Netlogon absence",
					identity.SAMAccountName,
				),
			)
		}
	}

	return errors.Join(
		found...,
	)
}
