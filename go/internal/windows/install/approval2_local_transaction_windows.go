// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

func applyServer2016Approval2RemainingLocal(
	report Report,
	plan InstallPlan,
	transactionID string,
) ([]approval2ControllerStep, []AppliedMutation, error) {
	if !validApproval2TransactionID(
		transactionID,
	) {
		return nil, nil, fmt.Errorf(
			"invalid Approval 2 transaction ID %q",
			transactionID,
		)
	}

	steps := make(
		[]approval2ControllerStep,
		0,
		8,
	)
	applied := make(
		[]AppliedMutation,
		0,
		8,
	)

	rollbackOwned := func() error {
		var found []error
		for index := len(steps) - 1; index >= 0; index-- {
			step := steps[index]
			if step.rollback == nil {
				continue
			}
			if err := step.rollback(); err != nil {
				found = append(
					found,
					fmt.Errorf(
						"%s: %w",
						step.name,
						err,
					),
				)
			}
		}
		return errors.Join(
			found...,
		)
	}

	fail := func(
		authority string,
		err error,
	) ([]approval2ControllerStep, []AppliedMutation, error) {
		rollbackErr := rollbackOwned()
		base := fmt.Errorf(
			"%s transaction failed: %w",
			authority,
			err,
		)
		if rollbackErr != nil {
			base = errors.Join(
				base,
				fmt.Errorf(
					"rollback transaction-owned Approval 2 local state: %w",
					rollbackErr,
				),
			)
		}
		return nil, nil, base
	}

	if planHasMutationAuthority(
		plan,
		"RELEASE TRUST",
	) {
		current := Discover()
		rollback, commit, err := installReleaseTrust(
			current,
			transactionID,
		)
		if err != nil {
			return fail(
				"RELEASE TRUST",
				err,
			)
		}
		steps = append(
			steps,
			approval2ControllerStep{
				commit:   commit,
				name:     "RELEASE TRUST",
				rollback: rollback,
			},
		)
		applied = append(
			applied,
			AppliedMutation{
				Authority: "RELEASE TRUST",
				Target:    installedReleaseTrustRoot,
			},
		)
	}

	if planHasMutationAuthority(
		plan,
		"PACKAGE",
	) {
		current := Discover()
		rollback, commit, err := replaceApproval2RuntimeBinaries(
			current,
			transactionID,
		)
		if err != nil {
			return fail(
				"PACKAGE",
				err,
			)
		}
		steps = append(
			steps,
			approval2ControllerStep{
				commit:   commit,
				name:     "PACKAGE",
				rollback: rollback,
			},
		)
		applied = append(
			applied,
			AppliedMutation{
				Authority: "PACKAGE",
				Target:    `C:\Program Files\FI`,
			},
		)
	}

	if planHasMutationAuthority(
		plan,
		"RIGHTS",
	) {
		rollback, err := reconcileServer2016Rights(
			plan.Identities,
		)
		if err != nil {
			return fail(
				"RIGHTS",
				err,
			)
		}
		steps = append(
			steps,
			approval2ControllerStep{
				name:     "RIGHTS",
				rollback: rollback,
			},
		)
		applied = append(
			applied,
			AppliedMutation{
				Authority: "RIGHTS",
				Target:    "FI service identities",
			},
		)
	}

	if planHasMutationAuthority(
		plan,
		"GROUPS",
	) {
		rollback, err := reconcileServer2016Groups(
			plan.Identities,
		)
		if err != nil {
			return fail(
				"GROUPS",
				err,
			)
		}
		steps = append(
			steps,
			approval2ControllerStep{
				name:     "GROUPS",
				rollback: rollback,
			},
		)
		applied = append(
			applied,
			AppliedMutation{
				Authority: "GROUPS",
				Target:    "FI service identities",
			},
		)
	}

	var activateCreatedServices func() error

	if planHasMutationAuthority(
		plan,
		"SCM",
	) {
		current := Discover()
		rollback, activate, err := reconcileServer2016Services(
			current,
			plan.Identities,
			plan,
		)
		if err != nil {
			return fail(
				"SCM",
				err,
			)
		}
		activateCreatedServices = activate
		steps = append(
			steps,
			approval2ControllerStep{
				name:     "SCM",
				rollback: rollback,
			},
		)
		applied = append(
			applied,
			AppliedMutation{
				Authority: "SCM",
				Target:    "FI services",
			},
		)
	}

	if planHasMutationAuthority(
		plan,
		"ACL",
	) {
		filesystemRollback, err :=
			prepareCRLRefresherSecurityFilesystem()
		if err != nil {
			return fail(
				"ACL",
				err,
			)
		}

		current := Discover()

		aclRollback, err :=
			reconcileServer2016ACLs(
				current,
				plan.Identities,
				plan,
			)
		if err != nil {
			return fail(
				"ACL",
				errors.Join(
					err,
					filesystemRollback(),
				),
			)
		}

		rollback :=
			func() error {
				return errors.Join(
					aclRollback(),
					filesystemRollback(),
				)
			}

		steps = append(
			steps,
			approval2ControllerStep{
				name:     "ACL",
				rollback: rollback,
			},
		)

		applied = append(
			applied,
			AppliedMutation{
				Authority: "ACL",
				Target:    "FI-owned roots",
			},
		)
	}

	if activateCreatedServices != nil {
		if err := activateCreatedServices(); err != nil {
			return fail(
				"SCM activation",
				err,
			)
		}
	}

	if planHasMutationAuthority(
		plan,
		"RUNTIME",
	) {
		rollback, err := reconcileFIRuntimeServices(
			plan,
		)
		if err != nil {
			return fail(
				"RUNTIME",
				err,
			)
		}
		steps = append(
			steps,
			approval2ControllerStep{
				name:     "RUNTIME",
				rollback: rollback,
			},
		)
		applied = append(
			applied,
			AppliedMutation{
				Authority: "RUNTIME",
				Target:    "FI services",
			},
		)
	}

	if approval2BrokerReadinessRequired(
		plan,
	) {
		if err := waitForFIBrokerPipes(
			10 * time.Second,
		); err != nil {
			return fail(
				"BROKER READINESS",
				err,
			)
		}
	}

	if approval2ServiceStabilityRequired(
		plan,
	) {
		if err := waitForFIServiceStability(
			approval2ServiceStabilityWindow,
		); err != nil {
			return fail(
				"SERVICE READINESS",
				err,
			)
		}

		if err := waitForFICollectorRuntimeReadinessFromRediscovery(
			Discover,
			transactionID,
			approval2CollectorRuntimeReadinessTimeout,
		); err != nil {
			return fail(
				"COLLECTOR READINESS",
				err,
			)
		}
	}

	for _, action := range plan.Actions {
		if !planActionMutates(
			action.Action,
		) {
			continue
		}
		switch action.Authority {
		case "LOCAL ID", "CONFIG", "RELEASE TRUST", "PACKAGE", "RIGHTS", "GROUPS", "SCM", "ACL", "RUNTIME":
			continue
		default:
			return fail(
				"LOCAL SYSTEM",
				fmt.Errorf(
					"unexpected approved authority %q target=%s",
					action.Authority,
					strings.TrimSpace(
						action.Target,
					),
				),
			)
		}
	}

	_ = report

	return steps, applied, nil
}

func approval2BrokerReadinessRequired(
	plan InstallPlan,
) bool {
	for _, authority := range []string{
		"SCM",
		"RUNTIME",
	} {
		for _, name := range []string{
			"FIUSNReader",
			"FIObjReader",
		} {
			if planTargetMutates(
				plan,
				authority,
				name,
			) {
				return true
			}
		}
	}

	return false
}
