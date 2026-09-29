// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type approval2ServiceContract struct {
	Account     string
	Args        []string
	DisplayName string
	Executable  string
	Name        string
	Path        string
	SIDType     uint32
}

type approval2ServiceOwnership struct {
	Contract approval2ServiceContract
	Created  bool
	Original mgr.Config
}

func reconcileServer2016Services(
	report Report,
	identities DesiredFIIdentities,
	plan InstallPlan,
) (func() error, func() error, error) {
	contracts := approval2Server2016ServiceContracts(
		identities,
	)

	contractByName := make(
		map[string]approval2ServiceContract,
		len(contracts),
	)
	for _, contract := range contracts {
		contractByName[strings.ToLower(
			contract.Name,
		)] = contract
	}

	var targets []approval2ServiceContract
	seen := make(
		map[string]struct{},
	)

	for _, action := range plan.Actions {
		if action.Authority != "SCM" ||
			!planActionMutates(
				action.Action,
			) {
			continue
		}

		if action.Action != planActionCreate &&
			action.Action != planActionReconcile {
			return nil, nil, fmt.Errorf(
				"Approval 2 SCM action=%s target=%s is not characterized",
				action.Action,
				action.Target,
			)
		}

		key := strings.ToLower(
			strings.TrimSpace(
				action.Target,
			),
		)
		contract, found := contractByName[key]
		if !found {
			return nil, nil, fmt.Errorf(
				"Approval 2 SCM target %q is not an FI service",
				action.Target,
			)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, fmt.Errorf(
				"Approval 2 SCM target %q appears more than once",
				action.Target,
			)
		}
		seen[key] = struct{}{}
		targets = append(
			targets,
			contract,
		)
	}

	if len(targets) == 0 {
		return func() error { return nil }, func() error { return nil }, nil
	}

	if report.Host.BuildNumber != 14393 {
		return nil, nil, fmt.Errorf(
			"Approval 2 SCM mutation is characterized only for Windows Server 2016 build 14393; observed=%d",
			report.Host.BuildNumber,
		)
	}

	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf(
			"connect to service control manager for Approval 2: %w",
			err,
		)
	}
	defer manager.Disconnect()

	owned := make(
		[]approval2ServiceOwnership,
		0,
		len(targets),
	)

	rollbackOwned := func() error {
		return rollbackApproval2Services(
			owned,
		)
	}

	for _, contract := range targets {
		observed, found := findService(
			report.Services,
			contract.Name,
		)
		if !found {
			_ = rollbackOwned()
			return nil, nil, fmt.Errorf(
				"authoritative SCM discovery for %s is unavailable",
				contract.Name,
			)
		}
		if observed.Presence == presenceUnknown {
			_ = rollbackOwned()
			return nil, nil, fmt.Errorf(
				"authoritative SCM presence for %s is unknown",
				contract.Name,
			)
		}

		service, openErr := manager.OpenService(
			contract.Name,
		)

		switch observed.Presence {
		case presenceAbsent:
			if openErr == nil {
				service.Close()
				_ = rollbackOwned()
				return nil, nil, fmt.Errorf(
					"service %s appeared after Approval 2 review; no SCM mutation was performed for that target",
					contract.Name,
				)
			}
			if !errors.Is(
				openErr,
				windows.ERROR_SERVICE_DOES_NOT_EXIST,
			) {
				_ = rollbackOwned()
				return nil, nil, fmt.Errorf(
					"preflight open absent service %s: %w",
					contract.Name,
					openErr,
				)
			}

			created, err := manager.CreateService(
				contract.Name,
				contract.Executable,
				mgr.Config{
					DisplayName:      contract.DisplayName,
					ErrorControl:     mgr.ErrorNormal,
					ServiceStartName: contract.Account,
					StartType:        mgr.StartAutomatic,
					SidType:          contract.SIDType,
				},
				contract.Args...,
			)
			if err != nil {
				_ = rollbackOwned()
				return nil, nil, fmt.Errorf(
					"create service %s: %w",
					contract.Name,
					err,
				)
			}
			created.Close()

			owned = append(
				owned,
				approval2ServiceOwnership{
					Contract: contract,
					Created:  true,
				},
			)

		case presencePresent:
			if openErr != nil {
				_ = rollbackOwned()
				return nil, nil, fmt.Errorf(
					"open reviewed existing service %s: %w",
					contract.Name,
					openErr,
				)
			}

			original, err := service.Config()
			if err != nil {
				service.Close()
				_ = rollbackOwned()
				return nil, nil, fmt.Errorf(
					"snapshot service %s before reconciliation: %w",
					contract.Name,
					err,
				)
			}

			// Windows does not return an existing service password. Restoring an
			// arbitrary conventional account would therefore be impossible. FI
			// reconciles an existing service only when discovery proves it already
			// uses a managed account, for which the password remains SCM-managed.
			if observed.ManagedAccount != "true" {
				service.Close()
				_ = rollbackOwned()
				return nil, nil, fmt.Errorf(
					"refusing to reconcile existing service %s because prior managed-account state=%s cannot be rolled back safely",
					contract.Name,
					observed.ManagedAccount,
				)
			}

			desired := original
			desired.BinaryPathName = contract.Path
			desired.DisplayName = contract.DisplayName
			desired.ServiceStartName = contract.Account
			desired.Password = ""
			desired.StartType = mgr.StartAutomatic
			desired.SidType = contract.SIDType
			desired.DelayedAutoStart = false

			if err := service.UpdateConfig(
				desired,
			); err != nil {
				service.Close()
				_ = rollbackOwned()
				return nil, nil, fmt.Errorf(
					"reconcile service %s: %w",
					contract.Name,
					err,
				)
			}
			service.Close()

			owned = append(
				owned,
				approval2ServiceOwnership{
					Contract: contract,
					Original: original,
				},
			)

		default:
			if service != nil {
				service.Close()
			}
			_ = rollbackOwned()
			return nil, nil, fmt.Errorf(
				"unsupported reviewed service presence=%s for %s",
				observed.Presence,
				contract.Name,
			)
		}

		verificationManager, err := mgr.Connect()
		if err != nil {
			_ = rollbackOwned()
			return nil, nil, err
		}
		verified, err := discoverService(
			verificationManager,
			serviceContract{
				DisplayName: contract.DisplayName,
				Name:        contract.Name,
				Path:        contract.Path,
				SIDType:     contract.SIDType,
			},
		)
		verificationManager.Disconnect()
		if err != nil {
			_ = rollbackOwned()
			return nil, nil, fmt.Errorf(
				"verify service %s after SCM mutation: %w",
				contract.Name,
				err,
			)
		}
		if !approval2ServiceConfigMatches(
			verified,
			contract,
		) {
			_ = rollbackOwned()
			return nil, nil, fmt.Errorf(
				"service %s did not converge after SCM mutation: account=%q path=%q managed=%s start=%s sid=%s display=%q",
				contract.Name,
				verified.Account,
				verified.BinaryPath,
				verified.ManagedAccount,
				verified.StartType,
				verified.SIDType,
				verified.DisplayName,
			)
		}
	}

	activate := func() error {
		return startApproval2CreatedServices(
			owned,
		)
	}

	return rollbackOwned, activate, nil
}

func startApproval2CreatedServices(
	owned []approval2ServiceOwnership,
) error {
	created := make(
		map[string]bool,
	)
	for _, item := range owned {
		if item.Created {
			created[item.Contract.Name] = true
		}
	}

	if len(created) == 0 {
		return nil
	}

	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf(
			"connect to service control manager for initial FI start: %w",
			err,
		)
	}
	defer manager.Disconnect()

	start := func(name string) error {
		if !created[name] {
			return nil
		}

		service, err := manager.OpenService(
			name,
		)
		if err != nil {
			return fmt.Errorf(
				"open newly created service %s for initial start: %w",
				name,
				err,
			)
		}
		defer service.Close()

		status, err := service.Query()
		if err != nil {
			return fmt.Errorf(
				"query newly created service %s before initial start: %w",
				name,
				err,
			)
		}

		if status.State == svc.Running {
			return nil
		}

		if err := service.Start(); err != nil {
			return fmt.Errorf(
				"start newly created service %s: %w",
				name,
				err,
			)
		}

		return waitServiceState(
			service,
			svc.Running,
			serviceTransitionTimeout,
		)
	}

	if err := start("FIUSNReader"); err != nil {
		return err
	}
	if err := start("FIObjReader"); err != nil {
		return err
	}

	if err := start("FICollector"); err != nil {
		return err
	}
	if err := start("FISender"); err != nil {
		return err
	}

	return nil
}

func approval2Server2016ServiceContracts(
	identities DesiredFIIdentities,
) []approval2ServiceContract {
	return []approval2ServiceContract{
		{
			Account:     identities.CollectorSender.Account,
			Args:        []string{"-service"},
			DisplayName: "FI Collector",
			Executable:  `C:\Program Files\FI\fi.exe`,
			Name:        "FICollector",
			Path:        `"C:\Program Files\FI\fi.exe" -service`,
			SIDType:     windows.SERVICE_SID_TYPE_UNRESTRICTED,
		},
		{
			Account:     identities.USNReader.Account,
			DisplayName: "FIUSNReader",
			Executable:  `C:\Program Files\FI\fi-usn.exe`,
			Name:        "FIUSNReader",
			Path:        `"C:\Program Files\FI\fi-usn.exe"`,
			SIDType:     windows.SERVICE_SID_TYPE_UNRESTRICTED,
		},
		{
			Account:     identities.ObjReader.Account,
			DisplayName: "FI Object Reader",
			Executable:  `C:\Program Files\FI\fi-obj.exe`,
			Name:        "FIObjReader",
			Path:        `"C:\Program Files\FI\fi-obj.exe"`,
			SIDType:     windows.SERVICE_SID_TYPE_UNRESTRICTED,
		},
		{
			Account:     identities.CollectorSender.Account,
			DisplayName: "FI Sender",
			Executable:  `C:\Program Files\FI\fi-sender.exe`,
			Name:        "FISender",
			Path:        `"C:\Program Files\FI\fi-sender.exe"`,
			SIDType:     windows.SERVICE_SID_TYPE_NONE,
		},
	}
}

func approval2ServiceConfigMatches(
	observed ServiceState,
	contract approval2ServiceContract,
) bool {
	return observed.Presence == presencePresent &&
		strings.EqualFold(
			strings.TrimSpace(
				observed.Account,
			),
			contract.Account,
		) &&
		strings.EqualFold(
			strings.TrimSpace(
				observed.BinaryPath,
			),
			contract.Path,
		) &&
		observed.DisplayName == contract.DisplayName &&
		observed.ManagedAccount == "true" &&
		observed.StartType == "Automatic" &&
		observed.SIDType == serviceSIDTypeName(
			contract.SIDType,
		)
}

func rollbackApproval2Services(
	owned []approval2ServiceOwnership,
) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	var found []error

	for index := len(owned) - 1; index >= 0; index-- {
		item := owned[index]
		service, err := manager.OpenService(
			item.Contract.Name,
		)
		if err != nil {
			if item.Created &&
				errors.Is(
					err,
					windows.ERROR_SERVICE_DOES_NOT_EXIST,
				) {
				continue
			}
			found = append(
				found,
				fmt.Errorf(
					"open service %s for rollback: %w",
					item.Contract.Name,
					err,
				),
			)
			continue
		}

		if item.Created {
			status, queryErr := service.Query()
			if queryErr == nil &&
				status.State != svc.Stopped {
				if status.State != svc.StopPending {
					_, queryErr = service.Control(
						svc.Stop,
					)
				}
				if queryErr == nil {
					queryErr = waitServiceState(
						service,
						svc.Stopped,
						serviceTransitionTimeout,
					)
				}
			}
			if queryErr != nil {
				found = append(
					found,
					fmt.Errorf(
						"stop transaction-created service %s: %w",
						item.Contract.Name,
						queryErr,
					),
				)
				service.Close()
				continue
			}
			if err := service.Delete(); err != nil {
				found = append(
					found,
					fmt.Errorf(
						"delete transaction-created service %s: %w",
						item.Contract.Name,
						err,
					),
				)
			}
			service.Close()
			continue
		}

		original := item.Original
		original.Password = ""
		if err := service.UpdateConfig(
			original,
		); err != nil {
			found = append(
				found,
				fmt.Errorf(
					"restore service %s configuration: %w",
					item.Contract.Name,
					err,
				),
			)
		}
		service.Close()
	}

	return errors.Join(
		found...,
	)
}
