// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type runtimeReconcileSnapshot struct {
	Name        string
	ProcessPath string
	WasRunning  bool
}

func reconcileFIRuntimeServices(
	plan InstallPlan,
) (func() error, error) {
	manager, err :=
		mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf(
			"connect to service control manager for runtime reconciliation: %w",
			err,
		)
	}
	defer manager.Disconnect()

	receiverPending :=
		receiverPendingFromPlan(
			plan,
		)

	contracts :=
		approval2Server2016ServiceContracts(
			plan.Identities,
			receiverPending,
		)

	contractByName :=
		make(
			map[string]approval2ServiceContract,
			len(contracts),
		)

	for _, contract := range contracts {
		contractByName[contract.Name] =
			contract
	}

	snapshots :=
		make(
			[]runtimeReconcileSnapshot,
			0,
			len(contracts),
		)

	fail := func(
		base error,
	) (func() error, error) {
		restoreErr :=
			restoreFIRuntimeReconcileSnapshots(
				snapshots,
			)

		if restoreErr != nil {
			base =
				errors.Join(
					base,
					fmt.Errorf(
						"restore FI runtime state after reconciliation failure: %w",
						restoreErr,
					),
				)
		}

		return nil, base
	}

	for _, name := range []string{
		"FIUSNReader",
		"FIObjReader",
		"FICollector",
		"FICRLRefresher",
		"FISender",
	} {

		if !planTargetMutates(
			plan,
			"RUNTIME",
			name,
		) {
			continue
		}

		contract, found :=
			contractByName[name]
		if !found {
			return fail(
				fmt.Errorf(
					"runtime target %s has no approved service contract",
					name,
				),
			)
		}

		service, err :=
			manager.OpenService(
				name,
			)
		if err != nil {
			return fail(
				fmt.Errorf(
					"open service %s for runtime reconciliation: %w",
					name,
					err,
				),
			)
		}

		status, err :=
			service.Query()
		if err != nil {
			service.Close()

			return fail(
				fmt.Errorf(
					"query service %s for runtime reconciliation: %w",
					name,
					err,
				),
			)
		}

		if status.State != svc.Running &&
			status.State != svc.Stopped {
			service.Close()

			return fail(
				fmt.Errorf(
					"service %s state=%d is not stable enough for runtime reconciliation",
					name,
					status.State,
				),
			)
		}

		snapshot :=
			runtimeReconcileSnapshot{
				Name:       name,
				WasRunning: status.State == svc.Running,
			}

		if snapshot.WasRunning {
			if status.ProcessId == 0 {
				service.Close()

				return fail(
					fmt.Errorf(
						"service %s is Running but SCM reports PID 0 before runtime mutation",
						name,
					),
				)
			}

			snapshot.ProcessPath, err =
				runningProcessPathByID(
					status.ProcessId,
				)
			if err != nil {
				service.Close()

				return fail(
					fmt.Errorf(
						"capture service %s pre-mutation process image PID=%d: %w",
						name,
						status.ProcessId,
						err,
					),
				)
			}
		}

		snapshots =
			append(
				snapshots,
				snapshot,
			)

		desiredRunning :=
			name != "FISender" ||
				!receiverPending

		if !desiredRunning {
			if snapshot.WasRunning {
				if _, err :=
					service.Control(
						svc.Stop,
					); err != nil {
					service.Close()

					return fail(
						fmt.Errorf(
							"stop service %s for desired receiver-pending runtime state: %w",
							name,
							err,
						),
					)
				}

				if err :=
					waitServiceState(
						service,
						svc.Stopped,
						serviceTransitionTimeout,
					); err != nil {
					service.Close()

					return fail(
						fmt.Errorf(
							"wait for service %s to stop: %w",
							name,
							err,
						),
					)
				}
			}

			service.Close()
			continue
		}

		if err :=
			verifyApproval2ServiceStartBoundary(
				contract,
				plan.Identities,
			); err != nil {
			service.Close()

			return fail(
				fmt.Errorf(
					"pre-start security gate for runtime reconciliation %s: %w",
					name,
					err,
				),
			)
		}

		if snapshot.WasRunning {
			if _, err :=
				service.Control(
					svc.Stop,
				); err != nil {
				service.Close()

				return fail(
					fmt.Errorf(
						"stop running service %s for approved process-image restart: %w",
						name,
						err,
					),
				)
			}

			if err :=
				waitServiceState(
					service,
					svc.Stopped,
					serviceTransitionTimeout,
				); err != nil {
				service.Close()

				return fail(
					fmt.Errorf(
						"wait for service %s process-image restart stop: %w",
						name,
						err,
					),
				)
			}
		}

		if err :=
			service.Start(); err != nil {
			service.Close()

			return fail(
				fmt.Errorf(
					"start service %s during runtime reconciliation: %w",
					name,
					err,
				),
			)
		}

		if err :=
			waitServiceState(
				service,
				svc.Running,
				serviceTransitionTimeout,
			); err != nil {
			service.Close()

			return fail(
				fmt.Errorf(
					"wait for service %s to reach Running: %w",
					name,
					err,
				),
			)
		}

		status, err =
			service.Query()
		if err != nil {
			service.Close()

			return fail(
				fmt.Errorf(
					"query service %s after runtime restart: %w",
					name,
					err,
				),
			)
		}

		if status.ProcessId == 0 {
			service.Close()

			return fail(
				fmt.Errorf(
					"service %s reached Running after restart but SCM reports PID 0",
					name,
				),
			)
		}

		processPath, err :=
			runningProcessPathByID(
				status.ProcessId,
			)
		if err != nil {
			service.Close()

			return fail(
				fmt.Errorf(
					"verify service %s post-restart process image PID=%d: %w",
					name,
					status.ProcessId,
					err,
				),
			)
		}

		expectedPath, known :=
			expectedFIServiceExecutablePath(
				name,
			)
		if !known {
			service.Close()

			return fail(
				fmt.Errorf(
					"service %s has no characterized desired executable path",
					name,
				),
			)
		}

		if !sameWindowsExecutablePath(
			processPath,
			expectedPath,
		) {
			service.Close()

			return fail(
				fmt.Errorf(
					"service %s post-restart image=%s expected=%s",
					name,
					processPath,
					expectedPath,
				),
			)
		}

		service.Close()
	}

	rollback :=
		func() error {
			return restoreFIRuntimeReconcileSnapshots(
				snapshots,
			)
		}

	return rollback, nil
}

func restoreFIRuntimeReconcileSnapshots(
	snapshots []runtimeReconcileSnapshot,
) error {
	if len(snapshots) == 0 {
		return nil
	}

	manager, err :=
		mgr.Connect()
	if err != nil {
		return fmt.Errorf(
			"connect to service control manager for runtime rollback: %w",
			err,
		)
	}
	defer manager.Disconnect()

	var found []error

	for index :=
		len(snapshots) - 1; index >= 0; index-- {

		snapshot :=
			snapshots[index]

		service, err :=
			manager.OpenService(
				snapshot.Name,
			)
		if err != nil {
			found =
				append(
					found,
					fmt.Errorf(
						"open service %s for runtime rollback: %w",
						snapshot.Name,
						err,
					),
				)

			continue
		}

		if !snapshot.WasRunning {
			status, queryErr :=
				service.Query()

			if queryErr == nil &&
				status.State != svc.Stopped {

				if status.State != svc.StopPending {
					_, queryErr =
						service.Control(
							svc.Stop,
						)
				}

				if queryErr == nil {
					queryErr =
						waitServiceState(
							service,
							svc.Stopped,
							serviceTransitionTimeout,
						)
				}
			}

			service.Close()

			if queryErr != nil {
				found =
					append(
						found,
						fmt.Errorf(
							"restore service %s to pre-mutation Stopped state: %w",
							snapshot.Name,
							queryErr,
						),
					)
			}

			continue
		}

		config, restoreErr :=
			service.Config()
		if restoreErr != nil {
			service.Close()

			found =
				append(
					found,
					fmt.Errorf(
						"read service %s configuration for runtime rollback: %w",
						snapshot.Name,
						restoreErr,
					),
				)

			continue
		}

		status, restoreErr :=
			service.Query()
		if restoreErr != nil {
			service.Close()

			found =
				append(
					found,
					fmt.Errorf(
						"query service %s for runtime rollback: %w",
						snapshot.Name,
						restoreErr,
					),
				)

			continue
		}

		if status.State == svc.Running &&
			status.ProcessId != 0 {

			currentPath, pathErr :=
				runningProcessPathByID(
					status.ProcessId,
				)

			if pathErr == nil &&
				sameWindowsExecutablePath(
					currentPath,
					snapshot.ProcessPath,
				) {

				service.Close()
				continue
			}
		}

		switch status.State {
		case svc.Running:
			_, restoreErr =
				service.Control(
					svc.Stop,
				)

			if restoreErr == nil {
				restoreErr =
					waitServiceState(
						service,
						svc.Stopped,
						serviceTransitionTimeout,
					)
			}

		case svc.StopPending:
			restoreErr =
				waitServiceState(
					service,
					svc.Stopped,
					serviceTransitionTimeout,
				)

		case svc.Stopped:

		default:
			restoreErr =
				fmt.Errorf(
					"service state=%d is not safe for process-image rollback",
					status.State,
				)
		}

		if restoreErr != nil {
			service.Close()

			found =
				append(
					found,
					fmt.Errorf(
						"stop service %s for process-image rollback: %w",
						snapshot.Name,
						restoreErr,
					),
				)

			continue
		}

		temporaryBinaryPath, pathErr :=
			fiServiceBinaryPathForExecutable(
				snapshot.Name,
				snapshot.ProcessPath,
			)
		if pathErr != nil {
			service.Close()

			found =
				append(
					found,
					fmt.Errorf(
						"build temporary rollback binary path for service %s: %w",
						snapshot.Name,
						pathErr,
					),
				)

			continue
		}

		temporary :=
			config

		temporary.Password = ""
		temporary.BinaryPathName =
			temporaryBinaryPath

		if restoreErr =
			service.UpdateConfig(
				temporary,
			); restoreErr != nil {

			service.Close()

			found =
				append(
					found,
					fmt.Errorf(
						"temporarily restore service %s executable for runtime rollback: %w",
						snapshot.Name,
						restoreErr,
					),
				)

			continue
		}

		restoreOriginalConfig :=
			func() error {
				original :=
					config

				original.Password = ""

				return service.UpdateConfig(
					original,
				)
			}

		if restoreErr =
			service.Start(); restoreErr == nil {

			restoreErr =
				waitServiceState(
					service,
					svc.Running,
					serviceTransitionTimeout,
				)
		}

		if restoreErr == nil {
			status, restoreErr =
				service.Query()
		}

		if restoreErr == nil &&
			status.ProcessId == 0 {

			restoreErr =
				fmt.Errorf(
					"service restarted for rollback but SCM reports PID 0",
				)
		}

		if restoreErr == nil {
			var restoredPath string

			restoredPath, restoreErr =
				runningProcessPathByID(
					status.ProcessId,
				)

			if restoreErr == nil &&
				!sameWindowsExecutablePath(
					restoredPath,
					snapshot.ProcessPath,
				) {

				restoreErr =
					fmt.Errorf(
						"rollback process image=%s expected=%s",
						restoredPath,
						snapshot.ProcessPath,
					)
			}
		}

		configErr :=
			restoreOriginalConfig()

		service.Close()

		if restoreErr != nil ||
			configErr != nil {

			found =
				append(
					found,
					errors.Join(
						restoreErr,
						func() error {
							if configErr == nil {
								return nil
							}

							return fmt.Errorf(
								"restore service configuration after process-image rollback: %w",
								configErr,
							)
						}(),
					),
				)
		}
	}

	return errors.Join(
		found...,
	)
}
