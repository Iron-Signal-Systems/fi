// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func replaceApproval2RuntimeBinaries(
	report Report,
	transactionID string,
) (func() error, func() error, error) {
	if !report.Package.ManifestValid ||
		!report.Package.PayloadHashesMatch ||
		!report.Package.AuthenticodeFilesTrusted ||
		!report.Package.AuthenticodeSignerIdentitiesComplete ||
		!report.Package.AuthenticodeSignersAuthorized ||
		!report.ReleaseTrust.ManifestSignerAuthorized {
		return nil, nil, errors.New(
			"authenticated FI package preconditions are not satisfied",
		)
	}

	replacements := make(
		[]fileReplacement,
		0,
		len(report.Package.Files),
	)

	for _, file := range report.Package.Files {
		if !file.PayloadMatch ||
			!file.PayloadAuthenticodeTrusted ||
			!file.PayloadAuthenticodeSignerAuthorized {
			return nil, nil, fmt.Errorf(
				"payload %s is not fully authenticated and authorized",
				file.Role,
			)
		}

		if strings.TrimSpace(
			file.InstalledPath,
		) == "" {
			return nil, nil, fmt.Errorf(
				"payload %s has no installed destination",
				file.Role,
			)
		}

		if file.Match {
			continue
		}

		replacements = append(
			replacements,
			fileReplacement{
				Destination:    file.InstalledPath,
				ExpectedSHA256: file.ExpectedSHA256,
				Source:         file.PayloadPath,
			},
		)
	}

	programDirectory := `C:\Program Files\FI`

	if err := validateApproval2RuntimeBinaryDestinations(
		replacements,
		programDirectory,
	); err != nil {
		return nil, nil, err
	}

	createdProgramDirectories, err :=
		prepareApproval2OwnedDirectories(
			[]string{
				programDirectory,
			},
		)
	if err != nil {
		return nil, nil, err
	}

	programDirectoryCreated :=
		len(createdProgramDirectories) != 0

	rollbackProgramDirectories := func() error {
		return rollbackApproval2CreatedDirectories(
			createdProgramDirectories,
		)
	}

	snapshots, err :=
		stopApproval2FIServicesForBinaryReplacement()
	if err != nil {
		return nil, nil, joinFIRecoveryFailures(
			err,
			fiRecoveryStep{
				name: "rollback transaction-created FI program directories",
				run:  rollbackProgramDirectories,
			},
		)
	}

	replaced, err := replaceFileSet(
		replacements,
		transactionID+"-runtime",
	)
	if err != nil {
		return nil, nil, joinFIRecoveryFailures(
			err,
			fiRecoveryStep{
				name: "restore FI service runtime snapshot",
				run: func() error {
					return startFIServicesFromSnapshot(
						snapshots,
					)
				},
			},
			fiRecoveryStep{
				name: "rollback transaction-created FI program directories",
				run:  rollbackProgramDirectories,
			},
		)
	}

	recoverPackage := func() error {
		steps := []fiRecoveryStep{
			{
				name: "stop FI services before Approval 2 package rollback",
				run:  stopApproval2ExistingFIServicesBestEffort,
			},
			{
				name: "rollback Approval 2 runtime binaries",
				run: func() error {
					return rollbackReplacedFiles(
						replaced,
					)
				},
			},
			{
				name: "restore FI service runtime snapshot",
				run: func() error {
					return startFIServicesFromSnapshot(
						snapshots,
					)
				},
			},
		}

		if programDirectoryCreated {
			steps = append(
				steps,
				fiRecoveryStep{
					name: "rollback transaction-created FI program directories",
					run:  rollbackProgramDirectories,
				},
			)
		}

		return runFIRecoverySteps(
			steps...,
		)
	}

	if err := startFIServicesFromSnapshot(
		snapshots,
	); err != nil {
		base := fmt.Errorf(
			"restore running FI services after binary replacement: %w",
			err,
		)

		return nil, nil, joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "rollback failed Approval 2 package activation",
				run:  recoverPackage,
			},
		)
	}

	if approval2BrokerPipesWereRunning(
		snapshots,
	) {
		if err := waitForFIBrokerPipes(
			10 * time.Second,
		); err != nil {
			return nil, nil, joinFIRecoveryFailures(
				err,
				fiRecoveryStep{
					name: "rollback Approval 2 package after broker-readiness failure",
					run:  recoverPackage,
				},
			)
		}
	}

	rollback := func() error {
		return recoverPackage()
	}

	commit := func() error {
		return commitReplacedFiles(
			replaced,
		)
	}

	if programDirectoryCreated {
		info, err := os.Lstat(
			programDirectory,
		)
		if err != nil {
			base := fmt.Errorf(
				"inspect created FI program directory: %w",
				err,
			)

			return nil, nil, joinFIRecoveryFailures(
				base,
				fiRecoveryStep{
					name: "rollback Approval 2 package",
					run:  rollback,
				},
			)
		}

		if !info.IsDir() {
			return nil, nil, joinFIRecoveryFailures(
				errors.New(
					"FI program directory is not a directory after package activation",
				),
				fiRecoveryStep{
					name: "rollback Approval 2 package",
					run:  rollback,
				},
			)
		}
	}

	return rollback, commit, nil
}
func validateApproval2RuntimeBinaryDestinations(
	replacements []fileReplacement,
	programDirectory string,
) error {
	expectedDirectory := filepath.Clean(
		strings.TrimSpace(
			programDirectory,
		),
	)
	if expectedDirectory == "" ||
		expectedDirectory == "." {
		return errors.New(
			"fixed FI program directory is empty",
		)
	}

	for _, file := range replacements {
		destination := filepath.Clean(
			strings.TrimSpace(
				file.Destination,
			),
		)
		if destination == "" ||
			destination == "." {
			return errors.New(
				"package replacement destination is empty",
			)
		}

		if !strings.EqualFold(
			filepath.Clean(
				filepath.Dir(
					destination,
				),
			),
			expectedDirectory,
		) {
			return fmt.Errorf(
				"package destination escaped fixed FI program directory: %s",
				file.Destination,
			)
		}
	}

	return nil
}

func stopApproval2FIServicesForBinaryReplacement() (
	[]serviceRuntimeSnapshot,
	error,
) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf(
			"connect to service control manager: %w",
			err,
		)
	}
	defer manager.Disconnect()

	order := []string{
		"FICollector",
		"FIUSNReader",
		"FIObjReader",
		"FICRLRefresher",
		"FISender",
	}

	snapshots := make(
		[]serviceRuntimeSnapshot,
		0,
		len(order),
	)

	recoverSnapshot := func() error {
		return startFIServicesFromSnapshot(
			snapshots,
		)
	}

	fail := func(
		base error,
	) ([]serviceRuntimeSnapshot, error) {
		return nil, joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "restore FI services after Approval 2 package-stop failure",
				run:  recoverSnapshot,
			},
		)
	}

	for _, name := range order {
		service, err := manager.OpenService(
			name,
		)
		if err != nil {
			if errors.Is(
				err,
				windows.ERROR_SERVICE_DOES_NOT_EXIST,
			) {
				continue
			}

			return fail(
				fmt.Errorf(
					"open service %s for package stop: %w",
					name,
					err,
				),
			)
		}

		status, err := service.Query()
		if err != nil {
			service.Close()

			return fail(
				fmt.Errorf(
					"query service %s before package stop: %w",
					name,
					err,
				),
			)
		}

		snapshots = append(
			snapshots,
			serviceRuntimeSnapshot{
				Name:       name,
				WasRunning: status.State == svc.Running,
			},
		)

		if status.State == svc.Running {
			if _, err := service.Control(
				svc.Stop,
			); err != nil {
				service.Close()

				return fail(
					fmt.Errorf(
						"stop service %s for package replacement: %w",
						name,
						err,
					),
				)
			}

			if err := waitServiceState(
				service,
				svc.Stopped,
				serviceTransitionTimeout,
			); err != nil {
				service.Close()

				return fail(
					err,
				)
			}
		}

		service.Close()
	}

	return snapshots, nil
}
func stopApproval2ExistingFIServicesBestEffort() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	var found []error
	for _, name := range []string{
		"FICollector",
		"FIUSNReader",
		"FIObjReader",
		"FICRLRefresher",
		"FISender",
	} {
		service, err := manager.OpenService(
			name,
		)
		if err != nil {
			if errors.Is(
				err,
				windows.ERROR_SERVICE_DOES_NOT_EXIST,
			) {
				continue
			}
			found = append(
				found,
				err,
			)
			continue
		}

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
		service.Close()

		if queryErr != nil {
			found = append(
				found,
				queryErr,
			)
		}
	}

	return errors.Join(
		found...,
	)
}

func approval2BrokerPipesWereRunning(
	snapshots []serviceRuntimeSnapshot,
) bool {
	usn := false
	obj := false

	for _, snapshot := range snapshots {
		switch snapshot.Name {
		case "FIUSNReader":
			usn = snapshot.WasRunning
		case "FIObjReader":
			obj = snapshot.WasRunning
		}
	}

	return usn && obj
}
