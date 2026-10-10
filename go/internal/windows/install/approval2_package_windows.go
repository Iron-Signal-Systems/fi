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

	legacyRuntimeFiles, err :=
		snapshotApproval2LegacyRuntimeFiles(
			report,
		)
	if err != nil {
		return nil, nil, err
	}

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
		legacyCleanupErr :=
			removeApproval2LegacyRuntimeFiles(
				legacyRuntimeFiles,
			)

		replacementCommitErr :=
			commitReplacedFiles(
				replaced,
			)

		return errors.Join(
			legacyCleanupErr,
			replacementCommitErr,
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

type approval2LegacyRuntimeFile struct {
	Path   string
	SHA256 string
}

type approval2LegacyRuntimeSpec struct {
	BinaryPath        string
	DesiredBinaryPath string
	FilePath          string
	Service           string
}

func approval2LegacyRuntimePaths(
	report Report,
) []string {
	specs :=
		[]approval2LegacyRuntimeSpec{
			{
				BinaryPath:        `"C:\Program Files\FI\fi.exe" -service`,
				DesiredBinaryPath: `"C:\Program Files\FI\fi-collector.exe" -service`,
				FilePath:          `C:\Program Files\FI\fi.exe`,
				Service:           "FICollector",
			},
			{
				BinaryPath:        `"C:\Program Files\FI\fi-usn.exe"`,
				DesiredBinaryPath: `"C:\Program Files\FI\fi-usn-reader.exe"`,
				FilePath:          `C:\Program Files\FI\fi-usn.exe`,
				Service:           "FIUSNReader",
			},
			{
				BinaryPath:        `"C:\Program Files\FI\fi-obj.exe"`,
				DesiredBinaryPath: `"C:\Program Files\FI\fi-obj-reader.exe"`,
				FilePath:          `C:\Program Files\FI\fi-obj.exe`,
				Service:           "FIObjReader",
			},
			{
				BinaryPath:        `"C:\Program Files\FI\fi-crl-refresh.exe"`,
				DesiredBinaryPath: `"C:\Program Files\FI\fi-crl-refresher.exe"`,
				FilePath:          `C:\Program Files\FI\fi-crl-refresh.exe`,
				Service:           "FICRLRefresher",
			},
		}

	result :=
		make(
			[]string,
			0,
			len(specs),
		)

	for _, spec := range specs {
		observed, found :=
			findService(
				report.Services,
				spec.Service,
			)

		if !found ||
			observed.Presence != presencePresent {
			continue
		}

		legacySCMAuthority :=
			strings.EqualFold(
				strings.TrimSpace(
					observed.BinaryPath,
				),
				spec.BinaryPath,
			)

		interruptedMigrationAuthority :=
			observed.State == "Running" &&
				observed.ProcessID != 0 &&
				strings.EqualFold(
					strings.TrimSpace(
						observed.BinaryPath,
					),
					spec.DesiredBinaryPath,
				) &&
				sameWindowsExecutablePath(
					observed.ProcessPath,
					spec.FilePath,
				)

		if !legacySCMAuthority &&
			!interruptedMigrationAuthority {
			continue
		}

		result =
			append(
				result,
				spec.FilePath,
			)
	}

	return result
}

func removeApproval2LegacyRuntimeFiles(
	files []approval2LegacyRuntimeFile,
) error {
	for _, file := range files {
		info, err :=
			os.Lstat(
				file.Path,
			)

		if errors.Is(
			err,
			os.ErrNotExist,
		) {
			continue
		}

		if err != nil {
			return fmt.Errorf(
				"inspect legacy FI runtime %s before retirement: %w",
				file.Path,
				err,
			)
		}

		if info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() {
			return fmt.Errorf(
				"refusing to retire legacy FI runtime because it is not a regular non-symlink file: %s",
				file.Path,
			)
		}

		currentSHA256, err :=
			fileSHA256(
				file.Path,
			)
		if err != nil {
			return fmt.Errorf(
				"hash legacy FI runtime %s before retirement: %w",
				file.Path,
				err,
			)
		}

		if !strings.EqualFold(
			currentSHA256,
			file.SHA256,
		) {
			return fmt.Errorf(
				"refusing to retire changed legacy FI runtime %s: reviewed_sha256=%s current_sha256=%s",
				file.Path,
				file.SHA256,
				currentSHA256,
			)
		}
	}

	var found []error

	for _, file := range files {
		err :=
			removeFileWithRetry(
				file.Path,
				5*time.Second,
			)

		if err == nil ||
			errors.Is(
				err,
				os.ErrNotExist,
			) {
			continue
		}

		found =
			append(
				found,
				fmt.Errorf(
					"retire legacy FI runtime %s: %w",
					file.Path,
					err,
				),
			)
	}

	return errors.Join(
		found...,
	)
}

func snapshotApproval2LegacyRuntimeFiles(
	report Report,
) ([]approval2LegacyRuntimeFile, error) {
	paths :=
		approval2LegacyRuntimePaths(
			report,
		)

	result :=
		make(
			[]approval2LegacyRuntimeFile,
			0,
			len(paths),
		)

	for _, path := range paths {
		info, err :=
			os.Lstat(
				path,
			)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect legacy FI runtime %s before migration: %w",
				path,
				err,
			)
		}

		if info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() {
			return nil, fmt.Errorf(
				"legacy FI runtime is not a regular non-symlink file: %s",
				path,
			)
		}

		hash, err :=
			fileSHA256(
				path,
			)
		if err != nil {
			return nil, fmt.Errorf(
				"hash legacy FI runtime %s before migration: %w",
				path,
				err,
			)
		}

		result =
			append(
				result,
				approval2LegacyRuntimeFile{
					Path:   path,
					SHA256: hash,
				},
			)
	}

	return result, nil
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

			return snapshots, fmt.Errorf(
				"open service %s for package stop: %w",
				name,
				err,
			)
		}

		status, err := service.Query()
		if err != nil {
			service.Close()

			return snapshots, fmt.Errorf(
				"query service %s before package stop: %w",
				name,
				err,
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

				return snapshots, fmt.Errorf(
					"stop service %s for package replacement: %w",
					name,
					err,
				)
			}

			if err := waitServiceState(
				service,
				svc.Stopped,
				serviceTransitionTimeout,
			); err != nil {
				service.Close()

				return snapshots, err
			}
		}

		service.Close()
	}

	return snapshots, nil
}

func restoreApproval2FIServicesFromSnapshot(
	snapshots []serviceRuntimeSnapshot,
) error {
	if len(snapshots) == 0 {
		return nil
	}

	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf(
			"connect to service control manager for Approval 2 runtime restoration: %w",
			err,
		)
	}
	defer manager.Disconnect()

	required := make(
		map[string]bool,
		len(snapshots),
	)

	for _, snapshot := range snapshots {
		required[snapshot.Name] =
			snapshot.WasRunning
	}

	var found []error

	for _, name := range []string{
		"FICollector",
		"FIUSNReader",
		"FIObjReader",
		"FICRLRefresher",
		"FISender",
	} {
		wantRunning, tracked :=
			required[name]
		if !tracked ||
			wantRunning {
			continue
		}

		service, err :=
			manager.OpenService(
				name,
			)
		if err != nil {
			found = append(
				found,
				fmt.Errorf(
					"open service %s for stopped-state restoration: %w",
					name,
					err,
				),
			)
			continue
		}

		status, queryErr :=
			service.Query()
		if queryErr != nil {
			service.Close()

			found = append(
				found,
				fmt.Errorf(
					"query service %s for stopped-state restoration: %w",
					name,
					queryErr,
				),
			)
			continue
		}

		switch status.State {
		case svc.Stopped:

		case svc.StopPending:
			queryErr =
				waitServiceState(
					service,
					svc.Stopped,
					serviceTransitionTimeout,
				)

		default:
			_, queryErr =
				service.Control(
					svc.Stop,
				)
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
			found = append(
				found,
				fmt.Errorf(
					"restore service %s to Stopped: %w",
					name,
					queryErr,
				),
			)
		}
	}

	for _, name := range []string{
		"FIUSNReader",
		"FIObjReader",
		"FICollector",
		"FICRLRefresher",
		"FISender",
	} {
		wantRunning, tracked :=
			required[name]
		if !tracked ||
			!wantRunning {
			continue
		}

		service, err :=
			manager.OpenService(
				name,
			)
		if err != nil {
			found = append(
				found,
				fmt.Errorf(
					"open service %s for running-state restoration: %w",
					name,
					err,
				),
			)
			continue
		}

		status, queryErr :=
			service.Query()
		if queryErr != nil {
			service.Close()

			found = append(
				found,
				fmt.Errorf(
					"query service %s for running-state restoration: %w",
					name,
					queryErr,
				),
			)
			continue
		}

		switch status.State {
		case svc.Running:

		case svc.StartPending:
			queryErr =
				waitServiceState(
					service,
					svc.Running,
					serviceTransitionTimeout,
				)

		case svc.StopPending:
			queryErr =
				waitServiceState(
					service,
					svc.Stopped,
					serviceTransitionTimeout,
				)
			if queryErr == nil {
				queryErr =
					service.Start()
			}
			if queryErr == nil {
				queryErr =
					waitServiceState(
						service,
						svc.Running,
						serviceTransitionTimeout,
					)
			}

		case svc.Stopped:
			queryErr =
				service.Start()
			if queryErr == nil {
				queryErr =
					waitServiceState(
						service,
						svc.Running,
						serviceTransitionTimeout,
					)
			}

		default:
			queryErr =
				fmt.Errorf(
					"service state=%d is not safe for automatic running-state restoration",
					status.State,
				)
		}

		service.Close()

		if queryErr != nil {
			found = append(
				found,
				fmt.Errorf(
					"restore service %s to Running: %w",
					name,
					queryErr,
				),
			)
		}
	}

	return errors.Join(
		found...,
	)
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
