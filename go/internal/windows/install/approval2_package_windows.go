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

	createdProgramDirectories, err := prepareApproval2OwnedDirectories(
		[]string{programDirectory},
	)
	if err != nil {
		return nil, nil, err
	}
	programDirectoryCreated := len(createdProgramDirectories) != 0
	rollbackProgramDirectories := func() error {
		return rollbackApproval2CreatedDirectories(
			createdProgramDirectories,
		)
	}

	snapshots, err := stopApproval2FIServicesForBinaryReplacement()
	if err != nil {
		_ = rollbackProgramDirectories()
		return nil, nil, err
	}

	replaced, err := replaceFileSet(
		replacements,
		transactionID+"-runtime",
	)
	if err != nil {
		_ = startFIServicesFromSnapshot(
			snapshots,
		)
		_ = rollbackProgramDirectories()
		return nil, nil, err
	}

	if err := startFIServicesFromSnapshot(
		snapshots,
	); err != nil {
		_ = stopApproval2ExistingFIServicesBestEffort()
		_ = rollbackReplacedFiles(
			replaced,
		)
		_ = startFIServicesFromSnapshot(
			snapshots,
		)
		_ = rollbackProgramDirectories()
		return nil, nil, fmt.Errorf(
			"restore running FI services after binary replacement: %w",
			err,
		)
	}

	if approval2BrokerPipesWereRunning(
		snapshots,
	) {
		if err := waitForFIBrokerPipes(
			10 * time.Second,
		); err != nil {
			_ = stopApproval2ExistingFIServicesBestEffort()
			_ = rollbackReplacedFiles(
				replaced,
			)
			_ = startFIServicesFromSnapshot(
				snapshots,
			)
			_ = rollbackProgramDirectories()
			return nil, nil, err
		}
	}

	rollback := func() error {
		var found []error

		if err := stopApproval2ExistingFIServicesBestEffort(); err != nil {
			found = append(
				found,
				err,
			)
		}

		if err := rollbackReplacedFiles(
			replaced,
		); err != nil {
			found = append(
				found,
				err,
			)
		}

		if err := startFIServicesFromSnapshot(
			snapshots,
		); err != nil {
			found = append(
				found,
				err,
			)
		}

		if programDirectoryCreated {
			if err := rollbackProgramDirectories(); err != nil {
				found = append(
					found,
					err,
				)
			}
		}

		return errors.Join(
			found...,
		)
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
			_ = rollback()
			return nil, nil, fmt.Errorf(
				"inspect created FI program directory: %w",
				err,
			)
		}
		if !info.IsDir() {
			_ = rollback()
			return nil, nil, errors.New(
				"FI program directory is not a directory after package activation",
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
			_ = startFIServicesFromSnapshot(
				snapshots,
			)
			return nil, fmt.Errorf(
				"open service %s for package stop: %w",
				name,
				err,
			)
		}

		status, err := service.Query()
		if err != nil {
			service.Close()
			_ = startFIServicesFromSnapshot(
				snapshots,
			)
			return nil, fmt.Errorf(
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
				_ = startFIServicesFromSnapshot(
					snapshots,
				)
				return nil, fmt.Errorf(
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
				_ = startFIServicesFromSnapshot(
					snapshots,
				)
				return nil, err
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
