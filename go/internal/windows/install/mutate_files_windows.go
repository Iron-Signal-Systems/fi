// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceTransitionTimeout = 30 * time.Second

type fileReplacement struct {
	Destination    string
	ExpectedSHA256 string
	Source         string
}

type replacedFile struct {
	Backup      string
	Destination string
	HadOriginal bool
}

type serviceRuntimeSnapshot struct {
	Name       string
	WasRunning bool
}

func installReleaseTrust(report Report, transactionID string) (func() error, func() error, error) {
	if !report.ReleaseTrust.Package.Valid ||
		!report.ReleaseTrust.Package.AuthorityPinned ||
		!report.ReleaseTrust.TransitionAllowed {
		return nil, nil, fmt.Errorf("package release-trust policy is not an authorized transition")
	}

	createdDirectory := false
	if _, err := os.Stat(installedReleaseTrustRoot); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(installedReleaseTrustRoot, 0o755); err != nil {
			return nil, nil, fmt.Errorf("create FI release-trust directory: %w", err)
		}
		createdDirectory = true
	} else if err != nil {
		return nil, nil, fmt.Errorf("stat FI release-trust directory: %w", err)
	}

	previousSDDL, err := captureNamedSecurityDescriptorSDDL(installedReleaseTrustRoot)
	if err != nil {
		if createdDirectory {
			_ = os.Remove(installedReleaseTrustRoot)
		}
		return nil, nil, err
	}
	if err := setNamedSecurityDescriptorFromSDDL(installedReleaseTrustRoot, desiredProtectedDirectorySDDL(nil)); err != nil {
		if createdDirectory {
			_ = os.Remove(installedReleaseTrustRoot)
		}
		return nil, nil, err
	}

	if report.ReleaseTrust.Installed.Present &&
		report.ReleaseTrust.Package.Present &&
		strings.EqualFold(report.ReleaseTrust.Installed.PolicySHA256, report.ReleaseTrust.Package.PolicySHA256) {
		rollback := func() error {
			return restoreNamedSecurityDescriptorFromSDDL(installedReleaseTrustRoot, previousSDDL)
		}
		return rollback, func() error { return nil }, nil
	}

	policyDestination := filepath.Join(installedReleaseTrustRoot, releaseTrustPolicyFileName)
	signatureDestination := filepath.Join(installedReleaseTrustRoot, releaseTrustPolicySignatureName)
	replaced, err := replaceFileSet([]fileReplacement{
		{
			Destination:    policyDestination,
			ExpectedSHA256: report.ReleaseTrust.Package.PolicySHA256,
			Source:         report.ReleaseTrust.Package.Path,
		},
		{
			Destination: signatureDestination,
			Source:      report.ReleaseTrust.Package.SignaturePath,
		},
	}, transactionID+"-trust")
	if err != nil {
		_ = restoreNamedSecurityDescriptorFromSDDL(installedReleaseTrustRoot, previousSDDL)
		if createdDirectory {
			_ = os.Remove(installedReleaseTrustRoot)
		}
		return nil, nil, err
	}

	installed := discoverReleaseTrustDocument(
		policyDestination,
		signatureDestination,
		report.ReleaseTrust.BootstrapAuthoritySPKISHA256,
	)
	if !installed.Valid || !strings.EqualFold(installed.PolicySHA256, report.ReleaseTrust.Package.PolicySHA256) {
		_ = rollbackReplacedFiles(replaced)
		_ = restoreNamedSecurityDescriptorFromSDDL(installedReleaseTrustRoot, previousSDDL)
		if createdDirectory {
			_ = os.Remove(installedReleaseTrustRoot)
		}
		return nil, nil, fmt.Errorf("installed FI release-trust policy did not re-verify exactly after copy")
	}

	rollback := func() error {
		first := rollbackReplacedFiles(replaced)
		if err := restoreNamedSecurityDescriptorFromSDDL(installedReleaseTrustRoot, previousSDDL); err != nil && first == nil {
			first = err
		}
		if createdDirectory {
			if err := os.Remove(installedReleaseTrustRoot); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
				first = err
			}
		}
		return first
	}
	commit := func() error {
		return commitReplacedFiles(replaced)
	}
	return rollback, commit, nil
}

func replaceRuntimeBinaries(report Report, transactionID string) (func() error, func() error, error) {
	if !report.Package.ManifestValid ||
		!report.Package.PayloadHashesMatch ||
		!report.Package.AuthenticodeFilesTrusted ||
		!report.Package.AuthenticodeSignerIdentitiesComplete ||
		!report.Package.AuthenticodeSignersAuthorized ||
		!report.ReleaseTrust.ManifestSignerAuthorized {
		return nil, nil, fmt.Errorf("authenticated FI package preconditions are not satisfied")
	}

	replacements := make([]fileReplacement, 0, len(report.Package.Files))
	for _, file := range report.Package.Files {
		if !file.PayloadMatch || !file.PayloadAuthenticodeTrusted || !file.PayloadAuthenticodeSignerAuthorized {
			return nil, nil, fmt.Errorf("payload %s is not fully authenticated and authorized", file.Role)
		}
		if strings.TrimSpace(file.InstalledPath) == "" {
			return nil, nil, fmt.Errorf("payload %s has no installed destination", file.Role)
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

	snapshots, err := stopFIServicesForBinaryReplacement()
	if err != nil {
		return nil, nil, err
	}

	replaced, err := replaceFileSet(replacements, transactionID+"-runtime")
	if err != nil {
		_ = startFIServicesFromSnapshot(snapshots)
		return nil, nil, err
	}
	if err := startFIServicesFromSnapshot(snapshots); err != nil {
		_ = stopFIServicesBestEffort()
		_ = rollbackReplacedFiles(replaced)
		_ = startFIServicesFromSnapshot(snapshots)
		return nil, nil, fmt.Errorf("start FI services after binary replacement: %w", err)
	}
	if err := waitForFIBrokerPipes(10 * time.Second); err != nil {
		_ = stopFIServicesBestEffort()
		_ = rollbackReplacedFiles(replaced)
		_ = startFIServicesFromSnapshot(snapshots)
		return nil, nil, err
	}

	rollback := func() error {
		_ = stopFIServicesBestEffort()
		first := rollbackReplacedFiles(replaced)
		if err := startFIServicesFromSnapshot(snapshots); err != nil && first == nil {
			first = err
		}
		return first
	}
	commit := func() error {
		return commitReplacedFiles(replaced)
	}
	return rollback, commit, nil
}

func replaceFileSet(files []fileReplacement, transactionID string) ([]replacedFile, error) {
	replaced := make([]replacedFile, 0, len(files))
	for _, file := range files {
		if strings.TrimSpace(file.Source) == "" || strings.TrimSpace(file.Destination) == "" {
			_ = rollbackReplacedFiles(replaced)
			return nil, fmt.Errorf("source and destination are required for file replacement")
		}

		sourceInfo, err := os.Lstat(file.Source)
		if err != nil {
			_ = rollbackReplacedFiles(replaced)
			return nil, fmt.Errorf("stat replacement source %s: %w", file.Source, err)
		}
		if sourceInfo.Mode()&os.ModeSymlink != 0 || !sourceInfo.Mode().IsRegular() {
			_ = rollbackReplacedFiles(replaced)
			return nil, fmt.Errorf("replacement source must be a regular non-symlink file: %s", file.Source)
		}

		destinationDirectory := filepath.Dir(file.Destination)
		if err := os.MkdirAll(destinationDirectory, 0o755); err != nil {
			_ = rollbackReplacedFiles(replaced)
			return nil, fmt.Errorf("create destination directory %s: %w", destinationDirectory, err)
		}

		stage := file.Destination + ".fi-new-" + transactionID
		backup := file.Destination + ".fi-old-" + transactionID
		_ = os.Remove(stage)
		if err := copyFileExclusive(file.Source, stage); err != nil {
			_ = rollbackReplacedFiles(replaced)
			return nil, err
		}
		if file.ExpectedSHA256 != "" {
			hash, err := fileSHA256(stage)
			if err != nil {
				_ = os.Remove(stage)
				_ = rollbackReplacedFiles(replaced)
				return nil, err
			}
			if !strings.EqualFold(hash, file.ExpectedSHA256) {
				_ = os.Remove(stage)
				_ = rollbackReplacedFiles(replaced)
				return nil, fmt.Errorf("staged file hash mismatch destination=%s expected=%s actual=%s", file.Destination, file.ExpectedSHA256, hash)
			}
		}

		hadOriginal := false
		if _, err := os.Lstat(file.Destination); err == nil {
			hadOriginal = true
			_ = os.Remove(backup)
			if err := os.Rename(file.Destination, backup); err != nil {
				_ = os.Remove(stage)
				_ = rollbackReplacedFiles(replaced)
				return nil, fmt.Errorf("backup installed file %s: %w", file.Destination, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(stage)
			_ = rollbackReplacedFiles(replaced)
			return nil, fmt.Errorf("stat installed file %s: %w", file.Destination, err)
		}

		if err := os.Rename(stage, file.Destination); err != nil {
			if hadOriginal {
				_ = os.Rename(backup, file.Destination)
			}
			_ = os.Remove(stage)
			_ = rollbackReplacedFiles(replaced)
			return nil, fmt.Errorf("activate replacement file %s: %w", file.Destination, err)
		}
		if file.ExpectedSHA256 != "" {
			hash, err := fileSHA256(file.Destination)
			if err != nil || !strings.EqualFold(hash, file.ExpectedSHA256) {
				_ = os.Remove(file.Destination)
				if hadOriginal {
					_ = os.Rename(backup, file.Destination)
				}
				_ = rollbackReplacedFiles(replaced)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("activated file hash mismatch destination=%s expected=%s actual=%s", file.Destination, file.ExpectedSHA256, hash)
			}
		}

		replaced = append(replaced, replacedFile{Backup: backup, Destination: file.Destination, HadOriginal: hadOriginal})
	}
	return replaced, nil
}

func commitReplacedFiles(replaced []replacedFile) error {
	var first error
	for _, file := range replaced {
		if !file.HadOriginal {
			continue
		}
		if err := os.Remove(file.Backup); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}

func rollbackReplacedFiles(
	replaced []replacedFile,
) error {
	var first error
	for index := len(replaced) - 1; index >= 0; index-- {
		file := replaced[index]

		if err := removeFileWithRetry(
			file.Destination,
			5*time.Second,
		); err != nil &&
			!errors.Is(
				err,
				os.ErrNotExist,
			) {
			if first == nil {
				first = err
			}
			continue
		}

		if file.HadOriginal {
			if err := renameFileWithRetry(
				file.Backup,
				file.Destination,
				5*time.Second,
			); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func removeFileWithRetry(
	path string,
	timeout time.Duration,
) error {
	deadline := time.Now().Add(
		timeout,
	)
	var last error
	for {
		err := os.Remove(
			path,
		)
		if err == nil ||
			errors.Is(
				err,
				os.ErrNotExist,
			) {
			return err
		}
		last = err
		if time.Now().After(
			deadline,
		) {
			return fmt.Errorf(
				"remove %s after %s of retries: %w",
				path,
				timeout,
				last,
			)
		}
		time.Sleep(
			100 * time.Millisecond,
		)
	}
}

func renameFileWithRetry(
	oldPath string,
	newPath string,
	timeout time.Duration,
) error {
	deadline := time.Now().Add(
		timeout,
	)
	var last error
	for {
		err := os.Rename(
			oldPath,
			newPath,
		)
		if err == nil {
			return nil
		}
		last = err
		if time.Now().After(
			deadline,
		) {
			return fmt.Errorf(
				"rename %s to %s after %s of retries: %w",
				oldPath,
				newPath,
				timeout,
				last,
			)
		}
		time.Sleep(
			100 * time.Millisecond,
		)
	}
}

func copyFileExclusive(source string, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %s: %w", source, err)
	}
	defer input.Close()

	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create staged file %s: %w", destination, err)
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		_ = os.Remove(destination)
		return fmt.Errorf("copy %s to %s: %w", source, destination, err)
	}
	if err := output.Sync(); err != nil {
		output.Close()
		_ = os.Remove(destination)
		return fmt.Errorf("sync staged file %s: %w", destination, err)
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("close staged file %s: %w", destination, err)
	}
	return nil
}

func stopFIServicesForBinaryReplacement() ([]serviceRuntimeSnapshot, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect to service control manager: %w", err)
	}
	defer manager.Disconnect()

	order := []string{"FICollector", "FIUSNReader", "FIObjReader", "FISender"}
	snapshots := make([]serviceRuntimeSnapshot, 0, len(order))
	for _, name := range order {
		service, err := manager.OpenService(name)
		if err != nil {
			_ = startFIServicesFromSnapshot(snapshots)
			return nil, fmt.Errorf("open service %s for stop: %w", name, err)
		}
		status, err := service.Query()
		if err != nil {
			service.Close()
			_ = startFIServicesFromSnapshot(snapshots)
			return nil, fmt.Errorf("query service %s before stop: %w", name, err)
		}
		snapshots = append(snapshots, serviceRuntimeSnapshot{Name: name, WasRunning: status.State == svc.Running})
		if status.State == svc.Running {
			if _, err := service.Control(svc.Stop); err != nil {
				service.Close()
				_ = startFIServicesFromSnapshot(snapshots)
				return nil, fmt.Errorf("stop service %s: %w", name, err)
			}
			if err := waitServiceState(service, svc.Stopped, serviceTransitionTimeout); err != nil {
				service.Close()
				_ = startFIServicesFromSnapshot(snapshots)
				return nil, err
			}
		}
		service.Close()
	}
	return snapshots, nil
}

func startFIServicesFromSnapshot(snapshots []serviceRuntimeSnapshot) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service control manager: %w", err)
	}
	defer manager.Disconnect()

	required := make(map[string]bool, len(snapshots))
	for _, snapshot := range snapshots {
		required[snapshot.Name] = snapshot.WasRunning
	}
	for _, name := range []string{"FIUSNReader", "FIObjReader", "FICollector", "FISender"} {
		if !required[name] {
			continue
		}
		service, err := manager.OpenService(name)
		if err != nil {
			return fmt.Errorf("open service %s for start: %w", name, err)
		}
		status, err := service.Query()
		if err != nil {
			service.Close()
			return fmt.Errorf("query service %s before start: %w", name, err)
		}
		if status.State != svc.Running {
			if err := service.Start(); err != nil {
				service.Close()
				return fmt.Errorf("start service %s: %w", name, err)
			}
			if err := waitServiceState(service, svc.Running, serviceTransitionTimeout); err != nil {
				service.Close()
				return err
			}
		}
		service.Close()
	}
	return nil
}

func stopFIServicesBestEffort() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	var first error
	for _, name := range []string{"FICollector", "FIUSNReader", "FIObjReader", "FISender"} {
		service, err := manager.OpenService(name)
		if err != nil {
			if first == nil {
				first = err
			}
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
		if queryErr != nil && first == nil {
			first = queryErr
		}
	}
	return first
}

func waitForFIBrokerPipes(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		allPresent := true
		for _, name := range []string{"FI-USN", "FI-OBJ"} {
			present, err := namedPipePresent(name)
			if err != nil {
				allPresent = false
				break
			}
			if !present {
				allPresent = false
				break
			}
		}
		if allPresent {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("FI broker pipes were not ready within %s after service restart", timeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func waitServiceState(service *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := service.Query()
		if err != nil {
			return fmt.Errorf("query service %s while waiting for state %d: %w", service.Name, want, err)
		}
		if status.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service %s did not reach state %d within %s; current=%d", service.Name, want, timeout, status.State)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
