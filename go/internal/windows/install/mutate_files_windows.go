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

func failFileReplacementTransaction(
	base error,
	replaced []replacedFile,
	stage string,
) error {
	if base == nil {
		base = errors.New(
			"file replacement transaction failed",
		)
	}

	var found []error
	found = append(
		found,
		base,
	)

	stage = strings.TrimSpace(
		stage,
	)

	if stage != "" {
		if err := removeFileWithRetry(
			stage,
			5*time.Second,
		); err != nil &&
			!errors.Is(
				err,
				os.ErrNotExist,
			) {
			found = append(
				found,
				fmt.Errorf(
					"remove staged replacement %s: %w",
					stage,
					err,
				),
			)
		}
	}

	if err := rollbackReplacedFiles(
		replaced,
	); err != nil {
		found = append(
			found,
			fmt.Errorf(
				"rollback replaced files: %w",
				err,
			),
		)
	}

	return errors.Join(
		found...,
	)
}

type fiRecoveryStep struct {
	name string
	run  func() error
}

func runFIRecoverySteps(
	steps ...fiRecoveryStep,
) error {
	var found []error

	for _, step := range steps {
		if step.run == nil {
			continue
		}

		if err := step.run(); err != nil {
			name := strings.TrimSpace(
				step.name,
			)
			if name == "" {
				name = "FI recovery step"
			}

			found = append(
				found,
				fmt.Errorf(
					"%s: %w",
					name,
					err,
				),
			)
		}
	}

	return errors.Join(
		found...,
	)
}

func joinFIRecoveryFailures(
	base error,
	steps ...fiRecoveryStep,
) error {
	if base == nil {
		base = errors.New(
			"FI transaction failed",
		)
	}

	return errors.Join(
		base,
		runFIRecoverySteps(
			steps...,
		),
	)
}
func installReleaseTrust(
	report Report,
	transactionID string,
) (func() error, func() error, error) {
	if !report.ReleaseTrust.Package.Valid ||
		!report.ReleaseTrust.Package.AuthorityPinned ||
		!report.ReleaseTrust.TransitionAllowed {
		return nil, nil, fmt.Errorf(
			"package release-trust policy is not an authorized transition",
		)
	}

	createdDirectory := false

	if _, err := os.Stat(
		installedReleaseTrustRoot,
	); errors.Is(
		err,
		os.ErrNotExist,
	) {
		if err := os.MkdirAll(
			installedReleaseTrustRoot,
			0o755,
		); err != nil {
			return nil, nil, fmt.Errorf(
				"create FI release-trust directory: %w",
				err,
			)
		}

		createdDirectory = true
	} else if err != nil {
		return nil, nil, fmt.Errorf(
			"stat FI release-trust directory: %w",
			err,
		)
	}

	removeCreatedDirectory := func() error {
		if !createdDirectory {
			return nil
		}

		err := os.Remove(
			installedReleaseTrustRoot,
		)
		if err == nil ||
			errors.Is(
				err,
				os.ErrNotExist,
			) {
			return nil
		}

		return fmt.Errorf(
			"remove transaction-created FI release-trust directory: %w",
			err,
		)
	}

	previousSDDL, err :=
		captureNamedSecurityDescriptorSDDL(
			installedReleaseTrustRoot,
		)
	if err != nil {
		return nil, nil, joinFIRecoveryFailures(
			err,
			fiRecoveryStep{
				name: "remove transaction-created FI release-trust directory",
				run:  removeCreatedDirectory,
			},
		)
	}

	replaced := make(
		[]replacedFile,
		0,
		2,
	)

	rollback := func() error {
		var found []error

		if err := rollbackReplacedFiles(
			replaced,
		); err != nil {
			found = append(
				found,
				fmt.Errorf(
					"rollback FI release-trust files: %w",
					err,
				),
			)
		}

		if err := restoreNamedSecurityDescriptorFromSDDL(
			installedReleaseTrustRoot,
			previousSDDL,
		); err != nil {
			found = append(
				found,
				fmt.Errorf(
					"restore FI release-trust directory security descriptor: %w",
					err,
				),
			)
		}

		if err := removeCreatedDirectory(); err != nil {
			found = append(
				found,
				err,
			)
		}

		return errors.Join(
			found...,
		)
	}

	// Rollback ownership exists before the ACL mutation. A native security
	// descriptor write can fail after changing part of the target state.
	if err := setNamedSecurityDescriptorFromSDDL(
		installedReleaseTrustRoot,
		desiredProtectedDirectorySDDL(
			nil,
		),
	); err != nil {
		return nil, nil, joinFIRecoveryFailures(
			err,
			fiRecoveryStep{
				name: "rollback FI release-trust state",
				run:  rollback,
			},
		)
	}

	if report.ReleaseTrust.Installed.Present &&
		report.ReleaseTrust.Package.Present &&
		strings.EqualFold(
			report.ReleaseTrust.Installed.PolicySHA256,
			report.ReleaseTrust.Package.PolicySHA256,
		) {
		return rollback, func() error {
			return nil
		}, nil
	}

	policyDestination := filepath.Join(
		installedReleaseTrustRoot,
		releaseTrustPolicyFileName,
	)

	signatureDestination := filepath.Join(
		installedReleaseTrustRoot,
		releaseTrustPolicySignatureName,
	)

	replacedFiles, err := replaceFileSet(
		[]fileReplacement{
			{
				Destination:    policyDestination,
				ExpectedSHA256: report.ReleaseTrust.Package.PolicySHA256,
				Source:         report.ReleaseTrust.Package.Path,
			},
			{
				Destination: signatureDestination,
				Source:      report.ReleaseTrust.Package.SignaturePath,
			},
		},
		transactionID+"-trust",
	)
	if err != nil {
		return nil, nil, joinFIRecoveryFailures(
			err,
			fiRecoveryStep{
				name: "rollback FI release-trust state",
				run:  rollback,
			},
		)
	}

	replaced = replacedFiles

	installed := discoverReleaseTrustDocument(
		policyDestination,
		signatureDestination,
		report.ReleaseTrust.BootstrapAuthoritySPKISHA256,
	)

	if !installed.Valid ||
		!strings.EqualFold(
			installed.PolicySHA256,
			report.ReleaseTrust.Package.PolicySHA256,
		) {
		base := fmt.Errorf(
			"installed FI release-trust policy did not re-verify exactly after copy",
		)

		return nil, nil, joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "rollback FI release-trust state",
				run:  rollback,
			},
		)
	}

	commit := func() error {
		return commitReplacedFiles(
			replaced,
		)
	}

	return rollback, commit, nil
}
func replaceRuntimeBinaries(
	report Report,
	transactionID string,
) (func() error, func() error, error) {
	if !report.Package.ManifestValid ||
		!report.Package.PayloadHashesMatch ||
		!report.Package.AuthenticodeFilesTrusted ||
		!report.Package.AuthenticodeSignerIdentitiesComplete ||
		!report.Package.AuthenticodeSignersAuthorized ||
		!report.ReleaseTrust.ManifestSignerAuthorized {
		return nil, nil, fmt.Errorf(
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

	snapshots, err :=
		stopFIServicesForBinaryReplacement()
	if err != nil {
		return nil, nil, err
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
		)
	}

	recoverPackage := func() error {
		return runFIRecoverySteps(
			fiRecoveryStep{
				name: "stop FI services before package rollback",
				run:  stopFIServicesBestEffort,
			},
			fiRecoveryStep{
				name: "rollback FI runtime binaries",
				run: func() error {
					return rollbackReplacedFiles(
						replaced,
					)
				},
			},
			fiRecoveryStep{
				name: "restore FI service runtime snapshot",
				run: func() error {
					return startFIServicesFromSnapshot(
						snapshots,
					)
				},
			},
		)
	}

	if err := startFIServicesFromSnapshot(
		snapshots,
	); err != nil {
		base := fmt.Errorf(
			"start FI services after binary replacement: %w",
			err,
		)

		return nil, nil, joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "rollback failed FI package activation",
				run:  recoverPackage,
			},
		)
	}

	if err := waitForFIBrokerPipes(
		10 * time.Second,
	); err != nil {
		return nil, nil, joinFIRecoveryFailures(
			err,
			fiRecoveryStep{
				name: "rollback FI package after broker-readiness failure",
				run:  recoverPackage,
			},
		)
	}

	rollback := func() error {
		return recoverPackage()
	}

	commit := func() error {
		return commitReplacedFiles(
			replaced,
		)
	}

	return rollback, commit, nil
}
func replaceFileSet(
	files []fileReplacement,
	transactionID string,
) ([]replacedFile, error) {
	replaced := make(
		[]replacedFile,
		0,
		len(files),
	)

	for _, file := range files {
		if strings.TrimSpace(
			file.Source,
		) == "" ||
			strings.TrimSpace(
				file.Destination,
			) == "" {
			return nil, failFileReplacementTransaction(
				errors.New(
					"source and destination are required for file replacement",
				),
				replaced,
				"",
			)
		}

		sourceInfo, err := os.Lstat(
			file.Source,
		)
		if err != nil {
			return nil, failFileReplacementTransaction(
				fmt.Errorf(
					"stat replacement source %s: %w",
					file.Source,
					err,
				),
				replaced,
				"",
			)
		}

		if sourceInfo.Mode()&
			os.ModeSymlink != 0 ||
			!sourceInfo.Mode().IsRegular() {
			return nil, failFileReplacementTransaction(
				fmt.Errorf(
					"replacement source must be a regular non-symlink file: %s",
					file.Source,
				),
				replaced,
				"",
			)
		}

		destinationDirectory := filepath.Dir(
			file.Destination,
		)

		if err := os.MkdirAll(
			destinationDirectory,
			0o755,
		); err != nil {
			return nil, failFileReplacementTransaction(
				fmt.Errorf(
					"create destination directory %s: %w",
					destinationDirectory,
					err,
				),
				replaced,
				"",
			)
		}

		stage := file.Destination +
			".fi-new-" +
			transactionID

		backup := file.Destination +
			".fi-old-" +
			transactionID

		if err := removeFileWithRetry(
			stage,
			5*time.Second,
		); err != nil &&
			!errors.Is(
				err,
				os.ErrNotExist,
			) {
			return nil, failFileReplacementTransaction(
				fmt.Errorf(
					"remove stale staged replacement %s: %w",
					stage,
					err,
				),
				replaced,
				"",
			)
		}

		if err := copyFileExclusive(
			file.Source,
			stage,
		); err != nil {
			return nil, failFileReplacementTransaction(
				err,
				replaced,
				stage,
			)
		}

		if file.ExpectedSHA256 != "" {
			hash, err := fileSHA256(
				stage,
			)
			if err != nil {
				return nil, failFileReplacementTransaction(
					err,
					replaced,
					stage,
				)
			}

			if !strings.EqualFold(
				hash,
				file.ExpectedSHA256,
			) {
				return nil, failFileReplacementTransaction(
					fmt.Errorf(
						"staged file hash mismatch destination=%s expected=%s actual=%s",
						file.Destination,
						file.ExpectedSHA256,
						hash,
					),
					replaced,
					stage,
				)
			}
		}

		hadOriginal := false

		if _, err := os.Lstat(
			file.Destination,
		); err == nil {
			hadOriginal = true

			if err := removeFileWithRetry(
				backup,
				5*time.Second,
			); err != nil &&
				!errors.Is(
					err,
					os.ErrNotExist,
				) {
				return nil, failFileReplacementTransaction(
					fmt.Errorf(
						"remove stale replacement backup %s: %w",
						backup,
						err,
					),
					replaced,
					stage,
				)
			}

			if err := renameFileWithRetry(
				file.Destination,
				backup,
				5*time.Second,
			); err != nil {
				return nil, failFileReplacementTransaction(
					fmt.Errorf(
						"backup installed file %s: %w",
						file.Destination,
						err,
					),
					replaced,
					stage,
				)
			}
		} else if !errors.Is(
			err,
			os.ErrNotExist,
		) {
			return nil, failFileReplacementTransaction(
				fmt.Errorf(
					"stat installed file %s: %w",
					file.Destination,
					err,
				),
				replaced,
				stage,
			)
		}

		// Rollback ownership begins before activation. If the native rename
		// succeeds and a later verification fails, the exact previous
		// destination remains represented by this transaction entry.
		replaced = append(
			replaced,
			replacedFile{
				Backup:      backup,
				Destination: file.Destination,
				HadOriginal: hadOriginal,
			},
		)

		if err := renameFileWithRetry(
			stage,
			file.Destination,
			5*time.Second,
		); err != nil {
			return nil, failFileReplacementTransaction(
				fmt.Errorf(
					"activate replacement file %s: %w",
					file.Destination,
					err,
				),
				replaced,
				stage,
			)
		}

		if file.ExpectedSHA256 != "" {
			hash, err := fileSHA256(
				file.Destination,
			)
			if err != nil {
				return nil, failFileReplacementTransaction(
					err,
					replaced,
					"",
				)
			}

			if !strings.EqualFold(
				hash,
				file.ExpectedSHA256,
			) {
				return nil, failFileReplacementTransaction(
					fmt.Errorf(
						"activated file hash mismatch destination=%s expected=%s actual=%s",
						file.Destination,
						file.ExpectedSHA256,
						hash,
					),
					replaced,
					"",
				)
			}
		}
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

func copyFileExclusive(
	source string,
	destination string,
) error {
	input, err := os.Open(
		source,
	)
	if err != nil {
		return fmt.Errorf(
			"open %s: %w",
			source,
			err,
		)
	}
	defer input.Close()

	output, err := os.OpenFile(
		destination,
		os.O_CREATE|
			os.O_EXCL|
			os.O_WRONLY,
		0o755,
	)
	if err != nil {
		return fmt.Errorf(
			"create staged file %s: %w",
			destination,
			err,
		)
	}

	removeDestination := func() error {
		err := removeFileWithRetry(
			destination,
			5*time.Second,
		)
		if err == nil ||
			errors.Is(
				err,
				os.ErrNotExist,
			) {
			return nil
		}

		return fmt.Errorf(
			"remove failed staged file %s: %w",
			destination,
			err,
		)
	}

	failWithOpenOutput := func(
		base error,
	) error {
		return joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "close failed staged file",
				run:  output.Close,
			},
			fiRecoveryStep{
				name: "remove failed staged file",
				run:  removeDestination,
			},
		)
	}

	if _, err := io.Copy(
		output,
		input,
	); err != nil {
		return failWithOpenOutput(
			fmt.Errorf(
				"copy %s to %s: %w",
				source,
				destination,
				err,
			),
		)
	}

	if err := output.Sync(); err != nil {
		return failWithOpenOutput(
			fmt.Errorf(
				"sync staged file %s: %w",
				destination,
				err,
			),
		)
	}

	if err := output.Close(); err != nil {
		return joinFIRecoveryFailures(
			fmt.Errorf(
				"close staged file %s: %w",
				destination,
				err,
			),
			fiRecoveryStep{
				name: "remove failed staged file",
				run:  removeDestination,
			},
		)
	}

	return nil
}
func stopFIServicesForBinaryReplacement() (
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
				name: "restore FI services after package-stop failure",
				run:  recoverSnapshot,
			},
		)
	}

	for _, name := range order {
		service, err := manager.OpenService(
			name,
		)
		if err != nil {
			return fail(
				fmt.Errorf(
					"open service %s for stop: %w",
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
					"query service %s before stop: %w",
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
						"stop service %s: %w",
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
func startFIServicesFromSnapshot(
	snapshots []serviceRuntimeSnapshot,
) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf(
			"connect to service control manager: %w",
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
		"FIUSNReader",
		"FIObjReader",
		"FICollector",
		"FICRLRefresher",
		"FISender",
	} {
		if !required[name] {
			continue
		}

		service, err := manager.OpenService(
			name,
		)
		if err != nil {
			found = append(
				found,
				fmt.Errorf(
					"open service %s for start: %w",
					name,
					err,
				),
			)
			continue
		}

		status, err := service.Query()
		if err != nil {
			service.Close()

			found = append(
				found,
				fmt.Errorf(
					"query service %s before start: %w",
					name,
					err,
				),
			)
			continue
		}

		if status.State != svc.Running {
			if err := service.Start(); err != nil {
				service.Close()

				found = append(
					found,
					fmt.Errorf(
						"start service %s: %w",
						name,
						err,
					),
				)
				continue
			}

			if err := waitServiceState(
				service,
				svc.Running,
				serviceTransitionTimeout,
			); err != nil {
				service.Close()

				found = append(
					found,
					err,
				)
				continue
			}
		}

		service.Close()
	}

	return errors.Join(
		found...,
	)
}
func stopFIServicesBestEffort() error {
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
			found = append(
				found,
				fmt.Errorf(
					"open service %s for stop: %w",
					name,
					err,
				),
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
				fmt.Errorf(
					"stop service %s: %w",
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
