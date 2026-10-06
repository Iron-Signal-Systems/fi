// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// -----------------------------------------------------------------------------
// Host update contract
// -----------------------------------------------------------------------------

type hostBaseModel string

const (
	hostBaseDistset hostBaseModel = "DISTSET"
	hostBasePkgbase hostBaseModel = "PKGBASE"
)

type HostUpdateCheckReport struct {
	HostUpdateReport
	Current          bool
	OperatorCommands []string
	Status           string
}

type HostUpdateReport struct {
	BaseModel       string
	FreeBSDRelease  string
	InstalledKernel string
	PackageManager  bool
	RebootRequired  bool
	RunningKernel   string
	Userland        string
}

type hostUpdateChecker interface {
	CheckDistsetBase() (bool, error)
	CheckPackages() (bool, error)
}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func CheckHostUpdate(
	config Config,
) (HostUpdateCheckReport, error) {
	return checkHostUpdate(
		config,
		systemHostProbe{},
		systemHostUpdateChecker{},
	)
}

func InspectHostUpdate(
	config Config,
) (HostUpdateReport, error) {
	return inspectHostUpdate(
		config,
		systemHostProbe{},
	)
}

func (report HostUpdateCheckReport) WriteText(
	output io.Writer,
) error {
	if err := report.HostUpdateReport.WriteText(
		output,
	); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(
		output,
		"    update status:       %s\n",
		report.Status,
	); err != nil {
		return err
	}

	if report.Current {
		_, err := fmt.Fprintln(
			output,
			"\nFreeBSD host is current. FI installation may continue.",
		)

		return err
	}

	if _, err := fmt.Fprintln(
		output,
		"\nOperator action required. Run as root:",
	); err != nil {
		return err
	}

	for _, command := range report.OperatorCommands {
		if _, err := fmt.Fprintf(
			output,
			"\n    %s\n",
			command,
		); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(
		output,
		"\nAfter the command completes, rerun the FI installer.",
	)

	return err
}

func (report HostUpdateReport) WriteText(
	output io.Writer,
) error {
	_, err := fmt.Fprintf(
		output,
		`Host update state:

    FreeBSD release:     %s
    base model:          %s
    package manager:     %t
    installed kernel:    %s
    running kernel:      %s
    installed userland:  %s
    reboot required:     %t
`,
		report.FreeBSDRelease,
		report.BaseModel,
		report.PackageManager,
		report.InstalledKernel,
		report.RunningKernel,
		report.Userland,
		report.RebootRequired,
	)

	return err
}

// -----------------------------------------------------------------------------
// Update-check orchestration
// -----------------------------------------------------------------------------

func checkHostUpdate(
	config Config,
	probe hostProbe,
	checker hostUpdateChecker,
) (HostUpdateCheckReport, error) {
	state, err := inspectHostUpdate(
		config,
		probe,
	)
	if err != nil {
		return HostUpdateCheckReport{}, err
	}

	report := HostUpdateCheckReport{
		HostUpdateReport: state,
	}

	if state.RebootRequired {
		report.Status = "REBOOT_REQUIRED"
		report.OperatorCommands = []string{
			"reboot",
		}

		return report, nil
	}

	switch hostBaseModel(state.BaseModel) {
	case hostBaseDistset:
		available, err := checker.CheckDistsetBase()
		if err != nil {
			return HostUpdateCheckReport{}, fmt.Errorf(
				"check traditional FreeBSD base updates: %w",
				err,
			)
		}

		if available {
			report.Status = "BASE_UPDATE_REQUIRED"
			report.OperatorCommands = []string{
				"freebsd-update install",
			}

			return report, nil
		}

		if state.PackageManager {
			available, err := checker.CheckPackages()
			if err != nil {
				return HostUpdateCheckReport{}, fmt.Errorf(
					"check installed package updates: %w",
					err,
				)
			}

			if available {
				report.Status = "PACKAGE_UPDATE_REQUIRED"
				report.OperatorCommands = []string{
					"pkg upgrade",
				}

				return report, nil
			}
		}

	case hostBasePkgbase:
		available, err := checker.CheckPackages()
		if err != nil {
			return HostUpdateCheckReport{}, fmt.Errorf(
				"check pkgbase host updates: %w",
				err,
			)
		}

		if available {
			report.Status = "PACKAGE_UPDATE_REQUIRED"
			report.OperatorCommands = []string{
				"pkg upgrade",
			}

			return report, nil
		}

	default:
		return HostUpdateCheckReport{}, fmt.Errorf(
			"unsupported host base model: %s",
			state.BaseModel,
		)
	}

	report.Current = true
	report.Status = "CURRENT"

	return report, nil
}

// -----------------------------------------------------------------------------
// Host inspection
// -----------------------------------------------------------------------------

func inspectHostUpdate(
	config Config,
	probe hostProbe,
) (HostUpdateReport, error) {
	if probe.EUID() != 0 {
		return HostUpdateReport{}, fmt.Errorf(
			"host update inspection requires root",
		)
	}

	systemName, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return HostUpdateReport{}, fmt.Errorf(
			"inspect operating system before host update: %w",
			err,
		)
	}

	if strings.TrimSpace(systemName) != "FreeBSD" {
		return HostUpdateReport{}, fmt.Errorf(
			"host update requires FreeBSD",
		)
	}

	hostname, err := probe.Run(
		"hostname",
	)
	if err != nil {
		return HostUpdateReport{}, fmt.Errorf(
			"inspect hostname before host update: %w",
			err,
		)
	}

	hostname = strings.TrimSpace(hostname)

	if hostname != config.Value("FI_HOSTNAME") {
		return HostUpdateReport{}, fmt.Errorf(
			"deployment hostname mismatch: expected %s, observed %s",
			config.Value("FI_HOSTNAME"),
			hostname,
		)
	}

	release, err := probe.Run(
		"freebsd-version",
	)
	if err != nil {
		return HostUpdateReport{}, fmt.Errorf(
			"inspect FreeBSD release before host update: %w",
			err,
		)
	}

	release = strings.TrimSpace(release)

	if !supportedFreeBSD15Release(release) {
		return HostUpdateReport{}, fmt.Errorf(
			"FI backend requires FreeBSD 15.x RELEASE: observed %s",
			release,
		)
	}

	model, packageManager, err := detectHostBaseModel(
		probe,
	)
	if err != nil {
		return HostUpdateReport{}, err
	}

	installedKernel, err := probe.Run(
		"freebsd-version",
		"-k",
	)
	if err != nil {
		return HostUpdateReport{}, fmt.Errorf(
			"inspect installed kernel version: %w",
			err,
		)
	}

	runningKernel, err := probe.Run(
		"freebsd-version",
		"-r",
	)
	if err != nil {
		return HostUpdateReport{}, fmt.Errorf(
			"inspect running kernel version: %w",
			err,
		)
	}

	userland, err := probe.Run(
		"freebsd-version",
		"-u",
	)
	if err != nil {
		return HostUpdateReport{}, fmt.Errorf(
			"inspect installed userland version: %w",
			err,
		)
	}

	installedKernel = strings.TrimSpace(installedKernel)
	runningKernel = strings.TrimSpace(runningKernel)
	userland = strings.TrimSpace(userland)

	return HostUpdateReport{
		BaseModel:       string(model),
		FreeBSDRelease:  release,
		InstalledKernel: installedKernel,
		PackageManager:  packageManager,
		RebootRequired:  installedKernel != runningKernel,
		RunningKernel:   runningKernel,
		Userland:        userland,
	}, nil
}

// -----------------------------------------------------------------------------
// Base-model classification
// -----------------------------------------------------------------------------

func classifyHostPackageInventory(
	inventory string,
) (hostBaseModel, error) {
	sawBase := false

	for _, line := range strings.Split(
		inventory,
		"\n",
	) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.SplitN(
			line,
			"|",
			2,
		)
		if len(fields) != 2 {
			return "", fmt.Errorf(
				"invalid local package inventory record: %q",
				line,
			)
		}

		name := strings.TrimSpace(fields[0])
		origin := strings.TrimSpace(fields[1])

		baseName := strings.HasPrefix(
			name,
			"FreeBSD-",
		)
		baseOrigin := strings.HasPrefix(
			origin,
			"base/",
		)

		if baseName != baseOrigin {
			return "", fmt.Errorf(
				"inconsistent base-package identity: name=%q origin=%q",
				name,
				origin,
			)
		}

		if baseName && baseOrigin {
			sawBase = true
		}
	}

	if sawBase {
		return hostBasePkgbase, nil
	}

	return hostBaseDistset, nil
}

func detectHostBaseModel(
	probe hostProbe,
) (hostBaseModel, bool, error) {
	const realPkgPath = "/usr/local/sbin/pkg"

	pkgExists, err := probe.Lstat(
		realPkgPath,
	)
	if err != nil {
		return "", false, fmt.Errorf(
			"inspect local pkg installation: %w",
			err,
		)
	}

	if !pkgExists {
		return hostBaseDistset, false, nil
	}

	inventory, err := probe.Run(
		"pkg",
		"query",
		"-a",
		"%n|%o",
	)
	if err != nil {
		return "", true, fmt.Errorf(
			"query local package database without network access: %w",
			err,
		)
	}

	model, err := classifyHostPackageInventory(
		inventory,
	)
	if err != nil {
		return "", true, err
	}

	return model, true, nil
}

func supportedFreeBSD15Release(
	release string,
) bool {
	release = freeBSDReleaseBase(
		strings.TrimSpace(release),
	)

	return strings.HasPrefix(
		release,
		"15.",
	) &&
		strings.HasSuffix(
			release,
			"-RELEASE",
		)
}

// -----------------------------------------------------------------------------
// System update checking
// -----------------------------------------------------------------------------

type systemHostUpdateChecker struct {
	execute func(
		string,
		...string,
	) ([]byte, int, error)
}

func (checker systemHostUpdateChecker) CheckDistsetBase() (bool, error) {
	output, exitCode, err := checker.run(
		"freebsd-update",
		"--not-running-from-cron",
		"fetch",
	)
	if err != nil {
		return false, err
	}

	if exitCode != 0 {
		return false, commandExitError(
			"freebsd-update fetch",
			exitCode,
			output,
		)
	}

	output, exitCode, err = checker.run(
		"freebsd-update",
		"updatesready",
	)
	if err != nil {
		return false, err
	}

	switch exitCode {
	case 0:
		return true, nil

	case 2:
		return false, nil

	default:
		return false, commandExitError(
			"freebsd-update updatesready",
			exitCode,
			output,
		)
	}
}

func (checker systemHostUpdateChecker) CheckPackages() (bool, error) {
	output, exitCode, err := checker.run(
		"pkg",
		"update",
		"-f",
	)
	if err != nil {
		return false, err
	}

	if exitCode != 0 {
		return false, commandExitError(
			"pkg update -f",
			exitCode,
			output,
		)
	}

	output, exitCode, err = checker.run(
		"pkg",
		"version",
		"-R",
		"-U",
		"-q",
		"-l",
		"<",
	)
	if err != nil {
		return false, err
	}

	if exitCode != 0 {
		return false, commandExitError(
			"pkg version -R -U -q -l <",
			exitCode,
			output,
		)
	}

	return strings.TrimSpace(
		string(output),
	) != "", nil
}

func (checker systemHostUpdateChecker) run(
	name string,
	args ...string,
) ([]byte, int, error) {
	commandPath, err := systemCommandPath(
		name,
	)
	if err != nil {
		return nil, -1, err
	}

	if checker.execute != nil {
		return checker.execute(
			commandPath,
			args...,
		)
	}

	output, err := exec.Command(
		commandPath,
		args...,
	).CombinedOutput()
	if err == nil {
		return output, 0, nil
	}

	var exitError *exec.ExitError
	if errors.As(
		err,
		&exitError,
	) {
		return output, exitError.ExitCode(), nil
	}

	return output, -1, fmt.Errorf(
		"execute %s: %w",
		commandPath,
		err,
	)
}

// -----------------------------------------------------------------------------
// Error formatting
// -----------------------------------------------------------------------------

func commandExitError(
	operation string,
	exitCode int,
	output []byte,
) error {
	message := strings.TrimSpace(
		string(output),
	)

	if message == "" {
		return fmt.Errorf(
			"%s exited with status %d",
			operation,
			exitCode,
		)
	}

	return fmt.Errorf(
		"%s exited with status %d: %s",
		operation,
		exitCode,
		message,
	)
}
