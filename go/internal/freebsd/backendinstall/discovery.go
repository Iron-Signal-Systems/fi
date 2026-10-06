// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// -----------------------------------------------------------------------------
// Host discovery types
// -----------------------------------------------------------------------------

type HostReport struct {
	BaselineResources         []ResourceState
	SafetyResources           []ResourceState
	CurrentHostname           string
	FreeBSDRelease            string
	HostAdminAddresses        []string
	HostAdminInterface        string
	ReceiverExternalAddresses []string
	ReceiverExternalInterface string
	TargetHostname            string
	TargetHostAdminAddress    string
	TargetReceiverAddress     string
	ZPool                     string
}

type hostProbe interface {
	EUID() int
	Lstat(string) (bool, error)
	Run(string, ...string) (string, error)
}

type systemHostProbe struct{}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func DiscoverHost(config Config) (HostReport, error) {
	return discoverHost(
		config,
		systemHostProbe{},
	)
}

func (report HostReport) WriteText(output io.Writer) error {
	_, err := fmt.Fprintf(
		output,
		`Host preflight accepted:

    FreeBSD release:     %s
    current hostname:    %s
    target hostname:     %s
    ZFS pool:            %s

    admin interface:     %s
    current addresses:   %s
    target address:      %s

    receiver interface:  %s
    current addresses:   %s
    target address:      %s

Baseline resource plan:
`,
		report.FreeBSDRelease,
		report.CurrentHostname,
		report.TargetHostname,
		report.ZPool,
		report.HostAdminInterface,
		formatAddresses(report.HostAdminAddresses),
		report.TargetHostAdminAddress,
		report.ReceiverExternalInterface,
		formatAddresses(report.ReceiverExternalAddresses),
		report.TargetReceiverAddress,
	)
	if err != nil {
		return err
	}

	for _, state := range report.BaselineResources {
		if _, err := fmt.Fprintf(
			output,
			"    %-12s %-26s %s\n",
			state.Disposition,
			state.Name,
			state.Target,
		); err != nil {
			return err
		}

		if state.Detail != "" {
			if _, err := fmt.Fprintf(
				output,
				"                 %s\n",
				state.Detail,
			); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(
		output,
		"\nBaseline safety plan:",
	); err != nil {
		return err
	}

	for _, state := range report.SafetyResources {
		if _, err := fmt.Fprintf(
			output,
			"    %-12s %-26s %s\n",
			state.Disposition,
			state.Name,
			state.Target,
		); err != nil {
			return err
		}

		if state.Detail != "" {
			if _, err := fmt.Fprintf(
				output,
				"                 %s\n",
				state.Detail,
			); err != nil {
				return err
			}
		}
	}

	_, err = fmt.Fprintln(
		output,
		"\nREAD-ONLY PREFLIGHT: no host state has been modified.",
	)

	return err
}

// -----------------------------------------------------------------------------
// Host discovery
// -----------------------------------------------------------------------------

func discoverHost(
	config Config,
	probe hostProbe,
) (HostReport, error) {
	if probe.EUID() != 0 {
		return HostReport{}, fmt.Errorf(
			"host preflight must run as root",
		)
	}

	kernel, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return HostReport{}, fmt.Errorf(
			"inspect operating system: %w",
			err,
		)
	}

	kernel = strings.TrimSpace(kernel)

	if kernel != "FreeBSD" {
		return HostReport{}, fmt.Errorf(
			"host preflight requires FreeBSD: observed %s",
			kernel,
		)
	}

	release, err := probe.Run(
		"freebsd-version",
	)
	if err != nil {
		return HostReport{}, fmt.Errorf(
			"inspect FreeBSD release: %w",
			err,
		)
	}

	release = strings.TrimSpace(release)

	currentHostname, err := probe.Run(
		"hostname",
	)
	if err != nil {
		return HostReport{}, fmt.Errorf(
			"inspect hostname: %w",
			err,
		)
	}

	currentHostname = strings.TrimSpace(currentHostname)

	zpool := config.Value("FI_ZPOOL")

	if _, err := probe.Run(
		"zpool",
		"list",
		"-H",
		"-o",
		"name",
		zpool,
	); err != nil {
		return HostReport{}, fmt.Errorf(
			"configured ZFS pool does not exist or is unavailable: %s: %w",
			zpool,
			err,
		)
	}

	adminInterface := config.Value("FI_HOST_ADMIN_IF")

	adminOutput, err := probe.Run(
		"ifconfig",
		adminInterface,
	)
	if err != nil {
		return HostReport{}, fmt.Errorf(
			"configured host admin interface does not exist or is unavailable: %s: %w",
			adminInterface,
			err,
		)
	}

	receiverInterface := config.Value(
		"FI_RECEIVER_EXTERNAL_IF",
	)

	receiverOutput, err := probe.Run(
		"ifconfig",
		receiverInterface,
	)
	if err != nil {
		return HostReport{}, fmt.Errorf(
			"configured receiver external interface does not exist or is unavailable: %s: %w",
			receiverInterface,
			err,
		)
	}

	baselineResources, err := discoverBaselineResources(
		config,
		probe,
		release,
	)
	if err != nil {
		return HostReport{}, err
	}

	for _, state := range baselineResources {
		if state.Disposition != ResourceBlocked {
			continue
		}

		return HostReport{}, fmt.Errorf(
			"baseline resource blocked: %s (%s): %s",
			state.Name,
			state.Target,
			state.Detail,
		)
	}

	safetyResources, err := discoverSafetyResources(
		config,
		probe,
	)
	if err != nil {
		return HostReport{}, err
	}

	for _, state := range safetyResources {
		if state.Disposition != ResourceBlocked {
			continue
		}

		return HostReport{}, fmt.Errorf(
			"baseline safety blocked: %s (%s): %s",
			state.Name,
			state.Target,
			state.Detail,
		)
	}

	return HostReport{
		BaselineResources: baselineResources,
		SafetyResources:   safetyResources,
		CurrentHostname:   currentHostname,
		FreeBSDRelease:    release,
		HostAdminAddresses: parseInterfaceIPv4Addresses(
			adminOutput,
		),
		HostAdminInterface: adminInterface,
		ReceiverExternalAddresses: parseInterfaceIPv4Addresses(
			receiverOutput,
		),
		ReceiverExternalInterface: receiverInterface,
		TargetHostname: config.Value(
			"FI_HOSTNAME",
		),
		TargetHostAdminAddress: config.Value(
			"FI_HOST_ADMIN_ADDRESS",
		),
		TargetReceiverAddress: config.Value(
			"FI_RECEIVER_EXTERNAL_ADDRESS",
		),
		ZPool: zpool,
	}, nil
}

// -----------------------------------------------------------------------------
// Formatting
// -----------------------------------------------------------------------------

func formatAddresses(addresses []string) string {
	if len(addresses) == 0 {
		return "none"
	}

	return strings.Join(
		addresses,
		", ",
	)
}

// -----------------------------------------------------------------------------
// Interface parsing
// -----------------------------------------------------------------------------

func parseInterfaceIPv4Addresses(output string) []string {
	addresses := make([]string, 0)

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)

		if len(fields) < 2 ||
			fields[0] != "inet" {
			continue
		}

		addresses = append(
			addresses,
			fields[1],
		)
	}

	return addresses
}

// -----------------------------------------------------------------------------
// System probe
// -----------------------------------------------------------------------------

func (systemHostProbe) EUID() int {
	return os.Geteuid()
}

func (systemHostProbe) Lstat(path string) (bool, error) {
	_, err := os.Lstat(path)

	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

func systemCommandPath(name string) (string, error) {
	switch name {
	case "freebsd-update":
		return "/usr/sbin/freebsd-update", nil
	case "freebsd-version":
		return "/bin/freebsd-version", nil
	case "getent":
		return "/usr/bin/getent", nil
	case "hostname":
		return "/bin/hostname", nil
	case "ifconfig":
		return "/sbin/ifconfig", nil
	case "jls":
		return "/usr/sbin/jls", nil
	case "pkg":
		return "/usr/local/sbin/pkg", nil
	case "uname":
		return "/usr/bin/uname", nil
	case "zfs":
		return "/sbin/zfs", nil
	case "zpool":
		return "/sbin/zpool", nil
	default:
		return "", fmt.Errorf(
			"unsupported host probe command: %s",
			name,
		)
	}
}

func (systemHostProbe) Run(
	name string,
	args ...string,
) (string, error) {
	commandPath, err := systemCommandPath(name)
	if err != nil {
		return "", err
	}

	command := exec.Command(
		commandPath,
		args...,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(
			string(output),
		)

		if message == "" {
			return "", err
		}

		return "", fmt.Errorf(
			"%w: %s",
			err,
			message,
		)
	}

	return string(output), nil
}
