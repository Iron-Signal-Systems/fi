// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
	"testing"
)

type hostUpdateTestChecker struct {
	distsetAvailable bool
	distsetCalls     int
	packageAvailable bool
	packageCalls     int
}

type hostUpdateTestProbeResponse struct {
	err    error
	output string
}

type hostUpdateTestProbe struct {
	euid      int
	existing  map[string]bool
	responses map[string]hostUpdateTestProbeResponse
}

func (checker *hostUpdateTestChecker) CheckDistsetBase() (bool, error) {
	checker.distsetCalls++
	return checker.distsetAvailable, nil
}

func (checker *hostUpdateTestChecker) CheckPackages() (bool, error) {
	checker.packageCalls++
	return checker.packageAvailable, nil
}

func (probe hostUpdateTestProbe) EUID() int {
	return probe.euid
}

func (probe hostUpdateTestProbe) Lstat(
	target string,
) (bool, error) {
	return probe.existing[target], nil
}

func (probe hostUpdateTestProbe) Run(
	name string,
	args ...string,
) (string, error) {
	parts := append(
		[]string{name},
		args...,
	)

	key := strings.Join(
		parts,
		" ",
	)

	response, ok := probe.responses[key]
	if !ok {
		return "", fmt.Errorf(
			"unexpected test command: %s",
			key,
		)
	}

	return response.output, response.err
}

func TestCheckHostUpdateDistsetCurrent(t *testing.T) {
	config := loadTestConfig(t)
	probe := currentHostUpdateTestProbe(
		config,
		false,
		false,
	)
	checker := &hostUpdateTestChecker{}

	report, err := checkHostUpdate(
		config,
		probe,
		checker,
	)
	if err != nil {
		t.Fatalf(
			"checkHostUpdate() error = %v",
			err,
		)
	}

	if !report.Current ||
		report.Status != "CURRENT" {
		t.Fatalf(
			"report = %+v",
			report,
		)
	}

	if checker.distsetCalls != 1 ||
		checker.packageCalls != 0 {
		t.Fatalf(
			"checker calls = distset:%d package:%d",
			checker.distsetCalls,
			checker.packageCalls,
		)
	}
}

func TestCheckHostUpdateDistsetRequiresBaseInstall(t *testing.T) {
	config := loadTestConfig(t)
	probe := currentHostUpdateTestProbe(
		config,
		false,
		false,
	)
	checker := &hostUpdateTestChecker{
		distsetAvailable: true,
	}

	report, err := checkHostUpdate(
		config,
		probe,
		checker,
	)
	if err != nil {
		t.Fatalf(
			"checkHostUpdate() error = %v",
			err,
		)
	}

	if report.Current ||
		report.Status != "BASE_UPDATE_REQUIRED" {
		t.Fatalf(
			"report = %+v",
			report,
		)
	}

	if len(report.OperatorCommands) != 1 ||
		report.OperatorCommands[0] != "freebsd-update install" {
		t.Fatalf(
			"OperatorCommands = %v",
			report.OperatorCommands,
		)
	}
}

func TestCheckHostUpdateDistsetRequiresPackageUpgrade(t *testing.T) {
	config := loadTestConfig(t)
	probe := currentHostUpdateTestProbe(
		config,
		true,
		false,
	)
	checker := &hostUpdateTestChecker{
		packageAvailable: true,
	}

	report, err := checkHostUpdate(
		config,
		probe,
		checker,
	)
	if err != nil {
		t.Fatalf(
			"checkHostUpdate() error = %v",
			err,
		)
	}

	if report.Status != "PACKAGE_UPDATE_REQUIRED" {
		t.Fatalf(
			"Status = %q",
			report.Status,
		)
	}

	if checker.distsetCalls != 1 ||
		checker.packageCalls != 1 {
		t.Fatalf(
			"checker calls = distset:%d package:%d",
			checker.distsetCalls,
			checker.packageCalls,
		)
	}
}

func TestCheckHostUpdatePkgbaseRequiresPackageUpgrade(t *testing.T) {
	config := loadTestConfig(t)
	probe := currentHostUpdateTestProbe(
		config,
		true,
		true,
	)
	checker := &hostUpdateTestChecker{
		packageAvailable: true,
	}

	report, err := checkHostUpdate(
		config,
		probe,
		checker,
	)
	if err != nil {
		t.Fatalf(
			"checkHostUpdate() error = %v",
			err,
		)
	}

	if report.Status != "PACKAGE_UPDATE_REQUIRED" {
		t.Fatalf(
			"Status = %q",
			report.Status,
		)
	}

	if checker.distsetCalls != 0 ||
		checker.packageCalls != 1 {
		t.Fatalf(
			"checker calls = distset:%d package:%d",
			checker.distsetCalls,
			checker.packageCalls,
		)
	}
}

func TestCheckHostUpdateStopsForPendingReboot(t *testing.T) {
	config := loadTestConfig(t)
	probe := currentHostUpdateTestProbe(
		config,
		false,
		false,
	)

	probe.responses["freebsd-version -r"] =
		hostUpdateTestProbeResponse{
			output: "15.1-RELEASE-p3\n",
		}

	checker := &hostUpdateTestChecker{}

	report, err := checkHostUpdate(
		config,
		probe,
		checker,
	)
	if err != nil {
		t.Fatalf(
			"checkHostUpdate() error = %v",
			err,
		)
	}

	if report.Status != "REBOOT_REQUIRED" {
		t.Fatalf(
			"Status = %q",
			report.Status,
		)
	}

	if checker.distsetCalls != 0 ||
		checker.packageCalls != 0 {
		t.Fatal(
			"update checker ran despite pending reboot",
		)
	}
}

func TestClassifyHostPackageInventoryDistset(t *testing.T) {
	model, err := classifyHostPackageInventory(
		"pkg|ports-mgmt/pkg\nca_root_nss|security/ca_root_nss\n",
	)
	if err != nil {
		t.Fatalf(
			"classifyHostPackageInventory() error = %v",
			err,
		)
	}

	if model != hostBaseDistset {
		t.Fatalf(
			"model = %s, want %s",
			model,
			hostBaseDistset,
		)
	}
}

func TestClassifyHostPackageInventoryPkgbase(t *testing.T) {
	model, err := classifyHostPackageInventory(
		"FreeBSD-runtime|base/runtime\nFreeBSD-zoneinfo|base/zoneinfo\npkg|ports-mgmt/pkg\n",
	)
	if err != nil {
		t.Fatalf(
			"classifyHostPackageInventory() error = %v",
			err,
		)
	}

	if model != hostBasePkgbase {
		t.Fatalf(
			"model = %s, want %s",
			model,
			hostBasePkgbase,
		)
	}
}

func TestClassifyHostPackageInventoryRejectsInconsistentBaseIdentity(t *testing.T) {
	_, err := classifyHostPackageInventory(
		"FreeBSD-runtime|ports-mgmt/pkg\n",
	)

	if err == nil {
		t.Fatal(
			"classifyHostPackageInventory() accepted inconsistent base identity",
		)
	}
}

func TestInspectHostUpdateRejectsNon15Release(t *testing.T) {
	config := loadTestConfig(t)

	probe := hostUpdateTestProbe{
		euid:     0,
		existing: map[string]bool{},
		responses: map[string]hostUpdateTestProbeResponse{
			"uname -s": {
				output: "FreeBSD\n",
			},
			"hostname": {
				output: config.Value("FI_HOSTNAME") + "\n",
			},
			"freebsd-version": {
				output: "14.3-RELEASE-p1\n",
			},
		},
	}

	_, err := inspectHostUpdate(
		config,
		probe,
	)

	if err == nil {
		t.Fatal(
			"inspectHostUpdate() accepted non-15.x host",
		)
	}
}

func TestSystemHostUpdateCheckerDistsetCurrent(t *testing.T) {
	calls := make(
		[]string,
		0,
	)

	checker := systemHostUpdateChecker{
		execute: func(
			executable string,
			args ...string,
		) ([]byte, int, error) {
			call := executable + " " +
				strings.Join(
					args,
					" ",
				)

			calls = append(
				calls,
				call,
			)

			if strings.Contains(
				call,
				"updatesready",
			) {
				return nil, 2, nil
			}

			return nil, 0, nil
		},
	}

	available, err := checker.CheckDistsetBase()
	if err != nil {
		t.Fatalf(
			"CheckDistsetBase() error = %v",
			err,
		)
	}

	if available {
		t.Fatal(
			"CheckDistsetBase() reported updates",
		)
	}

	expected := []string{
		"/usr/sbin/freebsd-update --not-running-from-cron fetch",
		"/usr/sbin/freebsd-update updatesready",
	}

	if strings.Join(calls, "\n") !=
		strings.Join(expected, "\n") {
		t.Fatalf(
			"calls = %v, want %v",
			calls,
			expected,
		)
	}
}

func TestSystemHostUpdateCheckerDistsetUpdatesReady(t *testing.T) {
	checker := systemHostUpdateChecker{
		execute: func(
			executable string,
			args ...string,
		) ([]byte, int, error) {
			return nil, 0, nil
		},
	}

	available, err := checker.CheckDistsetBase()
	if err != nil {
		t.Fatalf(
			"CheckDistsetBase() error = %v",
			err,
		)
	}

	if !available {
		t.Fatal(
			"CheckDistsetBase() did not report fetched updates",
		)
	}
}

func TestSystemHostUpdateCheckerPackagesCurrent(t *testing.T) {
	calls := make(
		[]string,
		0,
	)

	checker := systemHostUpdateChecker{
		execute: func(
			executable string,
			args ...string,
		) ([]byte, int, error) {
			call := executable + " " +
				strings.Join(
					args,
					" ",
				)

			calls = append(
				calls,
				call,
			)

			return nil, 0, nil
		},
	}

	available, err := checker.CheckPackages()
	if err != nil {
		t.Fatalf(
			"CheckPackages() error = %v",
			err,
		)
	}

	if available {
		t.Fatal(
			"CheckPackages() reported updates",
		)
	}

	expected := []string{
		"/usr/local/sbin/pkg update -f",
		"/usr/local/sbin/pkg version -R -U -q -l <",
	}

	if strings.Join(calls, "\n") !=
		strings.Join(expected, "\n") {
		t.Fatalf(
			"calls = %v, want %v",
			calls,
			expected,
		)
	}
}

func TestSystemHostUpdateCheckerPackagesUpdatesReady(t *testing.T) {
	checker := systemHostUpdateChecker{
		execute: func(
			executable string,
			args ...string,
		) ([]byte, int, error) {
			if len(args) != 0 &&
				args[0] == "version" {
				return []byte(
					"FreeBSD-runtime\n",
				), 0, nil
			}

			return nil, 0, nil
		},
	}

	available, err := checker.CheckPackages()
	if err != nil {
		t.Fatalf(
			"CheckPackages() error = %v",
			err,
		)
	}

	if !available {
		t.Fatal(
			"CheckPackages() did not report package updates",
		)
	}
}

func currentHostUpdateTestProbe(
	config Config,
	packageManager bool,
	pkgbase bool,
) hostUpdateTestProbe {
	existing := map[string]bool{}

	responses := map[string]hostUpdateTestProbeResponse{
		"uname -s": {
			output: "FreeBSD\n",
		},
		"hostname": {
			output: config.Value("FI_HOSTNAME") + "\n",
		},
		"freebsd-version": {
			output: "15.1-RELEASE-p4\n",
		},
		"freebsd-version -k": {
			output: "15.1-RELEASE-p4\n",
		},
		"freebsd-version -r": {
			output: "15.1-RELEASE-p4\n",
		},
		"freebsd-version -u": {
			output: "15.1-RELEASE-p4\n",
		},
	}

	if packageManager {
		existing["/usr/local/sbin/pkg"] = true

		inventory := "pkg|ports-mgmt/pkg\n"

		if pkgbase {
			inventory =
				"FreeBSD-runtime|base/runtime\npkg|ports-mgmt/pkg\n"
		}

		responses["pkg query -a %n|%o"] =
			hostUpdateTestProbeResponse{
				output: inventory,
			}
	}

	return hostUpdateTestProbe{
		euid:      0,
		existing:  existing,
		responses: responses,
	}
}
