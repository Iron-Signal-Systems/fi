// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
	"testing"
)

type fakeHostProbe struct {
	euid      int
	paths     map[string]fakeHostPathResponse
	responses map[string]fakeHostProbeResponse
}

type fakeHostPathResponse struct {
	err    error
	exists bool
}

type fakeHostProbeResponse struct {
	err    error
	output string
}

func (probe fakeHostProbe) EUID() int {
	return probe.euid
}

func (probe fakeHostProbe) Lstat(path string) (bool, error) {
	response, ok := probe.paths[path]
	if !ok {
		return false, nil
	}

	return response.exists, response.err
}

func (probe fakeHostProbe) Run(
	name string,
	args ...string,
) (string, error) {
	key := strings.Join(
		append(
			[]string{name},
			args...,
		),
		" ",
	)

	response, ok := probe.responses[key]
	if !ok {
		return "", fmt.Errorf(
			"unexpected command: %s",
			key,
		)
	}

	return response.output, response.err
}

func TestDiscoverHostAcceptsBaselineHostPrerequisites(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	report, err := discoverHost(
		config,
		probe,
	)
	if err != nil {
		t.Fatalf(
			"discoverHost() error = %v",
			err,
		)
	}

	if report.CurrentHostname != "temporary-installer-host" {
		t.Fatalf(
			"CurrentHostname = %q",
			report.CurrentHostname,
		)
	}

	if report.TargetHostname != "fi-test.invalid" {
		t.Fatalf(
			"TargetHostname = %q",
			report.TargetHostname,
		)
	}

	if len(report.HostAdminAddresses) != 1 ||
		report.HostAdminAddresses[0] != "192.168.1.50" {
		t.Fatalf(
			"HostAdminAddresses = %#v",
			report.HostAdminAddresses,
		)
	}

	if len(report.ReceiverExternalAddresses) != 0 {
		t.Fatalf(
			"ReceiverExternalAddresses = %#v",
			report.ReceiverExternalAddresses,
		)
	}

	if len(report.BaselineResources) != 6 {
		t.Fatalf(
			"BaselineResources count = %d, want 6",
			len(report.BaselineResources),
		)
	}

	for _, state := range report.BaselineResources {
		if state.Disposition != ResourceNeedsCreate {
			t.Fatalf(
				"%s disposition = %s detail=%q",
				state.Name,
				state.Disposition,
				state.Detail,
			)
		}
	}
}

func TestDiscoverHostRejectsBlockedBaselineResource(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed zroot/fi"] = fakeHostProbeResponse{
		output: "-\t-\n",
	}

	_, err := discoverHost(
		config,
		probe,
	)
	if err == nil {
		t.Fatal(
			"discoverHost() expected blocked-resource error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"baseline resource blocked",
	) {
		t.Fatalf(
			"discoverHost() error = %v",
			err,
		)
	}
}

func TestDiscoverHostRejectsMissingAdminInterface(t *testing.T) {
	config := loadTestConfig(t)

	probe := validFakeHostProbe()
	probe.responses["ifconfig vtnet0"] = fakeHostProbeResponse{
		err: fmt.Errorf("interface does not exist"),
	}

	_, err := discoverHost(
		config,
		probe,
	)
	if err == nil {
		t.Fatal("discoverHost() expected missing-interface error")
	}

	if !strings.Contains(
		err.Error(),
		"configured host admin interface",
	) {
		t.Fatalf("discoverHost() error = %v", err)
	}
}

func TestDiscoverHostRejectsMissingReceiverInterface(t *testing.T) {
	config := loadTestConfig(t)

	probe := validFakeHostProbe()
	probe.responses["ifconfig vtnet1"] = fakeHostProbeResponse{
		err: fmt.Errorf("interface does not exist"),
	}

	_, err := discoverHost(
		config,
		probe,
	)
	if err == nil {
		t.Fatal("discoverHost() expected missing-interface error")
	}

	if !strings.Contains(
		err.Error(),
		"configured receiver external interface",
	) {
		t.Fatalf("discoverHost() error = %v", err)
	}
}

func TestDiscoverHostRejectsMissingZPool(t *testing.T) {
	config := loadTestConfig(t)

	probe := validFakeHostProbe()
	probe.responses["zpool list -H -o name zroot"] = fakeHostProbeResponse{
		err: fmt.Errorf("no such pool"),
	}

	_, err := discoverHost(
		config,
		probe,
	)
	if err == nil {
		t.Fatal("discoverHost() expected missing-zpool error")
	}

	if !strings.Contains(
		err.Error(),
		"configured ZFS pool",
	) {
		t.Fatalf("discoverHost() error = %v", err)
	}
}

func TestDiscoverHostRejectsNonFreeBSD(t *testing.T) {
	config := loadTestConfig(t)

	probe := validFakeHostProbe()
	probe.responses["uname -s"] = fakeHostProbeResponse{
		output: "Linux\n",
	}

	_, err := discoverHost(
		config,
		probe,
	)
	if err == nil {
		t.Fatal("discoverHost() expected operating-system error")
	}

	if !strings.Contains(
		err.Error(),
		"requires FreeBSD",
	) {
		t.Fatalf("discoverHost() error = %v", err)
	}
}

func TestDiscoverHostRejectsNonRoot(t *testing.T) {
	config := loadTestConfig(t)

	probe := validFakeHostProbe()
	probe.euid = 1000

	_, err := discoverHost(
		config,
		probe,
	)
	if err == nil {
		t.Fatal("discoverHost() expected root error")
	}

	if !strings.Contains(
		err.Error(),
		"must run as root",
	) {
		t.Fatalf("discoverHost() error = %v", err)
	}
}

func TestParseInterfaceIPv4Addresses(t *testing.T) {
	addresses := parseInterfaceIPv4Addresses(
		`vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
inet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
inet6 fe80::1%vtnet0 prefixlen 64 scopeid 0x1
inet 192.168.1.51 netmask 0xffffff00 broadcast 192.168.1.255
`,
	)

	if len(addresses) != 2 {
		t.Fatalf(
			"addresses = %#v",
			addresses,
		)
	}

	if addresses[0] != "192.168.1.50" ||
		addresses[1] != "192.168.1.51" {
		t.Fatalf(
			"addresses = %#v",
			addresses,
		)
	}
}

func loadTestConfig(t *testing.T) Config {
	t.Helper()

	config, err := LoadConfig(fixturePath)
	if err != nil {
		t.Fatalf(
			"LoadConfig() error = %v",
			err,
		)
	}

	return config
}

func validFakeHostProbe() fakeHostProbe {
	return fakeHostProbe{
		euid:  0,
		paths: make(map[string]fakeHostPathResponse),
		responses: map[string]fakeHostProbeResponse{
			"uname -s": {
				output: "FreeBSD\n",
			},
			"freebsd-version": {
				output: "15.1-RELEASE\n",
			},
			"hostname": {
				output: "temporary-installer-host\n",
			},
			"zpool list -H -o name zroot": {
				output: "zroot\n",
			},
			"ifconfig vtnet0": {
				output: "vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n\tinet 192.168.1.50 netmask 0xffffff00\n",
			},
			"ifconfig vtnet1": {
				output: "vtnet1: flags=1008842<BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n",
			},
			"zfs list -H -t filesystem -o name": {
				output: "zroot\n",
			},
			"zfs list -H -t snapshot -o name": {
				output: "",
			},
			"ifconfig -l": {
				output: "lo0 vtnet0 vtnet1\n",
			},
			"getent passwd": {
				output: "root:*:0:0:Charlie &:/root:/bin/csh\\nnobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin\\n",
			},
			"getent group": {
				output: "wheel:*:0:root\\nnogroup:*:65533:\\n",
			},
			"jls -n name": {
				output: "",
			},
		},
	}
}
