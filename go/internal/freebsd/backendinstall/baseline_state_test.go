// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Baseline-host classification
// -----------------------------------------------------------------------------

func TestDiscoverBaselineResourcesNeedsCreateOnBaselineHost(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	probe.responses["zfs list -H -t snapshot -o name"] =
		fakeHostProbeResponse{
			output: "",
		}

	probe.responses["ifconfig -l"] =
		fakeHostProbeResponse{
			output: "lo0 vtnet0 vtnet1\n",
		}

	states, err := discoverBaselineResources(
		config,
		probe,
		"15.1-RELEASE",
	)
	if err != nil {
		t.Fatalf(
			"discoverBaselineResources() error = %v",
			err,
		)
	}

	if len(states) != 6 {
		t.Fatalf(
			"state count = %d, want 6",
			len(states),
		)
	}

	for _, state := range states {
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

func TestDiscoverBaselineResourcesMatchesOnlyOwnedFIRoot(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\nzroot/jails/containers\n",
		}

	probe.responses["zfs list -H -t snapshot -o name"] =
		fakeHostProbeResponse{
			output: "zroot/jails/templates/15.1-RELEASE@base-test\n",
		}

	probe.responses["ifconfig -l"] =
		fakeHostProbeResponse{
			output: "lo0 vtnet0 vtnet1 bridge10 bridge20 bridge30\n",
		}

	setExpectedFIRootContractResponses(&probe)

	states, err := discoverBaselineResources(
		config,
		probe,
		"15.1-RELEASE-p3",
	)
	if err != nil {
		t.Fatalf(
			"discoverBaselineResources() error = %v",
			err,
		)
	}

	if len(states) != 6 {
		t.Fatalf(
			"state count = %d, want 6",
			len(states),
		)
	}

	if states[0].Disposition != ResourceMatch {
		t.Fatalf(
			"FI root disposition = %s detail=%q",
			states[0].Disposition,
			states[0].Detail,
		)
	}

	for _, state := range states[1:] {
		if state.Disposition != ResourceBlocked {
			t.Fatalf(
				"%s disposition = %s detail=%q",
				state.Name,
				state.Disposition,
				state.Detail,
			)
		}
	}
}

// -----------------------------------------------------------------------------
// Fail-closed classification
// -----------------------------------------------------------------------------

func TestDiscoverBaselineResourcesBlocksForeignFIRoot(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	probe.responses["zfs list -H -t snapshot -o name"] =
		fakeHostProbeResponse{
			output: "",
		}

	probe.responses["ifconfig -l"] =
		fakeHostProbeResponse{
			output: "lo0 vtnet0 vtnet1\n",
		}

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed zroot/fi"] = fakeHostProbeResponse{
		output: "-\t-\n",
	}

	states, err := discoverBaselineResources(
		config,
		probe,
		"15.1-RELEASE",
	)
	if err != nil {
		t.Fatalf(
			"discoverBaselineResources() error = %v",
			err,
		)
	}

	if states[0].Disposition != ResourceBlocked {
		t.Fatalf(
			"FI root disposition = %s",
			states[0].Disposition,
		)
	}

	if !strings.Contains(
		states[0].Detail,
		"org.ironsignal.fi:managed does not match authoritative local state",
	) {
		t.Fatalf(
			"FI root detail = %q",
			states[0].Detail,
		)
	}
}

func TestDiscoverBaselineResourcesBlocksExistingJailDatasetRoot(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/jails/containers\n",
		}

	probe.responses["zfs list -H -t snapshot -o name"] =
		fakeHostProbeResponse{
			output: "",
		}

	probe.responses["ifconfig -l"] =
		fakeHostProbeResponse{
			output: "lo0 vtnet0 vtnet1\n",
		}

	probe.responses["zfs get -H -o value mountpoint zroot/jails/containers"] = fakeHostProbeResponse{
		output: "/wrong/jail/root\n",
	}

	states, err := discoverBaselineResources(
		config,
		probe,
		"15.1-RELEASE",
	)
	if err != nil {
		t.Fatalf(
			"discoverBaselineResources() error = %v",
			err,
		)
	}

	if states[1].Disposition != ResourceBlocked {
		t.Fatalf(
			"jail root disposition = %s",
			states[1].Disposition,
		)
	}

	if !strings.Contains(
		states[1].Detail,
		"ownership is not established",
	) {
		t.Fatalf(
			"jail root detail = %q",
			states[1].Detail,
		)
	}
}

func TestDiscoverBaselineResourcesBlocksBridgeNameCollision(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	probe.responses["zfs list -H -t snapshot -o name"] =
		fakeHostProbeResponse{
			output: "",
		}

	probe.responses["ifconfig -l"] =
		fakeHostProbeResponse{
			output: "lo0 vtnet0 vtnet1 bridge10\n",
		}

	probe.responses["ifconfig bridge10"] =
		fakeHostProbeResponse{
			output: "bridge10: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n",
		}

	states, err := discoverBaselineResources(
		config,
		probe,
		"15.1-RELEASE",
	)
	if err != nil {
		t.Fatalf(
			"discoverBaselineResources() error = %v",
			err,
		)
	}

	managementBridge := states[3]

	if managementBridge.Disposition != ResourceBlocked {
		t.Fatalf(
			"management bridge disposition = %s",
			managementBridge.Disposition,
		)
	}

	if !strings.Contains(
		managementBridge.Detail,
		"ownership is not established",
	) {
		t.Fatalf(
			"management bridge detail = %q",
			managementBridge.Detail,
		)
	}
}

func TestDiscoverBaselineResourcesBlocksTemplateReleaseMismatch(t *testing.T) {
	fixture := readFixture(t)

	old := `FI_JAIL_TEMPLATE_SNAPSHOT="zroot/jails/templates/15.1-RELEASE@base-test"`
	new := `FI_JAIL_TEMPLATE_SNAPSHOT="zroot/jails/templates/14.3-RELEASE@base-test"`

	if strings.Count(fixture, old) != 1 {
		t.Fatalf(
			"fixture template anchor count != 1",
		)
	}

	fixture = strings.Replace(
		fixture,
		old,
		new,
		1,
	)

	config, err := ParseConfig(
		strings.NewReader(fixture),
	)
	if err != nil {
		t.Fatalf(
			"ParseConfig() error = %v",
			err,
		)
	}

	if err := ValidateConfig(config); err != nil {
		t.Fatalf(
			"ValidateConfig() error = %v",
			err,
		)
	}

	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	probe.responses["zfs list -H -t snapshot -o name"] =
		fakeHostProbeResponse{
			output: "",
		}

	probe.responses["ifconfig -l"] =
		fakeHostProbeResponse{
			output: "lo0 vtnet0 vtnet1\n",
		}

	states, err := discoverBaselineResources(
		config,
		probe,
		"15.1-RELEASE",
	)
	if err != nil {
		t.Fatalf(
			"discoverBaselineResources() error = %v",
			err,
		)
	}

	template := states[2]

	if template.Disposition != ResourceBlocked {
		t.Fatalf(
			"template disposition = %s",
			template.Disposition,
		)
	}

	if !strings.Contains(
		template.Detail,
		"template release mismatch",
	) {
		t.Fatalf(
			"template detail = %q",
			template.Detail,
		)
	}
}

// -----------------------------------------------------------------------------
// Discovery failure
// -----------------------------------------------------------------------------

func TestDiscoverBaselineResourcesRejectsEnumerationFailure(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			err: fmt.Errorf(
				"ZFS unavailable",
			),
		}

	_, err := discoverBaselineResources(
		config,
		probe,
		"15.1-RELEASE",
	)
	if err == nil {
		t.Fatal(
			"discoverBaselineResources() expected enumeration error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"enumerate ZFS filesystems",
	) {
		t.Fatalf(
			"discoverBaselineResources() error = %v",
			err,
		)
	}
}

// -----------------------------------------------------------------------------
// Release normalization
// -----------------------------------------------------------------------------

func TestFreeBSDReleaseBase(t *testing.T) {
	tests := map[string]string{
		"15.1-RELEASE":    "15.1-RELEASE",
		"15.1-RELEASE-p3": "15.1-RELEASE",
	}

	for input, expected := range tests {
		actual := freeBSDReleaseBase(input)

		if actual != expected {
			t.Fatalf(
				"freeBSDReleaseBase(%q) = %q, want %q",
				input,
				actual,
				expected,
			)
		}
	}
}

func setExpectedFIRootContractResponses(probe *fakeHostProbe) {
	probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed zroot/fi"] =
		fakeHostProbeResponse{
			output: "1\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:schema zroot/fi"] =
		fakeHostProbeResponse{
			output: "1\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:role zroot/fi"] =
		fakeHostProbeResponse{
			output: "fi-root\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source mountpoint zroot/fi"] =
		fakeHostProbeResponse{
			output: "/var/db/fi\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source canmount zroot/fi"] =
		fakeHostProbeResponse{
			output: "on\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source atime zroot/fi"] =
		fakeHostProbeResponse{
			output: "off\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source exec zroot/fi"] =
		fakeHostProbeResponse{
			output: "off\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source setuid zroot/fi"] =
		fakeHostProbeResponse{
			output: "off\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source devices zroot/fi"] =
		fakeHostProbeResponse{
			output: "off\tlocal\n",
		}

	probe.responses["zfs get -H -o value mounted zroot/fi"] =
		fakeHostProbeResponse{
			output: "yes\n",
		}
}

func TestClassifyFIRootBlocksRootContractDrift(t *testing.T) {
	tests := []struct {
		name    string
		command string
		output  string
	}{
		{
			name:    "wrong schema",
			command: "zfs get -H -o value,source org.ironsignal.fi:schema zroot/fi",
			output:  "2\tlocal\n",
		},
		{
			name:    "wrong role",
			command: "zfs get -H -o value,source org.ironsignal.fi:role zroot/fi",
			output:  "other-role\tlocal\n",
		},
		{
			name:    "inherited native property",
			command: "zfs get -H -o value,source canmount zroot/fi",
			output:  "on\tinherited from zroot\n",
		},
		{
			name:    "wrong hardening property",
			command: "zfs get -H -o value,source exec zroot/fi",
			output:  "on\tlocal\n",
		},
		{
			name:    "root not mounted",
			command: "zfs get -H -o value mounted zroot/fi",
			output:  "no\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadTestConfig(t)
			probe := validFakeHostProbe()

			setExpectedFIRootContractResponses(&probe)

			probe.responses[test.command] = fakeHostProbeResponse{
				output: test.output,
			}

			state := classifyFIRoot(
				config,
				probe,
				"zroot\nzroot/fi\n",
			)

			if state.Disposition != ResourceBlocked {
				t.Fatalf(
					"FI root disposition = %s detail=%q, want %s",
					state.Disposition,
					state.Detail,
					ResourceBlocked,
				)
			}
		})
	}
}
