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
// Baseline-host safety acceptance
// -----------------------------------------------------------------------------

func TestDiscoverSafetyResourcesNeedsCreateOnBaselineHost(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	states, err := discoverSafetyResources(
		config,
		probe,
	)
	if err != nil {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}

	if len(states) != 32 {
		t.Fatalf(
			"state count = %d, want 32",
			len(states),
		)
	}

	for _, state := range states {
		if state.Disposition != ResourceNeedsCreate {
			t.Fatalf(
				"%s %s disposition = %s detail=%q",
				state.Name,
				state.Target,
				state.Disposition,
				state.Detail,
			)
		}
	}
}

// -----------------------------------------------------------------------------
// Runtime identity collisions
// -----------------------------------------------------------------------------

func TestDiscoverSafetyResourcesBlocksAllocatedRuntimeUID(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	probe.responses["getent passwd"] =
		fakeHostProbeResponse{
			output: "root:*:0:0:Charlie &:/root:/bin/csh\nfi-old:*:4100:4100:FI:/nonexistent:/usr/sbin/nologin\n",
		}

	states, err := discoverSafetyResources(
		config,
		probe,
	)
	if err != nil {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}

	assertBlockedState(
		t,
		states,
		"FI runtime UID",
		"4100",
		"already allocated",
	)
}

func TestDiscoverSafetyResourcesBlocksAllocatedRuntimeGID(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	probe.responses["getent group"] =
		fakeHostProbeResponse{
			output: "wheel:*:0:root\nfi-old:*:4100:\n",
		}

	states, err := discoverSafetyResources(
		config,
		probe,
	)
	if err != nil {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}

	assertBlockedState(
		t,
		states,
		"FI runtime GID",
		"4100",
		"already allocated",
	)
}

// -----------------------------------------------------------------------------
// Jail collision
// -----------------------------------------------------------------------------

func TestDiscoverSafetyResourcesBlocksActiveProductionJail(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	probe.responses["jls -n name"] =
		fakeHostProbeResponse{
			output: "name=fi-receiver\n",
		}

	states, err := discoverSafetyResources(
		config,
		probe,
	)
	if err != nil {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}

	assertBlockedState(
		t,
		states,
		"production jail",
		"fi-receiver",
		"already active",
	)
}

// -----------------------------------------------------------------------------
// Interface collisions
// -----------------------------------------------------------------------------

func TestDiscoverSafetyResourcesBlocksPlannedInterfaceCollision(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	probe.responses["ifconfig -l"] =
		fakeHostProbeResponse{
			output: "lo0 vtnet0 vtnet1 eprm0a\n",
		}

	states, err := discoverSafetyResources(
		config,
		probe,
	)
	if err != nil {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}

	assertBlockedState(
		t,
		states,
		"FI_RECEIVER_MGMT_HOST_IF",
		"eprm0a",
		"already exists",
	)
}

// -----------------------------------------------------------------------------
// Host-path collisions
// -----------------------------------------------------------------------------

func TestDiscoverSafetyResourcesBlocksExistingInstallerPath(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	probe.paths["/etc/jail.conf.d/fi-receiver.conf"] =
		fakeHostPathResponse{
			exists: true,
		}

	states, err := discoverSafetyResources(
		config,
		probe,
	)
	if err != nil {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}

	assertBlockedState(
		t,
		states,
		"receiver jail config",
		"/etc/jail.conf.d/fi-receiver.conf",
		"already exists",
	)
}

func TestDiscoverSafetyResourcesBlocksPathInspectionFailure(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	probe.paths["/etc/devfs.rules.fi"] =
		fakeHostPathResponse{
			err: fmt.Errorf(
				"permission denied",
			),
		}

	states, err := discoverSafetyResources(
		config,
		probe,
	)
	if err != nil {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}

	assertBlockedState(
		t,
		states,
		"FI devfs policy",
		"/etc/devfs.rules.fi",
		"cannot be established",
	)
}

// -----------------------------------------------------------------------------
// Discovery failures
// -----------------------------------------------------------------------------

func TestDiscoverSafetyResourcesRejectsPasswdEnumerationFailure(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	probe.responses["getent passwd"] =
		fakeHostProbeResponse{
			err: fmt.Errorf(
				"passwd database unavailable",
			),
		}

	_, err := discoverSafetyResources(
		config,
		probe,
	)
	if err == nil {
		t.Fatal(
			"discoverSafetyResources() expected passwd enumeration error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"enumerate passwd database",
	) {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}
}

func TestDiscoverSafetyResourcesRejectsJailEnumerationFailure(t *testing.T) {
	config := loadTestConfig(t)
	probe := validSafetyHostProbe()

	probe.responses["jls -n name"] =
		fakeHostProbeResponse{
			err: fmt.Errorf(
				"jail subsystem unavailable",
			),
		}

	_, err := discoverSafetyResources(
		config,
		probe,
	)
	if err == nil {
		t.Fatal(
			"discoverSafetyResources() expected jail enumeration error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"enumerate active jail names",
	) {
		t.Fatalf(
			"discoverSafetyResources() error = %v",
			err,
		)
	}
}

// -----------------------------------------------------------------------------
// Parsing helpers
// -----------------------------------------------------------------------------

func TestDatabaseContainsNumericField(t *testing.T) {
	passwd := "root:*:0:0:root:/root:/bin/csh\nfi:*:4100:4100:FI:/nonexistent:/usr/sbin/nologin\n"

	if !databaseContainsNumericField(
		passwd,
		2,
		"4100",
	) {
		t.Fatal(
			"databaseContainsNumericField() did not find UID 4100",
		)
	}

	if databaseContainsNumericField(
		passwd,
		2,
		"4200",
	) {
		t.Fatal(
			"databaseContainsNumericField() unexpectedly found UID 4200",
		)
	}
}

func TestListContainsJailName(t *testing.T) {
	output := "name=fi-receiver\nname=other-jail\n"

	if !listContainsJailName(
		output,
		"fi-receiver",
	) {
		t.Fatal(
			"listContainsJailName() did not find fi-receiver",
		)
	}

	if listContainsJailName(
		output,
		"fi-ingest",
	) {
		t.Fatal(
			"listContainsJailName() unexpectedly found fi-ingest",
		)
	}
}

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

func assertBlockedState(
	t *testing.T,
	states []ResourceState,
	name string,
	target string,
	detail string,
) {
	t.Helper()

	for _, state := range states {
		if state.Name != name ||
			state.Target != target {
			continue
		}

		if state.Disposition != ResourceBlocked {
			t.Fatalf(
				"%s %s disposition = %s, want %s",
				name,
				target,
				state.Disposition,
				ResourceBlocked,
			)
		}

		if !strings.Contains(
			state.Detail,
			detail,
		) {
			t.Fatalf(
				"%s %s detail = %q, expected %q",
				name,
				target,
				state.Detail,
				detail,
			)
		}

		return
	}

	t.Fatalf(
		"state not found: %s %s",
		name,
		target,
	)
}

func validSafetyHostProbe() fakeHostProbe {
	return fakeHostProbe{
		euid:  0,
		paths: make(map[string]fakeHostPathResponse),
		responses: map[string]fakeHostProbeResponse{
			"getent passwd": {
				output: "root:*:0:0:Charlie &:/root:/bin/csh\nnobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin\n",
			},
			"getent group": {
				output: "wheel:*:0:root\nnogroup:*:65533:\n",
			},
			"jls -n name": {
				output: "",
			},
			"ifconfig -l": {
				output: "lo0 vtnet0 vtnet1\n",
			},
		},
	}
}
