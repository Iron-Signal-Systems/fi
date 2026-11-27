// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
)

// -----------------------------------------------------------------------------
// Resource state
// -----------------------------------------------------------------------------

type ResourceDisposition string

const (
	ResourceBlocked     ResourceDisposition = "BLOCKED"
	ResourceMatch       ResourceDisposition = "MATCH"
	ResourceNeedsCreate ResourceDisposition = "NEEDS_CREATE"
)

type ResourceState struct {
	Detail      string
	Disposition ResourceDisposition
	Name        string
	Target      string
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

func classifyBridge(
	_ hostProbe,
	interfaces string,
	name string,
	role string,
) ResourceState {
	state := ResourceState{
		Name:   role,
		Target: name,
	}

	if listContainsWord(interfaces, name) {
		state.Disposition = ResourceBlocked
		state.Detail = "configured bridge name already exists; ownership is not established"
		return state
	}

	state.Disposition = ResourceNeedsCreate
	state.Detail = "bridge is absent"

	return state
}

func classifyFIRoot(
	config Config,
	probe hostProbe,
	filesystems string,
) ResourceState {
	target := config.Value("FI_ZPOOL") + "/fi"

	state := ResourceState{
		Name:   "FI ZFS root",
		Target: target,
	}

	if !listContainsLine(filesystems, target) {
		state.Disposition = ResourceNeedsCreate
		state.Detail = "FI ZFS root is absent"
		return state
	}

	requiredLocalProperties := []struct {
		name     string
		expected string
	}{
		{"org.ironsignal.fi:managed", "1"},
		{"org.ironsignal.fi:schema", "1"},
		{"org.ironsignal.fi:role", "fi-root"},
		{"mountpoint", "/var/db/fi"},
		{"canmount", "on"},
		{"atime", "off"},
		{"exec", "off"},
		{"setuid", "off"},
		{"devices", "off"},
	}

	for _, property := range requiredLocalProperties {
		result, err := probe.Run(
			"zfs",
			"get",
			"-H",
			"-o",
			"value,source",
			property.name,
			target,
		)
		if err != nil {
			state.Disposition = ResourceBlocked
			state.Detail = fmt.Sprintf(
				"existing FI ZFS root property %s cannot be inspected: %v",
				property.name,
				err,
			)
			return state
		}

		fields := strings.Fields(result)

		if len(fields) != 2 ||
			fields[0] != property.expected ||
			fields[1] != "local" {
			state.Disposition = ResourceBlocked
			state.Detail = fmt.Sprintf(
				"existing FI ZFS root property %s does not match authoritative local state",
				property.name,
			)
			return state
		}
	}

	mounted, err := probe.Run(
		"zfs",
		"get",
		"-H",
		"-o",
		"value",
		"mounted",
		target,
	)
	if err != nil {
		state.Disposition = ResourceBlocked
		state.Detail = fmt.Sprintf(
			"existing FI ZFS root mounted state cannot be inspected: %v",
			err,
		)
		return state
	}

	if strings.TrimSpace(mounted) != "yes" {
		state.Disposition = ResourceBlocked
		state.Detail = "existing FI ZFS root is not mounted"
		return state
	}

	state.Disposition = ResourceMatch
	state.Detail = "existing FI-owned root matches installer contract"

	return state
}

func classifyJailDatasetRoot(
	config Config,
	_ hostProbe,
	filesystems string,
) ResourceState {
	target := config.Value("FI_JAIL_DATASET_ROOT")

	state := ResourceState{
		Name:   "jail dataset root",
		Target: target,
	}

	if listContainsLine(filesystems, target) {
		state.Disposition = ResourceBlocked
		state.Detail = "configured jail dataset root already exists; ownership is not established"
		return state
	}

	state.Disposition = ResourceNeedsCreate
	state.Detail = "jail dataset root is absent"

	return state
}

func classifyTemplateSnapshot(
	config Config,
	snapshots string,
	hostRelease string,
) ResourceState {
	target := config.Value("FI_JAIL_TEMPLATE_SNAPSHOT")

	state := ResourceState{
		Name:   "jail template snapshot",
		Target: target,
	}

	expectedRelease := freeBSDReleaseBase(hostRelease)
	configuredRelease := templateRelease(target)

	if configuredRelease != expectedRelease {
		state.Disposition = ResourceBlocked
		state.Detail = fmt.Sprintf(
			"template release mismatch: host %s, configured template %s",
			expectedRelease,
			configuredRelease,
		)
		return state
	}

	if listContainsLine(snapshots, target) {
		state.Disposition = ResourceBlocked
		state.Detail = "configured jail template snapshot already exists; ownership is not established"
		return state
	}

	state.Disposition = ResourceNeedsCreate
	state.Detail = "jail template snapshot is absent"

	return state
}

// -----------------------------------------------------------------------------
// Discovery
// -----------------------------------------------------------------------------

func discoverBaselineResources(
	config Config,
	probe hostProbe,
	hostRelease string,
) ([]ResourceState, error) {
	filesystems, err := probe.Run(
		"zfs",
		"list",
		"-H",
		"-t",
		"filesystem",
		"-o",
		"name",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"enumerate ZFS filesystems: %w",
			err,
		)
	}

	snapshots, err := probe.Run(
		"zfs",
		"list",
		"-H",
		"-t",
		"snapshot",
		"-o",
		"name",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"enumerate ZFS snapshots: %w",
			err,
		)
	}

	interfaces, err := probe.Run(
		"ifconfig",
		"-l",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"enumerate host interfaces: %w",
			err,
		)
	}

	return []ResourceState{
		classifyFIRoot(
			config,
			probe,
			filesystems,
		),
		classifyJailDatasetRoot(
			config,
			probe,
			filesystems,
		),
		classifyTemplateSnapshot(
			config,
			snapshots,
			hostRelease,
		),
		classifyBridge(
			probe,
			interfaces,
			config.Value("FI_MGMT_BRIDGE"),
			"management bridge",
		),
		classifyBridge(
			probe,
			interfaces,
			config.Value("FI_WORK_BRIDGE"),
			"workload bridge",
		),
		classifyBridge(
			probe,
			interfaces,
			config.Value("FI_RECEIVER_EXTERNAL_BRIDGE"),
			"receiver external bridge",
		),
	}, nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func freeBSDReleaseBase(release string) string {
	release = strings.TrimSpace(release)

	if index := strings.LastIndex(release, "-p"); index > 0 {
		return release[:index]
	}

	return release
}

func listContainsLine(
	output string,
	value string,
) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == value {
			return true
		}
	}

	return false
}

func listContainsWord(
	output string,
	value string,
) bool {
	for _, field := range strings.Fields(output) {
		if field == value {
			return true
		}
	}

	return false
}

func templateRelease(snapshot string) string {
	dataset := snapshot

	if index := strings.IndexByte(dataset, '@'); index >= 0 {
		dataset = dataset[:index]
	}

	if index := strings.LastIndexByte(dataset, '/'); index >= 0 {
		return dataset[index+1:]
	}

	return dataset
}
