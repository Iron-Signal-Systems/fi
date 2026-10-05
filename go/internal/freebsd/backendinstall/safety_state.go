// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------------
// Safety-surface classification
// -----------------------------------------------------------------------------

func classifyInterfaceName(
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
		state.Detail = "planned installer-owned interface name already exists"
		return state
	}

	state.Disposition = ResourceNeedsCreate
	state.Detail = "interface name is available"

	return state
}

func classifyJailName(
	jails string,
	name string,
) ResourceState {
	state := ResourceState{
		Name:   "production jail",
		Target: name,
	}

	if listContainsJailName(jails, name) {
		state.Disposition = ResourceBlocked
		state.Detail = "production jail name is already active"
		return state
	}

	state.Disposition = ResourceNeedsCreate
	state.Detail = "production jail name is available"

	return state
}

func classifyPath(
	probe hostProbe,
	path string,
	role string,
) ResourceState {
	state := ResourceState{
		Name:   role,
		Target: path,
	}

	exists, err := probe.Lstat(path)
	if err != nil {
		state.Disposition = ResourceBlocked
		state.Detail = fmt.Sprintf(
			"path state cannot be established: %v",
			err,
		)
		return state
	}

	if exists {
		state.Disposition = ResourceBlocked
		state.Detail = "installer-owned path already exists"
		return state
	}

	state.Disposition = ResourceNeedsCreate
	state.Detail = "path is available"

	return state
}

func classifyRuntimeGID(
	groups string,
	gid string,
) ResourceState {
	state := ResourceState{
		Name:   "FI runtime GID",
		Target: gid,
	}

	if databaseContainsNumericField(
		groups,
		2,
		gid,
	) {
		state.Disposition = ResourceBlocked
		state.Detail = "configured runtime GID is already allocated"
		return state
	}

	state.Disposition = ResourceNeedsCreate
	state.Detail = "configured runtime GID is available"

	return state
}

func classifyRuntimeUID(
	passwd string,
	uid string,
) ResourceState {
	state := ResourceState{
		Name:   "FI runtime UID",
		Target: uid,
	}

	if databaseContainsNumericField(
		passwd,
		2,
		uid,
	) {
		state.Disposition = ResourceBlocked
		state.Detail = "configured runtime UID is already allocated"
		return state
	}

	state.Disposition = ResourceNeedsCreate
	state.Detail = "configured runtime UID is available"

	return state
}

// -----------------------------------------------------------------------------
// Safety discovery
// -----------------------------------------------------------------------------

func discoverSafetyResources(
	config Config,
	probe hostProbe,
) ([]ResourceState, error) {
	passwd, err := probe.Run(
		"getent",
		"passwd",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"enumerate passwd database: %w",
			err,
		)
	}

	groups, err := probe.Run(
		"getent",
		"group",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"enumerate group database: %w",
			err,
		)
	}

	jails, err := probe.Run(
		"jls",
		"-n",
		"name",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"enumerate active jail names: %w",
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

	states := make(
		[]ResourceState,
		0,
		32,
	)

	states = append(
		states,
		classifyRuntimeUID(
			passwd,
			config.Value("FI_RUNTIME_UID"),
		),
		classifyRuntimeGID(
			groups,
			config.Value("FI_RUNTIME_GID"),
		),
	)

	for _, jail := range []string{
		"fi-receiver",
		"fi-ingest",
		"fi-sor-db",
	} {
		states = append(
			states,
			classifyJailName(
				jails,
				jail,
			),
		)
	}

	interfaceKeys := []string{
		"FI_RECEIVER_EXTERNAL_HOST_IF",
		"FI_RECEIVER_EXTERNAL_JAIL_IF",
		"FI_RECEIVER_MGMT_HOST_IF",
		"FI_RECEIVER_MGMT_JAIL_IF",
		"FI_RECEIVER_WORK_HOST_IF",
		"FI_RECEIVER_WORK_JAIL_IF",
		"FI_INGEST_MGMT_HOST_IF",
		"FI_INGEST_MGMT_JAIL_IF",
		"FI_INGEST_WORK_HOST_IF",
		"FI_INGEST_WORK_JAIL_IF",
		"FI_SOR_DB_MGMT_HOST_IF",
		"FI_SOR_DB_MGMT_JAIL_IF",
		"FI_SOR_DB_WORK_HOST_IF",
		"FI_SOR_DB_WORK_JAIL_IF",
	}

	for _, key := range interfaceKeys {
		states = append(
			states,
			classifyInterfaceName(
				interfaces,
				config.Value(key),
				key,
			),
		)
	}

	pathSpecs := []struct {
		role string
		path string
	}{
		{"receiver jail config", "/etc/jail.conf.d/fi-receiver.conf"},
		{"ingest jail config", "/etc/jail.conf.d/fi-ingest.conf"},
		{"SOR jail config", "/etc/jail.conf.d/fi-sor-db.conf"},
		{"FI devfs policy", "/etc/devfs.rules.fi"},
		{"FI VNET helper", "/usr/local/libexec/fi-vnet-pair"},
		{"FI PF controller", "/usr/local/etc/rc.d/fi_pf"},
		{"FI jail controller", "/usr/local/etc/rc.d/fi_jails"},
		{"FI PF enable policy", "/etc/rc.conf.d/fi_pf"},
		{"FI jail enable policy", "/etc/rc.conf.d/fi_jails"},
		{"FI devfs boot policy", "/etc/rc.conf.d/devfs/90-fi"},
		{"receiver fstab", config.Value("FI_RECEIVER_FSTAB")},
		{"ingest fstab", config.Value("FI_INGEST_FSTAB")},
		{"SOR fstab", config.Value("FI_SOR_DB_FSTAB")},
	}

	for _, spec := range pathSpecs {
		states = append(
			states,
			classifyPath(
				probe,
				spec.path,
				spec.role,
			),
		)
	}

	return states, nil
}

// -----------------------------------------------------------------------------
// Parsing helpers
// -----------------------------------------------------------------------------

func databaseContainsNumericField(
	output string,
	field int,
	expected string,
) bool {
	expectedNumber, err := strconv.ParseUint(
		expected,
		10,
		64,
	)
	if err != nil {
		return false
	}

	for _, line := range strings.Split(
		output,
		"\n",
	) {
		fields := strings.Split(
			line,
			":",
		)

		if len(fields) <= field {
			continue
		}

		actual, err := strconv.ParseUint(
			fields[field],
			10,
			64,
		)
		if err != nil {
			continue
		}

		if actual == expectedNumber {
			return true
		}
	}

	return false
}

func listContainsJailName(
	output string,
	expected string,
) bool {
	for _, field := range strings.Fields(
		output,
	) {
		if strings.TrimSpace(
			field,
		) == "name="+expected {
			return true
		}
	}

	return false
}
