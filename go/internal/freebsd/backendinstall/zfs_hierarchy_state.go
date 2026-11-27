// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
)

// -----------------------------------------------------------------------------
// FI production ZFS dataset state
// -----------------------------------------------------------------------------

type fiDatasetState string

const (
	fiDatasetAbsent           fiDatasetState = "ABSENT"
	fiDatasetForeignCollision fiDatasetState = "FOREIGN_COLLISION"
	fiDatasetOwnedDrift       fiDatasetState = "OWNED_DRIFT"
	fiDatasetOwnedMatch       fiDatasetState = "OWNED_MATCH"
	fiDatasetUnknown          fiDatasetState = "UNKNOWN"
)

// -----------------------------------------------------------------------------
// Inspection
// -----------------------------------------------------------------------------

func inspectFIDatasetState(
	probe hostProbe,
	spec fiDatasetSpec,
) fiDatasetState {
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
		return fiDatasetUnknown
	}

	if !listContainsLine(filesystems, spec.Target) {
		return fiDatasetAbsent
	}

	matches, err := inspectLocalZFSProperty(
		probe,
		spec.Target,
		"org.ironsignal.fi:managed",
		"1",
	)
	if err != nil {
		return fiDatasetUnknown
	}

	if !matches {
		return fiDatasetForeignCollision
	}

	required := []struct {
		name     string
		expected string
	}{
		{
			name:     "org.ironsignal.fi:schema",
			expected: "1",
		},
		{
			name:     "org.ironsignal.fi:role",
			expected: spec.Role,
		},
		{
			name:     "mountpoint",
			expected: spec.Mountpoint,
		},
		{
			name:     "canmount",
			expected: spec.Canmount,
		},
		{
			name:     "atime",
			expected: "off",
		},
		{
			name:     "exec",
			expected: "off",
		},
		{
			name:     "setuid",
			expected: "off",
		},
		{
			name:     "devices",
			expected: "off",
		},
	}

	for _, property := range required {
		matches, err := inspectLocalZFSProperty(
			probe,
			spec.Target,
			property.name,
			property.expected,
		)
		if err != nil {
			return fiDatasetUnknown
		}

		if !matches {
			return fiDatasetOwnedDrift
		}
	}

	mounted, err := probe.Run(
		"zfs",
		"get",
		"-H",
		"-o",
		"value",
		"mounted",
		spec.Target,
	)
	if err != nil {
		return fiDatasetUnknown
	}

	if strings.TrimSpace(mounted) != spec.Mounted {
		return fiDatasetOwnedDrift
	}

	return fiDatasetOwnedMatch
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func inspectLocalZFSProperty(
	probe hostProbe,
	target string,
	property string,
	expected string,
) (bool, error) {
	result, err := probe.Run(
		"zfs",
		"get",
		"-H",
		"-o",
		"value,source",
		property,
		target,
	)
	if err != nil {
		return false, err
	}

	fields := strings.Fields(result)

	if len(fields) != 2 {
		return false, fmt.Errorf(
			"unexpected ZFS property result for %s on %s",
			property,
			target,
		)
	}

	return fields[0] == expected &&
		fields[1] == "local", nil
}
