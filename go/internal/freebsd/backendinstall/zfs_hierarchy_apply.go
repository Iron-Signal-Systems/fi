// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
)

// -----------------------------------------------------------------------------
// FI production ZFS hierarchy apply
// -----------------------------------------------------------------------------

type fiHierarchyMutator interface {
	CreateFIDataset(fiDatasetSpec) error
}

func ApplyFIHierarchy(config Config) error {
	probe := systemHostProbe{}

	if probe.EUID() != 0 {
		return fmt.Errorf("FI ZFS hierarchy apply requires root")
	}

	systemName, err := probe.Run("uname", "-s")
	if err != nil {
		return fmt.Errorf(
			"inspect operating system before FI ZFS hierarchy apply: %w",
			err,
		)
	}

	if strings.TrimSpace(systemName) != "FreeBSD" {
		return fmt.Errorf("FI ZFS hierarchy apply requires FreeBSD")
	}

	if _, err := probe.Run(
		"zpool",
		"list",
		"-H",
		"-o",
		"name",
		config.Value("FI_ZPOOL"),
	); err != nil {
		return fmt.Errorf(
			"configured ZFS pool is unavailable before FI hierarchy apply: %w",
			err,
		)
	}

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
		return fmt.Errorf(
			"enumerate ZFS filesystems before FI hierarchy apply: %w",
			err,
		)
	}

	rootState := classifyFIRoot(
		config,
		probe,
		filesystems,
	)

	if rootState.Disposition != ResourceMatch {
		return fmt.Errorf(
			"FI ZFS hierarchy apply requires matching FI root: disposition=%s detail=%s",
			rootState.Disposition,
			rootState.Detail,
		)
	}

	return applyFIHierarchy(
		config,
		probe,
		systemFIHierarchyMutator{},
	)
}

func applyFIHierarchy(
	config Config,
	probe hostProbe,
	mutator fiHierarchyMutator,
) error {
	if err := precheckFIHierarchy(
		config,
		probe,
	); err != nil {
		return fmt.Errorf(
			"FI ZFS hierarchy precheck failed: %w",
			err,
		)
	}

	for _, spec := range fiHierarchySpecs(config) {
		state := inspectFIDatasetState(
			probe,
			spec,
		)

		switch state {
		case fiDatasetOwnedMatch:
			continue

		case fiDatasetAbsent:
			if err := mutator.CreateFIDataset(spec); err != nil {
				return fmt.Errorf(
					"create FI ZFS dataset %s: %w",
					spec.Target,
					err,
				)
			}

			postState := inspectFIDatasetState(
				probe,
				spec,
			)

			if postState != fiDatasetOwnedMatch {
				return fmt.Errorf(
					"new FI ZFS dataset did not verify as OWNED_MATCH: %s (%s)",
					spec.Target,
					postState,
				)
			}

		case fiDatasetOwnedDrift:
			return fmt.Errorf(
				"OWNED_DRIFT: FI ZFS dataset differs from requested state: %s",
				spec.Target,
			)

		case fiDatasetForeignCollision:
			return fmt.Errorf(
				"FOREIGN_COLLISION: ZFS dataset is not authoritatively FI-owned: %s",
				spec.Target,
			)

		case fiDatasetUnknown:
			return fmt.Errorf(
				"UNKNOWN: unable to establish safe ZFS dataset state: %s",
				spec.Target,
			)

		default:
			return fmt.Errorf(
				"invalid FI ZFS dataset state for %s: %s",
				spec.Target,
				state,
			)
		}
	}

	return nil
}
