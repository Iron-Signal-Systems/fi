// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

// -----------------------------------------------------------------------------
// FI production ZFS hierarchy precheck
// -----------------------------------------------------------------------------

func precheckFIHierarchy(
	config Config,
	probe hostProbe,
) error {
	for _, spec := range fiHierarchySpecs(config) {
		state := inspectFIDatasetState(
			probe,
			spec,
		)

		switch state {
		case fiDatasetAbsent:
			if spec.Mountpoint == "none" {
				continue
			}

			exists, err := probe.Lstat(spec.Mountpoint)
			if err != nil {
				return fmt.Errorf(
					"UNKNOWN: unable to inspect FI ZFS mountpoint path %s: %w",
					spec.Mountpoint,
					err,
				)
			}

			if exists {
				return fmt.Errorf(
					"FOREIGN_COLLISION: FI ZFS mountpoint path already exists: %s",
					spec.Mountpoint,
				)
			}

		case fiDatasetOwnedMatch:
			continue

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
