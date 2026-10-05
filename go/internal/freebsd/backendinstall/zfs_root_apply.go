// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
)

// -----------------------------------------------------------------------------
// FI ZFS root apply
// -----------------------------------------------------------------------------

type fiRootMutator interface {
	CreateFIRoot(string) error
}

func ApplyFIRoot(config Config) error {
	probe := systemHostProbe{}

	if probe.EUID() != 0 {
		return fmt.Errorf(
			"FI ZFS root apply requires root",
		)
	}

	systemName, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect operating system before FI ZFS root apply: %w",
			err,
		)
	}

	if strings.TrimSpace(systemName) != "FreeBSD" {
		return fmt.Errorf(
			"FI ZFS root apply requires FreeBSD",
		)
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
			"configured ZFS pool is unavailable before FI root apply: %w",
			err,
		)
	}

	return applyFIRoot(
		config,
		probe,
		systemFIRootMutator{},
	)
}

func applyFIRoot(
	config Config,
	probe hostProbe,
	mutator fiRootMutator,
) error {
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
			"enumerate ZFS filesystems before FI root apply: %w",
			err,
		)
	}

	state := classifyFIRoot(
		config,
		probe,
		filesystems,
	)

	switch state.Disposition {
	case ResourceMatch:
		return nil

	case ResourceBlocked:
		return fmt.Errorf(
			"FI ZFS root apply blocked: %s",
			state.Detail,
		)

	case ResourceNeedsCreate:
		targetPath := "/var/db/fi"

		exists, err := probe.Lstat(targetPath)
		if err != nil {
			return fmt.Errorf(
				"inspect FI ZFS root mountpoint path: %w",
				err,
			)
		}

		if exists {
			return fmt.Errorf(
				"FOREIGN_COLLISION: FI ZFS root mountpoint path already exists: %s",
				targetPath,
			)
		}

	default:
		return fmt.Errorf(
			"invalid FI ZFS root disposition: %s",
			state.Disposition,
		)
	}

	target := config.Value("FI_ZPOOL") + "/fi"

	if err := mutator.CreateFIRoot(target); err != nil {
		return fmt.Errorf(
			"create FI ZFS root %s: %w",
			target,
			err,
		)
	}

	filesystems, err = probe.Run(
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
			"enumerate ZFS filesystems after FI root creation: %w",
			err,
		)
	}

	state = classifyFIRoot(
		config,
		probe,
		filesystems,
	)

	if state.Disposition != ResourceMatch {
		return fmt.Errorf(
			"new FI ZFS root did not verify as MATCH: disposition=%s detail=%s",
			state.Disposition,
			state.Detail,
		)
	}

	return nil
}
