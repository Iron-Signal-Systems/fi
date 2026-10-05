// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os/exec"
	"strings"
)

// -----------------------------------------------------------------------------
// FI production ZFS hierarchy mutation
// -----------------------------------------------------------------------------

type systemFIHierarchyMutator struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
	lstat func(string) (bool, error)
}

func (mutator systemFIHierarchyMutator) CreateFIDataset(
	spec fiDatasetSpec,
) error {
	commandPath, err := systemCommandPath("zfs")
	if err != nil {
		return fmt.Errorf(
			"resolve ZFS command: %w",
			err,
		)
	}

	execute := mutator.execute

	if execute == nil {
		execute = func(
			path string,
			args ...string,
		) ([]byte, error) {
			return exec.Command(
				path,
				args...,
			).CombinedOutput()
		}
	}

	if spec.Mountpoint != "none" {
		lstat := mutator.lstat

		if lstat == nil {
			probe := systemHostProbe{}
			lstat = probe.Lstat
		}

		exists, err := lstat(spec.Mountpoint)
		if err != nil {
			return fmt.Errorf(
				"inspect FI ZFS mountpoint immediately before creation %s: %w",
				spec.Mountpoint,
				err,
			)
		}

		if exists {
			return fmt.Errorf(
				"FOREIGN_COLLISION: FI ZFS mountpoint path already exists immediately before creation: %s",
				spec.Mountpoint,
			)
		}
	}

	output, err := execute(
		commandPath,
		"create",
		"-o", "org.ironsignal.fi:managed=1",
		"-o", "org.ironsignal.fi:schema=1",
		"-o", "org.ironsignal.fi:role="+spec.Role,
		"-o", "mountpoint="+spec.Mountpoint,
		"-o", "canmount="+spec.Canmount,
		"-o", "atime=off",
		"-o", "exec=off",
		"-o", "setuid=off",
		"-o", "devices=off",
		spec.Target,
	)
	if err != nil {
		message := strings.TrimSpace(
			string(output),
		)

		if message == "" {
			return fmt.Errorf(
				"execute ZFS dataset creation for %s: %w",
				spec.Target,
				err,
			)
		}

		return fmt.Errorf(
			"execute ZFS dataset creation for %s: %w: %s",
			spec.Target,
			err,
			message,
		)
	}

	return nil
}
