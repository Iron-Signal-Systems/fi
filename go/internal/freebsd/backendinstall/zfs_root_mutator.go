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
// FI ZFS root mutation
// -----------------------------------------------------------------------------

type systemFIRootMutator struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
	lstat func(string) (bool, error)
}

func (mutator systemFIRootMutator) CreateFIRoot(
	target string,
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

	lstat := mutator.lstat
	if lstat == nil {
		probe := systemHostProbe{}
		lstat = probe.Lstat
	}

	exists, err := lstat("/var/db/fi")
	if err != nil {
		return fmt.Errorf(
			"inspect FI ZFS root mountpoint immediately before creation: %w",
			err,
		)
	}

	if exists {
		return fmt.Errorf(
			"FOREIGN_COLLISION: FI ZFS root mountpoint path already exists immediately before creation: /var/db/fi",
		)
	}

	output, err := execute(
		commandPath,
		"create",
		"-o", "org.ironsignal.fi:managed=1",
		"-o", "org.ironsignal.fi:schema=1",
		"-o", "org.ironsignal.fi:role=fi-root",
		"-o", "mountpoint=/var/db/fi",
		"-o", "canmount=on",
		"-o", "atime=off",
		"-o", "exec=off",
		"-o", "setuid=off",
		"-o", "devices=off",
		target,
	)
	if err != nil {
		message := strings.TrimSpace(
			string(output),
		)

		if message == "" {
			return fmt.Errorf(
				"execute ZFS root creation: %w",
				err,
			)
		}

		return fmt.Errorf(
			"execute ZFS root creation: %w: %s",
			err,
			message,
		)
	}

	return nil
}
