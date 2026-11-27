// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// -----------------------------------------------------------------------------
// Host-file parent prerequisites
// -----------------------------------------------------------------------------

type hostFileParentState string

const (
	hostFileParentAbsent    hostFileParentState = "ABSENT"
	hostFileParentSafeMatch hostFileParentState = "SAFE_MATCH"
	hostFileParentUnknown   hostFileParentState = "UNKNOWN"
	hostFileParentUnsafe    hostFileParentState = "UNSAFE"
)

type hostFileParentSpec struct {
	GID  uint64
	Mode os.FileMode
	Path string
	UID  uint64
}

var hostFileManagedParents = []hostFileParentSpec{
	{
		GID:  0,
		Mode: 0o755,
		Path: "/usr/local/libexec",
		UID:  0,
	},
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

func classifyHostFileParent(
	spec hostFileParentSpec,
) hostFileParentState {
	info, err := os.Lstat(
		spec.Path,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return hostFileParentAbsent

	default:
		return hostFileParentUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return hostFileParentUnsafe
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return hostFileParentUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		info.Mode().Perm() != spec.Mode.Perm() {
		return hostFileParentUnsafe
	}

	return hostFileParentSafeMatch
}

func managedHostFileParent(
	path string,
) (hostFileParentSpec, bool) {
	for _, spec := range hostFileManagedParents {
		if spec.Path == path {
			return spec, true
		}
	}

	return hostFileParentSpec{}, false
}

// -----------------------------------------------------------------------------
// Layer preclassification
// -----------------------------------------------------------------------------

func preclassifyHostFileParents(
	specs []hostFileSpec,
) error {
	seen := make(
		map[string]struct{},
	)

	for _, fileSpec := range specs {
		parent := filepath.Dir(
			fileSpec.Target,
		)

		if _, exists := seen[parent]; exists {
			continue
		}

		seen[parent] = struct{}{}

		managed, isManaged := managedHostFileParent(
			parent,
		)

		if !isManaged {
			if err := requireHostFileDirectory(
				parent,
			); err != nil {
				return err
			}

			continue
		}

		if err := requireHostFileDirectory(
			filepath.Dir(parent),
		); err != nil {
			return err
		}

		state := classifyHostFileParent(
			managed,
		)

		switch state {
		case hostFileParentAbsent,
			hostFileParentSafeMatch:

		case hostFileParentUnsafe:
			return fmt.Errorf(
				"unsafe host-file prerequisite directory: %s",
				parent,
			)

		case hostFileParentUnknown:
			return fmt.Errorf(
				"unable to classify host-file prerequisite directory: %s",
				parent,
			)

		default:
			return fmt.Errorf(
				"invalid host-file prerequisite state: %s (%s)",
				parent,
				state,
			)
		}
	}

	return nil
}

func verifyHostFileParents(
	specs []hostFileSpec,
) error {
	seen := make(
		map[string]struct{},
	)

	for _, fileSpec := range specs {
		parent := filepath.Dir(
			fileSpec.Target,
		)

		if _, exists := seen[parent]; exists {
			continue
		}

		seen[parent] = struct{}{}

		managed, isManaged := managedHostFileParent(
			parent,
		)

		if !isManaged {
			if err := requireHostFileDirectory(
				parent,
			); err != nil {
				return err
			}

			continue
		}

		state := classifyHostFileParent(
			managed,
		)

		if state != hostFileParentSafeMatch {
			return fmt.Errorf(
				"host-file prerequisite is not SAFE_MATCH: %s (%s)",
				parent,
				state,
			)
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Mutation
// -----------------------------------------------------------------------------

func applyHostFileParents(
	mutator systemHostFileMutator,
) error {
	for _, spec := range hostFileManagedParents {
		state := classifyHostFileParent(
			spec,
		)

		switch state {
		case hostFileParentSafeMatch:
			continue

		case hostFileParentAbsent:
			if err := mutator.CreateParent(
				spec,
			); err != nil {
				return fmt.Errorf(
					"create host-file prerequisite %s: %w",
					spec.Path,
					err,
				)
			}

		case hostFileParentUnsafe:
			return fmt.Errorf(
				"unsafe host-file prerequisite directory: %s",
				spec.Path,
			)

		case hostFileParentUnknown:
			return fmt.Errorf(
				"unable to classify host-file prerequisite directory: %s",
				spec.Path,
			)

		default:
			return fmt.Errorf(
				"invalid host-file prerequisite state: %s (%s)",
				spec.Path,
				state,
			)
		}
	}

	return nil
}

func (systemHostFileMutator) CreateParent(
	spec hostFileParentSpec,
) error {
	state := classifyHostFileParent(
		spec,
	)

	if state != hostFileParentAbsent {
		return fmt.Errorf(
			"host-file prerequisite changed before creation: %s",
			state,
		)
	}

	if err := requireHostFileDirectory(
		filepath.Dir(spec.Path),
	); err != nil {
		return err
	}

	if err := os.Mkdir(
		spec.Path,
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"create host-file prerequisite directory: %w",
			err,
		)
	}

	if err := os.Chown(
		spec.Path,
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set host-file prerequisite ownership: %w",
			err,
		)
	}

	if err := os.Chmod(
		spec.Path,
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set host-file prerequisite mode: %w",
			err,
		)
	}

	state = classifyHostFileParent(
		spec,
	)

	if state != hostFileParentSafeMatch {
		return fmt.Errorf(
			"created host-file prerequisite failed verification: %s",
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Existing-directory prerequisites
// -----------------------------------------------------------------------------

func requireHostFileDirectory(
	path string,
) error {
	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return fmt.Errorf(
			"host-file prerequisite directory unavailable: %s: %w",
			path,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"host-file prerequisite directory is a symbolic link: %s",
			path,
		)
	}

	if !info.IsDir() {
		return fmt.Errorf(
			"host-file prerequisite path is not a directory: %s",
			path,
		)
	}

	return nil
}
