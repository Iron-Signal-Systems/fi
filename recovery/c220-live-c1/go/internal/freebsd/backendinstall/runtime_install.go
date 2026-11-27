// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type runtimeFileState string

const (
	runtimeFileAbsent           runtimeFileState = "ABSENT"
	runtimeFileForeignCollision runtimeFileState = "FOREIGN_COLLISION"
	runtimeFileOwnedDrift       runtimeFileState = "OWNED_DRIFT"
	runtimeFileOwnedMatch       runtimeFileState = "OWNED_MATCH"
	runtimeFileUnknown          runtimeFileState = "UNKNOWN"
)

func ApplyRuntime(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	plan, err := buildRuntimePlan(
		config,
	)
	if err != nil {
		return err
	}

	if err := preclassifyRuntimePlan(
		plan,
	); err != nil {
		return err
	}

	for _, spec := range plan.Parents {
		state := classifyLifecycleParent(
			spec,
		)

		switch state {
		case lifecycleParentDirectoryMatch:
			continue

		case lifecycleParentAbsent:
			if err := createLifecycleParent(
				spec,
			); err != nil {
				return fmt.Errorf(
					"create runtime parent %s: %w",
					spec.Role,
					err,
				)
			}

		default:
			return fmt.Errorf(
				"runtime parent changed after preclassification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyRuntimeFile(
			spec,
		)

		switch state {
		case runtimeFileOwnedMatch:
			continue

		case runtimeFileAbsent:
			if err := publishAbsentRuntimeFile(
				spec,
			); err != nil {
				return fmt.Errorf(
					"publish runtime file %s: %w",
					spec.Role,
					err,
				)
			}

		default:
			return fmt.Errorf(
				"runtime file changed after preclassification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return verifyRuntimePlan(
		plan,
	)
}

func VerifyRuntime(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	plan, err := buildRuntimePlan(
		config,
	)
	if err != nil {
		return err
	}

	return verifyRuntimePlan(
		plan,
	)
}

func classifyRuntimeFile(
	spec runtimeFileSpec,
) runtimeFileState {
	info, err := os.Lstat(
		spec.Target,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return runtimeFileAbsent

	default:
		return runtimeFileUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return runtimeFileForeignCollision
	}

	content, err := os.ReadFile(
		spec.Target,
	)
	if err != nil {
		return runtimeFileUnknown
	}

	if !containsExactLine(
		content,
		runtimeFileMarker,
	) {
		return runtimeFileForeignCollision
	}

	if !bytes.Equal(
		content,
		spec.Content,
	) {
		return runtimeFileOwnedDrift
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return runtimeFileUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) ||
		uint64(stat.Nlink) != 1 {
		return runtimeFileOwnedDrift
	}

	return runtimeFileOwnedMatch
}

func preclassifyRuntimePlan(
	plan runtimePlan,
) error {
	for _, spec := range plan.Parents {
		state := classifyLifecycleParent(
			spec,
		)

		switch state {
		case lifecycleParentAbsent,
			lifecycleParentDirectoryMatch:

		case lifecycleParentForeignCollision:
			return fmt.Errorf(
				"unsafe runtime parent: %s (FOREIGN_COLLISION)",
				spec.Role,
			)

		case lifecycleParentUnknown:
			return fmt.Errorf(
				"unable to classify runtime parent: %s (UNKNOWN)",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid runtime parent state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyRuntimeFile(
			spec,
		)

		switch state {
		case runtimeFileAbsent,
			runtimeFileOwnedMatch:

		case runtimeFileOwnedDrift:
			return fmt.Errorf(
				"FI-owned runtime file has drifted: %s",
				spec.Role,
			)

		case runtimeFileForeignCollision:
			return fmt.Errorf(
				"existing unowned runtime file requires explicit approved adoption: %s",
				spec.Role,
			)

		case runtimeFileUnknown:
			return fmt.Errorf(
				"unable to classify runtime file safely: %s",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid runtime-file state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}

func publishAbsentRuntimeFile(
	spec runtimeFileSpec,
) error {
	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileAbsent {
		return fmt.Errorf(
			"runtime file changed before creation: %s",
			state,
		)
	}

	if err := requireHostFileParent(
		spec.Target,
	); err != nil {
		return err
	}

	parent := filepath.Dir(
		spec.Target,
	)

	name := filepath.Base(
		spec.Target,
	)

	file, err := os.CreateTemp(
		parent,
		"."+name+".fi-runtime.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary runtime file: %w",
			err,
		)
	}

	temp := file.Name()
	closed := false
	published := false

	defer func() {
		if !closed {
			_ = file.Close()
		}

		if !published {
			_ = os.Remove(
				temp,
			)
		}
	}()

	if _, err := file.Write(
		spec.Content,
	); err != nil {
		return fmt.Errorf(
			"populate temporary runtime file: %w",
			err,
		)
	}

	if err := file.Chown(
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set temporary runtime ownership: %w",
			err,
		)
	}

	if err := file.Chmod(
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set temporary runtime mode: %w",
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync temporary runtime file: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close temporary runtime file: %w",
			err,
		)
	}

	closed = true

	tempSpec := spec
	tempSpec.Target = temp

	if state := classifyRuntimeFile(
		tempSpec,
	); state != runtimeFileOwnedMatch {
		return fmt.Errorf(
			"temporary runtime file failed verification: %s",
			state,
		)
	}

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileAbsent {
		return fmt.Errorf(
			"runtime file changed before publication: %s",
			state,
		)
	}

	if err := os.Link(
		temp,
		spec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish runtime file without overwrite: %w",
			err,
		)
	}

	if err := os.Remove(
		temp,
	); err != nil {
		return fmt.Errorf(
			"remove temporary runtime link: %w",
			err,
		)
	}

	published = true

	if err := syncHostFileDirectory(
		parent,
	); err != nil {
		return fmt.Errorf(
			"sync runtime parent directory: %w",
			err,
		)
	}

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileOwnedMatch {
		return fmt.Errorf(
			"runtime publication failed verification: %s",
			state,
		)
	}

	return nil
}

func verifyRuntimePlan(
	plan runtimePlan,
) error {
	for _, spec := range plan.Parents {
		state := classifyLifecycleParent(
			spec,
		)

		if state != lifecycleParentDirectoryMatch {
			return fmt.Errorf(
				"runtime parent is not DIRECTORY_MATCH: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyRuntimeFile(
			spec,
		)

		if state != runtimeFileOwnedMatch {
			return fmt.Errorf(
				"runtime file is not OWNED_MATCH: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}
