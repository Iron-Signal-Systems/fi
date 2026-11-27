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

type approvedPriorRuntimeFile struct {
	Content []byte
	Path    string
}

func AdoptRuntime(
	config Config,
	approvedPriorDirectory string,
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

	if err := verifyRuntimeTransitionParents(
		plan,
		"adoption",
	); err != nil {
		return err
	}

	if err := adoptRuntimeSpecs(
		plan.Files,
		approvedPriorDirectory,
	); err != nil {
		return err
	}

	return verifyRuntimePlan(
		plan,
	)
}

func UpdateRuntime(
	config Config,
	approvedPriorDirectory string,
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

	if err := verifyRuntimeTransitionParents(
		plan,
		"update",
	); err != nil {
		return err
	}

	if err := updateRuntimeSpecs(
		plan.Files,
		approvedPriorDirectory,
	); err != nil {
		return err
	}

	return verifyRuntimePlan(
		plan,
	)
}

func adoptRuntimeSpecs(
	specs []runtimeFileSpec,
	approvedPriorDirectory string,
) error {
	if err := requireApprovedPriorRuntimeDirectory(
		approvedPriorDirectory,
	); err != nil {
		return err
	}

	priors := make(
		map[string]approvedPriorRuntimeFile,
	)

	// Complete-layer preclassification before first mutation.
	for _, spec := range specs {
		state := classifyRuntimeFile(
			spec,
		)

		switch state {
		case runtimeFileOwnedMatch:

		case runtimeFileForeignCollision:
			prior, err := loadApprovedPriorRuntimeFile(
				approvedPriorDirectory,
				spec,
			)
			if err != nil {
				return err
			}

			if !runtimeForeignTargetMatchesPrior(
				spec,
				prior.Content,
			) {
				return fmt.Errorf(
					"live runtime file does not match approved prior: %s",
					spec.Role,
				)
			}

			priors[spec.Role] = prior

		case runtimeFileAbsent:
			return fmt.Errorf(
				"runtime adoption target is absent; use apply-runtime: %s",
				spec.Role,
			)

		case runtimeFileOwnedDrift:
			return fmt.Errorf(
				"FI-owned runtime drift is not eligible for adoption: %s",
				spec.Role,
			)

		case runtimeFileUnknown:
			return fmt.Errorf(
				"runtime resource could not be classified safely for adoption: %s",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"unexpected runtime adoption state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	// Publication pass.
	for _, spec := range specs {
		state := classifyRuntimeFile(
			spec,
		)

		switch state {
		case runtimeFileOwnedMatch:
			continue

		case runtimeFileForeignCollision:
			prior, exists := priors[spec.Role]
			if !exists {
				return fmt.Errorf(
					"approved prior runtime file is absent after adoption preclassification: %s",
					spec.Role,
				)
			}

			if err := replaceApprovedPriorRuntimeFile(
				spec,
				prior,
				false,
			); err != nil {
				return err
			}

		default:
			return fmt.Errorf(
				"runtime resource changed after adoption preclassification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return verifyRuntimeFiles(
		specs,
		"adopted",
	)
}

func updateRuntimeSpecs(
	specs []runtimeFileSpec,
	approvedPriorDirectory string,
) error {
	if err := requireApprovedPriorRuntimeDirectory(
		approvedPriorDirectory,
	); err != nil {
		return err
	}

	priors := make(
		map[string]approvedPriorRuntimeFile,
	)

	// Complete-layer preclassification before first mutation.
	for _, spec := range specs {
		state := classifyRuntimeFile(
			spec,
		)

		switch state {
		case runtimeFileOwnedMatch:

		case runtimeFileOwnedDrift:
			prior, err := loadApprovedPriorRuntimeFile(
				approvedPriorDirectory,
				spec,
			)
			if err != nil {
				return err
			}

			if !containsExactLine(
				prior.Content,
				runtimeFileMarker,
			) {
				return fmt.Errorf(
					"approved prior FI runtime file lacks ownership marker: %s",
					spec.Role,
				)
			}

			priorSpec := spec
			priorSpec.Content = prior.Content

			priorState := classifyRuntimeFile(
				priorSpec,
			)

			if priorState != runtimeFileOwnedMatch {
				return fmt.Errorf(
					"live FI runtime does not match approved prior: %s (%s)",
					spec.Role,
					priorState,
				)
			}

			priors[spec.Role] = prior

		case runtimeFileAbsent:
			return fmt.Errorf(
				"FI runtime target is absent; update-runtime will not create it: %s",
				spec.Role,
			)

		case runtimeFileForeignCollision:
			return fmt.Errorf(
				"update-runtime will not replace foreign runtime state: %s",
				spec.Role,
			)

		case runtimeFileUnknown:
			return fmt.Errorf(
				"FI runtime could not be classified safely for update: %s",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"unexpected runtime update state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	// Publication pass.
	for _, spec := range specs {
		state := classifyRuntimeFile(
			spec,
		)

		switch state {
		case runtimeFileOwnedMatch:
			continue

		case runtimeFileOwnedDrift:
			prior, exists := priors[spec.Role]
			if !exists {
				return fmt.Errorf(
					"approved prior FI runtime file is absent after update preclassification: %s",
					spec.Role,
				)
			}

			priorSpec := spec
			priorSpec.Content = prior.Content

			priorState := classifyRuntimeFile(
				priorSpec,
			)

			if priorState != runtimeFileOwnedMatch {
				return fmt.Errorf(
					"live FI runtime changed after update preclassification: %s (%s)",
					spec.Role,
					priorState,
				)
			}

			if err := replaceApprovedPriorRuntimeFile(
				spec,
				prior,
				true,
			); err != nil {
				return err
			}

		default:
			return fmt.Errorf(
				"runtime resource changed after update preclassification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return verifyRuntimeFiles(
		specs,
		"updated",
	)
}

func loadApprovedPriorRuntimeFile(
	directory string,
	spec runtimeFileSpec,
) (approvedPriorRuntimeFile, error) {
	if spec.PriorName == "" {
		return approvedPriorRuntimeFile{},
			fmt.Errorf(
				"runtime approved-prior name is empty: %s",
				spec.Role,
			)
	}

	path := filepath.Join(
		directory,
		spec.PriorName,
	)

	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return approvedPriorRuntimeFile{},
			fmt.Errorf(
				"approved prior runtime file is unavailable: %s: %w",
				spec.Role,
				err,
			)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return approvedPriorRuntimeFile{},
			fmt.Errorf(
				"approved prior runtime file is not a regular file: %s",
				spec.Role,
			)
	}

	content, err := os.ReadFile(
		path,
	)
	if err != nil {
		return approvedPriorRuntimeFile{},
			fmt.Errorf(
				"read approved prior runtime file %s: %w",
				spec.Role,
				err,
			)
	}

	return approvedPriorRuntimeFile{
		Content: content,
		Path:    path,
	}, nil
}

func replaceApprovedPriorRuntimeFile(
	currentSpec runtimeFileSpec,
	prior approvedPriorRuntimeFile,
	requireManagedPrior bool,
) error {
	if prior.Path == currentSpec.Target {
		return fmt.Errorf(
			"approved prior runtime file must be separate from live target: %s",
			currentSpec.Role,
		)
	}

	currentPrior, err := readStableApprovedPriorRuntimeFile(
		prior.Path,
		currentSpec.Role,
	)
	if err != nil {
		return err
	}

	if !bytes.Equal(
		currentPrior,
		prior.Content,
	) {
		return fmt.Errorf(
			"approved prior runtime file changed before replacement: %s",
			currentSpec.Role,
		)
	}

	if requireManagedPrior {
		priorSpec := currentSpec
		priorSpec.Content = prior.Content

		if state := classifyRuntimeFile(
			priorSpec,
		); state != runtimeFileOwnedMatch {
			return fmt.Errorf(
				"live FI runtime does not match approved prior before replacement: %s (%s)",
				currentSpec.Role,
				state,
			)
		}
	} else if !runtimeForeignTargetMatchesPrior(
		currentSpec,
		prior.Content,
	) {
		return fmt.Errorf(
			"live runtime file does not match approved prior before adoption: %s",
			currentSpec.Role,
		)
	}

	if err := requireHostFileParent(
		currentSpec.Target,
	); err != nil {
		return err
	}

	parent := filepath.Dir(
		currentSpec.Target,
	)

	name := filepath.Base(
		currentSpec.Target,
	)

	file, err := os.CreateTemp(
		parent,
		"."+name+".fi-runtime-update.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create runtime replacement candidate %s: %w",
			currentSpec.Role,
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
		currentSpec.Content,
	); err != nil {
		return fmt.Errorf(
			"populate runtime replacement candidate %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if err := file.Chown(
		int(currentSpec.UID),
		int(currentSpec.GID),
	); err != nil {
		return fmt.Errorf(
			"set runtime replacement ownership %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if err := file.Chmod(
		currentSpec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set runtime replacement mode %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync runtime replacement candidate %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close runtime replacement candidate %s: %w",
			currentSpec.Role,
			err,
		)
	}

	closed = true

	tempSpec := currentSpec
	tempSpec.Target = temp

	if state := classifyRuntimeFile(
		tempSpec,
	); state != runtimeFileOwnedMatch {
		return fmt.Errorf(
			"runtime replacement candidate is not exact: %s (%s)",
			currentSpec.Role,
			state,
		)
	}

	priorNow, err := readStableApprovedPriorRuntimeFile(
		prior.Path,
		currentSpec.Role,
	)
	if err != nil {
		return err
	}

	if !bytes.Equal(
		priorNow,
		prior.Content,
	) {
		return fmt.Errorf(
			"approved prior runtime file changed during replacement: %s",
			currentSpec.Role,
		)
	}

	if requireManagedPrior {
		priorSpec := currentSpec
		priorSpec.Content = prior.Content

		if state := classifyRuntimeFile(
			priorSpec,
		); state != runtimeFileOwnedMatch {
			return fmt.Errorf(
				"live FI runtime changed before update publication: %s (%s)",
				currentSpec.Role,
				state,
			)
		}
	} else if !runtimeForeignTargetMatchesPrior(
		currentSpec,
		prior.Content,
	) {
		return fmt.Errorf(
			"live runtime file changed before adoption publication: %s",
			currentSpec.Role,
		)
	}

	if err := os.Rename(
		temp,
		currentSpec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish runtime replacement %s: %w",
			currentSpec.Role,
			err,
		)
	}

	published = true

	if err := syncHostFileDirectory(
		parent,
	); err != nil {
		return fmt.Errorf(
			"sync runtime replacement parent %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if state := classifyRuntimeFile(
		currentSpec,
	); state != runtimeFileOwnedMatch {
		return fmt.Errorf(
			"runtime replacement failed final verification: %s (%s)",
			currentSpec.Role,
			state,
		)
	}

	return nil
}

func readStableApprovedPriorRuntimeFile(
	path string,
	role string,
) ([]byte, error) {
	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return nil,
			fmt.Errorf(
				"inspect approved prior runtime file %s: %w",
				role,
				err,
			)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return nil,
			fmt.Errorf(
				"approved prior runtime file is no longer a regular file: %s",
				role,
			)
	}

	content, err := os.ReadFile(
		path,
	)
	if err != nil {
		return nil,
			fmt.Errorf(
				"read approved prior runtime file %s: %w",
				role,
				err,
			)
	}

	return content, nil
}

func requireApprovedPriorRuntimeDirectory(
	path string,
) error {
	if path == "" {
		return fmt.Errorf(
			"approved prior runtime directory is required",
		)
	}

	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect approved prior runtime directory: %w",
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return fmt.Errorf(
			"approved prior runtime directory is unavailable: %s",
			path,
		)
	}

	return nil
}

func runtimeForeignTargetMatchesPrior(
	spec runtimeFileSpec,
	prior []byte,
) bool {
	info, err := os.Lstat(
		spec.Target,
	)
	if err != nil {
		return false
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return false
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) ||
		uint64(stat.Nlink) != 1 {
		return false
	}

	content, err := os.ReadFile(
		spec.Target,
	)
	if err != nil {
		return false
	}

	return bytes.Equal(
		content,
		prior,
	)
}

func verifyRuntimeFiles(
	specs []runtimeFileSpec,
	operation string,
) error {
	for _, spec := range specs {
		state := classifyRuntimeFile(
			spec,
		)

		if state != runtimeFileOwnedMatch {
			return fmt.Errorf(
				"%s runtime file failed final verification: %s (%s)",
				operation,
				spec.Role,
				state,
			)
		}
	}

	return nil
}

func verifyRuntimeTransitionParents(
	plan runtimePlan,
	operation string,
) error {
	for _, spec := range plan.Parents {
		state := classifyLifecycleParent(
			spec,
		)

		if state != lifecycleParentDirectoryMatch {
			return fmt.Errorf(
				"runtime %s parent is not exact: %s (%s)",
				operation,
				spec.Role,
				state,
			)
		}
	}

	return nil
}
