// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// UpdateHostFiles advances the complete FI-owned production host-file layer
// only from an explicitly supplied approved prior version.
//
// Existing resources already matching the current version remain untouched.
// An OWNED_DRIFT resource may be replaced only when the live resource exactly
// matches the corresponding approved-prior content and required live metadata.
//
// Production FI jails must be stopped for the transition.
func UpdateHostFiles(
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

	if err := requireHostFileUpdateQuiescent(); err != nil {
		return err
	}

	specs, err := hostFileSpecs(config)
	if err != nil {
		return err
	}

	if err := verifyHostFileParents(
		specs,
	); err != nil {
		return err
	}

	priorSpecs, err := loadApprovedPriorHostFileSpecs(
		approvedPriorDirectory,
		specs,
	)
	if err != nil {
		return err
	}

	return updateHostFileSpecs(
		specs,
		priorSpecs,
	)
}

func loadApprovedPriorHostFileSpecs(
	approvedPriorDirectory string,
	specs []hostFileSpec,
) (map[string]hostFileSpec, error) {
	if approvedPriorDirectory == "" {
		return nil, fmt.Errorf(
			"approved prior host-file directory is required",
		)
	}

	directoryInfo, err := os.Lstat(
		approvedPriorDirectory,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"inspect approved prior host-file directory: %w",
			err,
		)
	}

	if directoryInfo.Mode()&os.ModeSymlink != 0 ||
		!directoryInfo.IsDir() {
		return nil, fmt.Errorf(
			"approved prior host-file path is not an exact directory: %s",
			approvedPriorDirectory,
		)
	}

	expectedNames := make(
		map[string]hostFileSpec,
		len(specs),
	)

	for _, spec := range specs {
		name := filepath.Base(
			spec.Target,
		)

		if _, exists := expectedNames[name]; exists {
			return nil, fmt.Errorf(
				"duplicate host-file basename in approved-prior contract: %s",
				name,
			)
		}

		expectedNames[name] = spec
	}

	entries, err := os.ReadDir(
		approvedPriorDirectory,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read approved prior host-file directory: %w",
			err,
		)
	}

	if len(entries) != len(expectedNames) {
		return nil, fmt.Errorf(
			"approved prior host-file snapshot is incomplete or contains extra resources: got %d files, want %d",
			len(entries),
			len(expectedNames),
		)
	}

	priorSpecs := make(
		map[string]hostFileSpec,
		len(specs),
	)

	for _, entry := range entries {
		currentSpec, exists := expectedNames[entry.Name()]
		if !exists {
			return nil, fmt.Errorf(
				"approved prior host-file snapshot contains unexpected resource: %s",
				entry.Name(),
			)
		}

		path := filepath.Join(
			approvedPriorDirectory,
			entry.Name(),
		)

		info, err := os.Lstat(
			path,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect approved prior host file %s: %w",
				currentSpec.Role,
				err,
			)
		}

		if info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() {
			return nil, fmt.Errorf(
				"approved prior host file is not a regular file: %s",
				currentSpec.Role,
			)
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf(
				"approved prior host-file metadata unavailable: %s",
				currentSpec.Role,
			)
		}

		if uint64(stat.Nlink) != 1 {
			return nil, fmt.Errorf(
				"approved prior host file has unexpected link count: %s",
				currentSpec.Role,
			)
		}

		content, err := os.ReadFile(
			path,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"read approved prior host file %s: %w",
				currentSpec.Role,
				err,
			)
		}

		if !containsExactLine(
			content,
			hostFileMarker,
		) {
			return nil, fmt.Errorf(
				"approved prior host file lacks FI ownership marker: %s",
				currentSpec.Role,
			)
		}

		if !containsExactLine(
			content,
			"# FI-ROLE: "+currentSpec.Role,
		) {
			return nil, fmt.Errorf(
				"approved prior host file lacks exact FI role: %s",
				currentSpec.Role,
			)
		}

		if hostFileTokenPattern.Match(
			content,
		) {
			return nil, fmt.Errorf(
				"approved prior host file contains unresolved configuration token: %s",
				currentSpec.Role,
			)
		}

		priorSpec := currentSpec
		priorSpec.Content = content

		priorSpecs[currentSpec.Role] = priorSpec
	}

	if len(priorSpecs) != len(specs) {
		return nil, fmt.Errorf(
			"approved prior host-file snapshot is incomplete",
		)
	}

	return priorSpecs, nil
}

func replaceApprovedHostFile(
	currentSpec hostFileSpec,
	priorSpec hostFileSpec,
) error {
	if state := classifyHostFile(
		priorSpec,
	); state != hostFileOwnedMatch {
		return fmt.Errorf(
			"host file changed before approved replacement: %s (%s)",
			currentSpec.Role,
			state,
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
		"."+name+".fi-update.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary updated host file %s: %w",
			currentSpec.Role,
			err,
		)
	}

	temp := file.Name()
	closed := false
	published := false

	defer func() {
		if !closed {
			file.Close()
		}

		if !published {
			os.Remove(temp)
		}
	}()

	if _, err := file.Write(
		currentSpec.Content,
	); err != nil {
		return fmt.Errorf(
			"populate temporary updated host file %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if currentSpec.UID > uint64(^uint32(0)) ||
		currentSpec.GID > uint64(^uint32(0)) {
		return fmt.Errorf(
			"host-file UID/GID exceeds supported range: %s",
			currentSpec.Role,
		)
	}

	if err := file.Chown(
		int(currentSpec.UID),
		int(currentSpec.GID),
	); err != nil {
		return fmt.Errorf(
			"set temporary updated host-file ownership %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if err := file.Chmod(
		currentSpec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set temporary updated host-file mode %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync temporary updated host file %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close temporary updated host file %s: %w",
			currentSpec.Role,
			err,
		)
	}

	closed = true

	tempSpec := currentSpec
	tempSpec.Target = temp

	if state := classifyHostFile(
		tempSpec,
	); state != hostFileOwnedMatch {
		return fmt.Errorf(
			"temporary updated host file failed exact verification: %s (%s)",
			currentSpec.Role,
			state,
		)
	}

	// Re-establish approved-prior authority immediately before rename.
	if state := classifyHostFile(
		priorSpec,
	); state != hostFileOwnedMatch {
		return fmt.Errorf(
			"host file changed after update preclassification: %s (%s)",
			currentSpec.Role,
			state,
		)
	}

	if err := os.Rename(
		temp,
		currentSpec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish updated host file %s: %w",
			currentSpec.Role,
			err,
		)
	}

	published = true

	if err := syncHostFileDirectory(
		parent,
	); err != nil {
		return fmt.Errorf(
			"sync updated host-file parent for %s: %w",
			currentSpec.Role,
			err,
		)
	}

	if state := classifyHostFile(
		currentSpec,
	); state != hostFileOwnedMatch {
		return fmt.Errorf(
			"updated host file failed exact verification: %s (%s)",
			currentSpec.Role,
			state,
		)
	}

	return nil
}

func requireHostFileUpdateQuiescent() error {
	for _, jailName := range []string{
		"fi-sor-db",
		"fi-ingest",
		"fi-receiver",
	} {
		output, err := exec.Command(
			"/usr/sbin/jls",
			"-j",
			jailName,
		).CombinedOutput()

		if err == nil {
			return fmt.Errorf(
				"host-file update requires FI production jails stopped: %s is running",
				jailName,
			)
		}

		var exitError *exec.ExitError

		if !errors.As(
			err,
			&exitError,
		) {
			return fmt.Errorf(
				"inspect FI jail state before host-file update %s: %w",
				jailName,
				err,
			)
		}

		if exitError.ExitCode() != 1 {
			return fmt.Errorf(
				"inspect FI jail state before host-file update %s failed with status %d: %s",
				jailName,
				exitError.ExitCode(),
				string(output),
			)
		}
	}

	return nil
}

func syncHostFileDirectory(
	path string,
) error {
	directory, err := os.Open(
		path,
	)
	if err != nil {
		return err
	}

	if err := directory.Sync(); err != nil {
		directory.Close()
		return err
	}

	return directory.Close()
}

func updateHostFileSpecs(
	specs []hostFileSpec,
	priorSpecs map[string]hostFileSpec,
) error {
	// Preclassify the complete layer before first mutation.
	for _, spec := range specs {
		priorSpec, exists := priorSpecs[spec.Role]
		if !exists {
			return fmt.Errorf(
				"approved prior host file is absent: %s",
				spec.Role,
			)
		}

		state := classifyHostFile(
			spec,
		)

		switch state {
		case hostFileOwnedMatch:

		case hostFileOwnedDrift:
			priorState := classifyHostFile(
				priorSpec,
			)

			if priorState != hostFileOwnedMatch {
				return fmt.Errorf(
					"host file does not match approved prior version: %s (%s)",
					spec.Role,
					priorState,
				)
			}

		case hostFileAbsent:
			return fmt.Errorf(
				"host file is absent and is not eligible for update: %s",
				spec.Role,
			)

		case hostFileForeignCollision:
			return fmt.Errorf(
				"host file collides with a non-FI resource: %s",
				spec.Role,
			)

		case hostFileUnknown:
			return fmt.Errorf(
				"host file could not be classified safely: %s",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"unexpected host-file update state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	// Advance only resources still equal to their approved prior version.
	for _, spec := range specs {
		priorSpec := priorSpecs[spec.Role]

		state := classifyHostFile(
			spec,
		)

		switch state {
		case hostFileOwnedMatch:
			continue

		case hostFileOwnedDrift:
			priorState := classifyHostFile(
				priorSpec,
			)

			if priorState != hostFileOwnedMatch {
				return fmt.Errorf(
					"host file changed after update preclassification: %s (%s)",
					spec.Role,
					priorState,
				)
			}

			if err := replaceApprovedHostFile(
				spec,
				priorSpec,
			); err != nil {
				return err
			}

		default:
			return fmt.Errorf(
				"host file changed after update preclassification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range specs {
		state := classifyHostFile(
			spec,
		)

		if state != hostFileOwnedMatch {
			return fmt.Errorf(
				"updated host file failed final verification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}
