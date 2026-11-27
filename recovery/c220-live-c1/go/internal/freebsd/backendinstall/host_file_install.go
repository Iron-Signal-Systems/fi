// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type hostFileState string

const (
	hostFileAbsent           hostFileState = "ABSENT"
	hostFileForeignCollision hostFileState = "FOREIGN_COLLISION"
	hostFileOwnedDrift       hostFileState = "OWNED_DRIFT"
	hostFileOwnedMatch       hostFileState = "OWNED_MATCH"
	hostFileUnknown          hostFileState = "UNKNOWN"
)

func ApplyHostFiles(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	specs, err := hostFileSpecs(config)
	if err != nil {
		return err
	}

	if err := preclassifyHostFileParents(
		specs,
	); err != nil {
		return err
	}

	for _, spec := range specs {
		state := classifyHostFile(spec)

		switch state {
		case hostFileAbsent, hostFileOwnedMatch:

		case hostFileOwnedDrift:
			return fmt.Errorf(
				"OWNED_DRIFT: FI host file %s is FI-owned but has drifted",
				spec.Role,
			)

		case hostFileForeignCollision:
			return fmt.Errorf(
				"FOREIGN_COLLISION: FI host file %s collides with a non-FI resource",
				spec.Role,
			)

		case hostFileUnknown:
			return fmt.Errorf(
				"UNKNOWN: FI host file %s could not be classified safely",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid host-file state for %s: %s",
				spec.Role,
				state,
			)
		}
	}

	mutator := systemHostFileMutator{}

	if err := applyHostFileParents(
		mutator,
	); err != nil {
		return err
	}

	for _, spec := range specs {
		state := classifyHostFile(spec)

		switch state {
		case hostFileOwnedMatch:
			continue

		case hostFileAbsent:
			if err := mutator.PublishAbsent(
				spec,
			); err != nil {
				return fmt.Errorf(
					"create FI host file %s: %w",
					spec.Role,
					err,
				)
			}

		default:
			return fmt.Errorf(
				"FI host file changed after preclassification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range specs {
		state := classifyHostFile(spec)

		if state != hostFileOwnedMatch {
			return fmt.Errorf(
				"FI host file failed final verification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}

func VerifyHostFiles(
	config Config,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
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

	for _, spec := range specs {
		state := classifyHostFile(spec)

		if state != hostFileOwnedMatch {
			return fmt.Errorf(
				"FI host file is not OWNED_MATCH: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}

func exactManagedFileMode(
	actual os.FileMode,
	expected os.FileMode,
) bool {
	if actual.Perm() != expected.Perm() {
		return false
	}

	special := os.ModeSetuid | os.ModeSetgid | os.ModeSticky

	return actual&special == 0
}

func classifyHostFile(
	spec hostFileSpec,
) hostFileState {
	info, err := os.Lstat(spec.Target)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return hostFileAbsent

	default:
		return hostFileUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return hostFileForeignCollision
	}

	content, err := os.ReadFile(spec.Target)
	if err != nil {
		return hostFileUnknown
	}

	if !containsExactLine(
		content,
		hostFileMarker,
	) {
		return hostFileForeignCollision
	}

	if !bytes.Equal(
		content,
		spec.Content,
	) {
		return hostFileOwnedDrift
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return hostFileUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) ||
		uint64(stat.Nlink) != 1 {
		return hostFileOwnedDrift
	}

	return hostFileOwnedMatch
}

func requireHostFileHost(
	config Config,
	probe hostProbe,
) error {
	if probe.EUID() != 0 {
		return fmt.Errorf(
			"host-file operation must run as root on the intended FreeBSD host",
		)
	}

	kernel, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect operating system before host-file operation: %w",
			err,
		)
	}

	if strings.TrimSpace(kernel) != "FreeBSD" {
		return fmt.Errorf(
			"host-file operation requires FreeBSD",
		)
	}

	hostname, err := probe.Run(
		"hostname",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect hostname before host-file operation: %w",
			err,
		)
	}

	hostname = strings.TrimSpace(hostname)

	if hostname != config.Value("FI_HOSTNAME") {
		return fmt.Errorf(
			"deployment hostname mismatch: expected %s, observed %s",
			config.Value("FI_HOSTNAME"),
			hostname,
		)
	}

	return nil
}

func requireHostFileParent(
	target string,
) error {
	parent := filepath.Dir(target)

	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf(
			"host-file parent unavailable: %s: %w",
			parent,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"host-file parent is a symbolic link: %s",
			parent,
		)
	}

	if !info.IsDir() {
		return fmt.Errorf(
			"host-file parent is not a directory: %s",
			parent,
		)
	}

	return nil
}

type systemHostFileMutator struct{}

func (systemHostFileMutator) PublishAbsent(
	spec hostFileSpec,
) error {
	state := classifyHostFile(spec)

	if state != hostFileAbsent {
		return fmt.Errorf(
			"host file changed before creation: %s",
			state,
		)
	}

	if err := requireHostFileParent(
		spec.Target,
	); err != nil {
		return err
	}

	parent := filepath.Dir(spec.Target)
	name := filepath.Base(spec.Target)

	file, err := os.CreateTemp(
		parent,
		"."+name+".fi.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary host file: %w",
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
		spec.Content,
	); err != nil {
		return fmt.Errorf(
			"populate temporary host file: %w",
			err,
		)
	}

	if spec.UID > uint64(^uint32(0)) ||
		spec.GID > uint64(^uint32(0)) {
		return fmt.Errorf(
			"host-file UID/GID exceeds supported range",
		)
	}

	if err := file.Chown(
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set temporary host-file ownership: %w",
			err,
		)
	}

	if err := file.Chmod(
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set temporary host-file mode: %w",
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync temporary host file: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close temporary host file: %w",
			err,
		)
	}

	closed = true

	tempSpec := spec
	tempSpec.Target = temp

	if state := classifyHostFile(
		tempSpec,
	); state != hostFileOwnedMatch {
		return fmt.Errorf(
			"temporary host file failed exact verification: %s",
			state,
		)
	}

	if state := classifyHostFile(
		spec,
	); state != hostFileAbsent {
		return fmt.Errorf(
			"host file changed before publication: %s",
			state,
		)
	}

	if err := os.Link(
		temp,
		spec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish host file without overwrite: %w",
			err,
		)
	}

	if err := os.Remove(temp); err != nil {
		return fmt.Errorf(
			"remove temporary publication link: %w",
			err,
		)
	}

	published = true

	if state := classifyHostFile(
		spec,
	); state != hostFileOwnedMatch {
		return fmt.Errorf(
			"created host file failed verification: %s",
			state,
		)
	}

	return nil
}
