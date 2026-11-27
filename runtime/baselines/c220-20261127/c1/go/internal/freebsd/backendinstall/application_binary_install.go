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

type applicationBinaryFileState string

const (
	applicationBinaryFileAbsent applicationBinaryFileState = "ABSENT"

	applicationBinaryFileForeignCollision applicationBinaryFileState = "FOREIGN_COLLISION"

	applicationBinaryFileOwnedDrift applicationBinaryFileState = "OWNED_DRIFT"

	applicationBinaryFileOwnedMatch applicationBinaryFileState = "OWNED_MATCH"

	applicationBinaryFileUnknown applicationBinaryFileState = "UNKNOWN"
)

type applicationBinaryFileSpec struct {
	Content []byte
	GID     uint64
	Mode    os.FileMode
	Role    string
	Target  string
	UID     uint64
}

type applicationBinaryPlan struct {
	Files   []applicationBinaryFileSpec
	Parents []lifecycleParentSpec
}

func ApplyBinaries(
	config Config,
	releaseDirectory string,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	plan, err := buildApplicationBinaryPlan(
		config,
		releaseDirectory,
	)
	if err != nil {
		return err
	}

	if err := preclassifyApplicationBinaryPlan(
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
					"create application binary parent %s: %w",
					spec.Role,
					err,
				)
			}

		default:
			return fmt.Errorf(
				"application binary parent changed after preclassification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyApplicationBinaryFile(
			spec,
		)

		switch state {
		case applicationBinaryFileOwnedMatch:
			continue

		case applicationBinaryFileAbsent:
			if err := publishAbsentApplicationBinary(
				spec,
			); err != nil {
				return fmt.Errorf(
					"publish application binary %s: %w",
					spec.Role,
					err,
				)
			}

		default:
			return fmt.Errorf(
				"application binary changed after preclassification: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return verifyApplicationBinaryPlan(
		plan,
	)
}

func VerifyBinaries(
	config Config,
	releaseDirectory string,
) error {
	probe := systemHostProbe{}

	if err := requireHostFileHost(
		config,
		probe,
	); err != nil {
		return err
	}

	plan, err := buildApplicationBinaryPlan(
		config,
		releaseDirectory,
	)
	if err != nil {
		return err
	}

	return verifyApplicationBinaryPlan(
		plan,
	)
}

func buildApplicationBinaryPlan(
	config Config,
	releaseDirectory string,
) (applicationBinaryPlan, error) {
	directory, err :=
		requireApplicationBinaryReleaseDirectory(
			releaseDirectory,
		)
	if err != nil {
		return applicationBinaryPlan{}, err
	}

	receiverContent, err :=
		loadApplicationBinarySource(
			filepath.Join(
				directory,
				"fi-receiver",
			),
		)
	if err != nil {
		return applicationBinaryPlan{}, fmt.Errorf(
			"load fi-receiver release binary: %w",
			err,
		)
	}

	ingestContent, err :=
		loadApplicationBinarySource(
			filepath.Join(
				directory,
				"fi-ingest-worker",
			),
		)
	if err != nil {
		return applicationBinaryPlan{}, fmt.Errorf(
			"load fi-ingest-worker release binary: %w",
			err,
		)
	}

	receiverRoot :=
		config.Value("FI_RECEIVER_ROOT")

	ingestRoot :=
		config.Value("FI_INGEST_ROOT")

	receiverParent :=
		filepath.Join(
			receiverRoot,
			"usr/local/sbin",
		)

	ingestParent :=
		filepath.Join(
			ingestRoot,
			"usr/local/sbin",
		)

	return applicationBinaryPlan{
		Parents: []lifecycleParentSpec{
			{
				GID:  0,
				Mode: 0o755,
				Path: receiverParent,
				Role: "receiver-local-sbin",
				UID:  0,
			},
			{
				GID:  0,
				Mode: 0o755,
				Path: ingestParent,
				Role: "ingest-local-sbin",
				UID:  0,
			},
		},
		Files: []applicationBinaryFileSpec{
			{
				Content: receiverContent,
				GID:     0,
				Mode:    0o555,
				Role:    "fi-receiver",
				Target: filepath.Join(
					receiverParent,
					"fi-receiver",
				),
				UID: 0,
			},
			{
				Content: ingestContent,
				GID:     0,
				Mode:    0o555,
				Role:    "fi-ingest-worker",
				Target: filepath.Join(
					ingestParent,
					"fi-ingest-worker",
				),
				UID: 0,
			},
		},
	}, nil
}

func classifyApplicationBinaryFile(
	spec applicationBinaryFileSpec,
) applicationBinaryFileState {
	info, err := os.Lstat(
		spec.Target,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return applicationBinaryFileAbsent

	default:
		return applicationBinaryFileUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return applicationBinaryFileForeignCollision
	}

	content, err := os.ReadFile(
		spec.Target,
	)
	if err != nil {
		return applicationBinaryFileUnknown
	}

	if !bytes.Equal(
		content,
		spec.Content,
	) {
		return applicationBinaryFileForeignCollision
	}

	stat, ok :=
		info.Sys().(*syscall.Stat_t)
	if !ok {
		return applicationBinaryFileUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		!exactManagedFileMode(
			info.Mode(),
			spec.Mode,
		) ||
		uint64(stat.Nlink) != 1 {
		return applicationBinaryFileOwnedDrift
	}

	return applicationBinaryFileOwnedMatch
}

func loadApplicationBinarySource(
	source string,
) ([]byte, error) {
	info, err := os.Lstat(
		source,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"inspect release binary %s: %w",
			source,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf(
			"release binary is a symbolic link: %s",
			source,
		)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"release binary is not a regular file: %s",
			source,
		)
	}

	if info.Size() == 0 {
		return nil, fmt.Errorf(
			"release binary is empty: %s",
			source,
		)
	}

	content, err := os.ReadFile(
		source,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read release binary %s: %w",
			source,
			err,
		)
	}

	if len(content) == 0 {
		return nil, fmt.Errorf(
			"release binary became empty: %s",
			source,
		)
	}

	return content, nil
}

func preclassifyApplicationBinaryPlan(
	plan applicationBinaryPlan,
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
				"unsafe application binary parent: %s (FOREIGN_COLLISION)",
				spec.Role,
			)

		case lifecycleParentUnknown:
			return fmt.Errorf(
				"unable to classify application binary parent: %s (UNKNOWN)",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid application binary parent state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyApplicationBinaryFile(
			spec,
		)

		switch state {
		case applicationBinaryFileAbsent,
			applicationBinaryFileOwnedMatch:

		case applicationBinaryFileOwnedDrift:
			return fmt.Errorf(
				"application binary metadata has drifted: %s",
				spec.Role,
			)

		case applicationBinaryFileForeignCollision:
			return fmt.Errorf(
				"existing application binary does not match release: %s",
				spec.Role,
			)

		case applicationBinaryFileUnknown:
			return fmt.Errorf(
				"unable to classify application binary safely: %s",
				spec.Role,
			)

		default:
			return fmt.Errorf(
				"invalid application binary state: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}

func publishAbsentApplicationBinary(
	spec applicationBinaryFileSpec,
) error {
	if state := classifyApplicationBinaryFile(
		spec,
	); state != applicationBinaryFileAbsent {
		return fmt.Errorf(
			"application binary changed before creation: %s",
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
		"."+name+".fi-binary.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary application binary: %w",
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
			"populate temporary application binary: %w",
			err,
		)
	}

	if err := file.Chown(
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set temporary application binary ownership: %w",
			err,
		)
	}

	if err := file.Chmod(
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set temporary application binary mode: %w",
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync temporary application binary: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close temporary application binary: %w",
			err,
		)
	}

	closed = true

	tempSpec := spec
	tempSpec.Target = temp

	if state := classifyApplicationBinaryFile(
		tempSpec,
	); state != applicationBinaryFileOwnedMatch {
		return fmt.Errorf(
			"temporary application binary failed verification: %s",
			state,
		)
	}

	if state := classifyApplicationBinaryFile(
		spec,
	); state != applicationBinaryFileAbsent {
		return fmt.Errorf(
			"application binary changed before publication: %s",
			state,
		)
	}

	if err := os.Link(
		temp,
		spec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish application binary without overwrite: %w",
			err,
		)
	}

	if err := os.Remove(
		temp,
	); err != nil {
		return fmt.Errorf(
			"remove temporary application binary link: %w",
			err,
		)
	}

	published = true

	if err := syncHostFileDirectory(
		parent,
	); err != nil {
		return fmt.Errorf(
			"sync application binary parent directory: %w",
			err,
		)
	}

	if state := classifyApplicationBinaryFile(
		spec,
	); state != applicationBinaryFileOwnedMatch {
		return fmt.Errorf(
			"application binary publication failed verification: %s",
			state,
		)
	}

	return nil
}

func requireApplicationBinaryReleaseDirectory(
	releaseDirectory string,
) (string, error) {
	if releaseDirectory == "" {
		return "", fmt.Errorf(
			"application binary release directory cannot be empty",
		)
	}

	if !filepath.IsAbs(
		releaseDirectory,
	) {
		return "", fmt.Errorf(
			"application binary release directory must be absolute: %s",
			releaseDirectory,
		)
	}

	directory :=
		filepath.Clean(
			releaseDirectory,
		)

	info, err := os.Lstat(
		directory,
	)
	if err != nil {
		return "", fmt.Errorf(
			"inspect application binary release directory: %w",
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf(
			"application binary release directory is a symbolic link: %s",
			directory,
		)
	}

	if !info.IsDir() {
		return "", fmt.Errorf(
			"application binary release path is not a directory: %s",
			directory,
		)
	}

	return directory, nil
}

func verifyApplicationBinaryPlan(
	plan applicationBinaryPlan,
) error {
	for _, spec := range plan.Parents {
		state := classifyLifecycleParent(
			spec,
		)

		if state != lifecycleParentDirectoryMatch {
			return fmt.Errorf(
				"application binary parent is not DIRECTORY_MATCH: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	for _, spec := range plan.Files {
		state := classifyApplicationBinaryFile(
			spec,
		)

		if state != applicationBinaryFileOwnedMatch {
			return fmt.Errorf(
				"application binary is not OWNED_MATCH: %s (%s)",
				spec.Role,
				state,
			)
		}
	}

	return nil
}
