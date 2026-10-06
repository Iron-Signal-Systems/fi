// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// -----------------------------------------------------------------------------
// Directory contract
// -----------------------------------------------------------------------------

const (
	directorySchemaProperty = "org.ironsignal.fi:directory-schema"
	directorySchemaVersion  = "1"
)

type directoryState string

const (
	directoryAbsent           directoryState = "ABSENT"
	directoryForeignCollision directoryState = "FOREIGN_COLLISION"
	directoryOwnedDrift       directoryState = "OWNED_DRIFT"
	directoryOwnedMatch       directoryState = "OWNED_MATCH"
	directoryUnknown          directoryState = "UNKNOWN"
)

type directoryMarkerState string

const (
	directoryMarkerAbsent  directoryMarkerState = "ABSENT"
	directoryMarkerDrift   directoryMarkerState = "DRIFT"
	directoryMarkerMatch   directoryMarkerState = "MATCH"
	directoryMarkerUnknown directoryMarkerState = "UNKNOWN"
)

type managedDirectorySpec struct {
	GID  uint64
	Mode os.FileMode
	Path string
	UID  uint64
}

type hostDirectorySpec struct {
	Dataset fiDatasetSpec
	GID     uint64
	Mode    os.FileMode
	Name    string
	Path    string
	UID     uint64
}

type jailDirectorySpec struct {
	Dataset jailDatasetSpec
	Name    string
	Paths   []managedDirectorySpec
	Role    string
	Root    string
}

// -----------------------------------------------------------------------------
// Public operation
// -----------------------------------------------------------------------------

func ApplyDirectories(config Config) error {
	probe := systemHostProbe{}

	if err := requireDirectoryHost(
		config,
		probe,
	); err != nil {
		return err
	}

	hostSpecs, jailSpecs, err := directorySpecs(config)
	if err != nil {
		return err
	}

	if err := requireDirectoryPrerequisites(
		probe,
		hostSpecs,
		jailSpecs,
	); err != nil {
		return err
	}

	if err := precheckDirectoryLayer(
		probe,
		hostSpecs,
		jailSpecs,
	); err != nil {
		return err
	}

	mutator := systemDirectoryMutator{}

	for _, spec := range hostSpecs {
		if err := applyHostDirectory(
			probe,
			mutator,
			spec,
		); err != nil {
			return err
		}
	}

	for _, spec := range jailSpecs {
		if err := applyJailDirectories(
			probe,
			mutator,
			spec,
		); err != nil {
			return err
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Apply orchestration
// -----------------------------------------------------------------------------

func applyHostDirectory(
	probe hostProbe,
	mutator systemDirectoryMutator,
	spec hostDirectorySpec,
) error {
	state := classifyHostDirectory(
		probe,
		spec,
	)

	switch state {
	case directoryOwnedMatch:
		return nil

	case directoryAbsent:
		if err := mutator.InitializeHost(spec); err != nil {
			return fmt.Errorf(
				"initialize %s: %w",
				spec.Name,
				err,
			)
		}

	case directoryOwnedDrift:
		return fmt.Errorf(
			"OWNED_DRIFT: FI directory differs from requested state: %s",
			spec.Name,
		)

	case directoryForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: unsafe FI directory path: %s",
			spec.Name,
		)

	case directoryUnknown:
		return fmt.Errorf(
			"UNKNOWN: unable to establish safe FI directory state: %s",
			spec.Name,
		)

	default:
		return fmt.Errorf(
			"invalid directory state for %s: %s",
			spec.Name,
			state,
		)
	}

	state = classifyHostDirectory(
		probe,
		spec,
	)

	if state != directoryOwnedMatch {
		return fmt.Errorf(
			"initialized FI directory did not verify as OWNED_MATCH: %s (%s)",
			spec.Name,
			state,
		)
	}

	return nil
}

func applyJailDirectories(
	probe hostProbe,
	mutator systemDirectoryMutator,
	spec jailDirectorySpec,
) error {
	state := classifyJailDirectories(
		probe,
		spec,
	)

	switch state {
	case directoryOwnedMatch:
		return nil

	case directoryAbsent:
		if err := mutator.CreateJailPaths(spec); err != nil {
			return fmt.Errorf(
				"create %s: %w",
				spec.Name,
				err,
			)
		}

	case directoryOwnedDrift:
		return fmt.Errorf(
			"OWNED_DRIFT: FI jail directories differ from requested state: %s",
			spec.Name,
		)

	case directoryForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: unsafe FI jail directory path: %s",
			spec.Name,
		)

	case directoryUnknown:
		return fmt.Errorf(
			"UNKNOWN: unable to establish safe FI jail directory state: %s",
			spec.Name,
		)

	default:
		return fmt.Errorf(
			"invalid jail directory state for %s: %s",
			spec.Name,
			state,
		)
	}

	state = classifyJailDirectories(
		probe,
		spec,
	)

	if state != directoryOwnedMatch {
		return fmt.Errorf(
			"new FI jail directories did not verify as OWNED_MATCH: %s (%s)",
			spec.Name,
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Layer-wide preclassification
// -----------------------------------------------------------------------------

func precheckDirectoryLayer(
	probe hostProbe,
	hostSpecs []hostDirectorySpec,
	jailSpecs []jailDirectorySpec,
) error {
	for _, spec := range hostSpecs {
		state := classifyHostDirectory(
			probe,
			spec,
		)

		if err := acceptedDirectoryPrecheck(
			spec.Name,
			state,
		); err != nil {
			return err
		}
	}

	for _, spec := range jailSpecs {
		state := classifyJailDirectories(
			probe,
			spec,
		)

		if err := acceptedDirectoryPrecheck(
			spec.Name,
			state,
		); err != nil {
			return err
		}
	}

	return nil
}

func acceptedDirectoryPrecheck(
	name string,
	state directoryState,
) error {
	switch state {
	case directoryAbsent,
		directoryOwnedMatch:
		return nil

	case directoryOwnedDrift:
		return fmt.Errorf(
			"OWNED_DRIFT: FI directory differs from requested state: %s",
			name,
		)

	case directoryForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: unsafe FI directory path: %s",
			name,
		)

	case directoryUnknown:
		return fmt.Errorf(
			"UNKNOWN: unable to establish safe FI directory state: %s",
			name,
		)

	default:
		return fmt.Errorf(
			"invalid directory classification for %s: %s",
			name,
			state,
		)
	}
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

func classifyHostDirectory(
	probe hostProbe,
	spec hostDirectorySpec,
) directoryState {
	marker := inspectDirectoryMarker(
		probe,
		spec.Dataset.Target,
	)

	switch marker {
	case directoryMarkerMatch:
		exact, err := directoryPathExact(
			managedDirectorySpec{
				GID:  spec.GID,
				Mode: spec.Mode,
				Path: spec.Path,
				UID:  spec.UID,
			},
		)
		if err != nil {
			return directoryUnknown
		}

		if exact {
			return directoryOwnedMatch
		}

		return directoryOwnedDrift

	case directoryMarkerAbsent:
		info, err := os.Lstat(spec.Path)

		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return directoryForeignCollision
			}

			if info.IsDir() {
				return directoryAbsent
			}

			return directoryForeignCollision

		case os.IsNotExist(err):
			return directoryUnknown

		default:
			return directoryUnknown
		}

	case directoryMarkerDrift:
		return directoryOwnedDrift

	default:
		return directoryUnknown
	}
}

func classifyJailDirectories(
	probe hostProbe,
	spec jailDirectorySpec,
) directoryState {
	marker := inspectDirectoryMarker(
		probe,
		spec.Dataset.Target,
	)

	switch marker {
	case directoryMarkerMatch:
		for _, directory := range spec.Paths {
			exact, err := directoryPathExact(directory)
			if err != nil {
				return directoryUnknown
			}

			if !exact {
				return directoryOwnedDrift
			}
		}

		return directoryOwnedMatch

	case directoryMarkerAbsent:
		for _, directory := range spec.Paths {
			_, err := os.Lstat(directory.Path)

			switch {
			case err == nil:
				return directoryForeignCollision

			case os.IsNotExist(err):
				continue

			default:
				return directoryUnknown
			}
		}

		return directoryAbsent

	case directoryMarkerDrift:
		return directoryOwnedDrift

	default:
		return directoryUnknown
	}
}

func inspectDirectoryMarker(
	probe hostProbe,
	dataset string,
) directoryMarkerState {
	result, err := probe.Run(
		"zfs",
		"get",
		"-H",
		"-o",
		"value,source",
		directorySchemaProperty,
		dataset,
	)
	if err != nil {
		return directoryMarkerUnknown
	}

	fields := strings.Fields(result)
	if len(fields) < 2 {
		return directoryMarkerUnknown
	}

	if fields[1] != "local" {
		return directoryMarkerAbsent
	}

	if fields[0] != directorySchemaVersion {
		return directoryMarkerDrift
	}

	return directoryMarkerMatch
}

func directoryPathExact(
	spec managedDirectorySpec,
) (bool, error) {
	info, err := os.Lstat(spec.Path)

	switch {
	case err == nil:
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return false, nil
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf(
			"unsupported stat result for %s",
			spec.Path,
		)
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		info.Mode().Perm() != spec.Mode.Perm() {
		return false, nil
	}

	return true, nil
}

// -----------------------------------------------------------------------------
// Prerequisites
// -----------------------------------------------------------------------------

func requireDirectoryPrerequisites(
	probe hostProbe,
	hostSpecs []hostDirectorySpec,
	jailSpecs []jailDirectorySpec,
) error {
	for _, spec := range hostSpecs {
		if spec.Path != spec.Dataset.Mountpoint {
			return fmt.Errorf(
				"directory prerequisite path does not match dataset mountpoint: %s",
				spec.Name,
			)
		}

		state := inspectFIDatasetState(
			probe,
			spec.Dataset,
		)

		if state != fiDatasetOwnedMatch {
			return fmt.Errorf(
				"directory prerequisite ZFS dataset is not OWNED_MATCH: %s (%s)",
				spec.Dataset.Target,
				state,
			)
		}
	}

	for _, spec := range jailSpecs {
		state := inspectJailDatasetState(
			probe,
			spec.Dataset,
		)

		if state != jailDatasetOwnedMatch {
			return fmt.Errorf(
				"directory prerequisite jail root is not OWNED_MATCH: %s (%s)",
				spec.Dataset.Target,
				state,
			)
		}
	}

	return nil
}

func requireDirectoryHost(
	config Config,
	probe hostProbe,
) error {
	if probe.EUID() != 0 {
		return fmt.Errorf(
			"directory operation requires root",
		)
	}

	kernel, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect operating system before directory apply: %w",
			err,
		)
	}

	if strings.TrimSpace(kernel) != "FreeBSD" {
		return fmt.Errorf(
			"directory operation requires FreeBSD",
		)
	}

	hostname, err := probe.Run(
		"hostname",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect hostname before directory apply: %w",
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

// -----------------------------------------------------------------------------
// Specifications
// -----------------------------------------------------------------------------

func directorySpecs(
	config Config,
) ([]hostDirectorySpec, []jailDirectorySpec, error) {
	uid, err := parsePositiveDecimal(
		"FI_RUNTIME_UID",
		config.Value("FI_RUNTIME_UID"),
	)
	if err != nil {
		return nil, nil, err
	}

	gid, err := parsePositiveDecimal(
		"FI_RUNTIME_GID",
		config.Value("FI_RUNTIME_GID"),
	)
	if err != nil {
		return nil, nil, err
	}

	hierarchy := fiHierarchySpecs(config)
	byTarget := make(
		map[string]fiDatasetSpec,
		len(hierarchy),
	)

	for _, spec := range hierarchy {
		byTarget[spec.Target] = spec
	}

	root := config.Value("FI_ZPOOL") + "/fi"

	hostDefinitions := []struct {
		configKey string
		dataset   string
		gid       uint64
		mode      os.FileMode
		name      string
		uid       uint64
	}{
		{
			configKey: "FI_CUSTODY_GENERATION_HOST",
			dataset:   root + "/custody/generation",
			gid:       gid,
			mode:      0o700,
			name:      "custody generation directory",
			uid:       uid,
		},
		{
			configKey: "FI_CUSTODY_TRANSPORT_HOST",
			dataset:   root + "/custody/transport",
			gid:       gid,
			mode:      0o700,
			name:      "transport custody directory",
			uid:       uid,
		},
		{
			configKey: "FI_RECORDED_HOST",
			dataset:   root + "/recorded",
			gid:       gid,
			mode:      0o700,
			name:      "recorded directory",
			uid:       uid,
		},
		{
			configKey: "FI_READY_HOST",
			dataset:   root + "/ready",
			gid:       gid,
			mode:      0o700,
			name:      "READY directory",
			uid:       uid,
		},
		{
			configKey: "FI_RECEIVER_CONFIG_HOST",
			dataset:   root + "/config/receiver",
			gid:       gid,
			mode:      0o750,
			name:      "receiver configuration directory",
			uid:       0,
		},
		{
			configKey: "FI_INGEST_CONFIG_HOST",
			dataset:   root + "/config/ingest",
			gid:       gid,
			mode:      0o750,
			name:      "ingest configuration directory",
			uid:       0,
		},
	}

	hostSpecs := make(
		[]hostDirectorySpec,
		0,
		len(hostDefinitions),
	)

	for _, definition := range hostDefinitions {
		dataset, ok := byTarget[definition.dataset]
		if !ok {
			return nil, nil, fmt.Errorf(
				"missing FI hierarchy specification: %s",
				definition.dataset,
			)
		}

		hostSpecs = append(
			hostSpecs,
			hostDirectorySpec{
				Dataset: dataset,
				GID:     definition.gid,
				Mode:    definition.mode,
				Name:    definition.name,
				Path:    config.Value(definition.configKey),
				UID:     definition.uid,
			},
		)
	}

	roots := jailRootSpecs(config)
	if len(roots) != 3 {
		return nil, nil, fmt.Errorf(
			"unexpected production jail-root specification count: %d",
			len(roots),
		)
	}

	receiverRoot := config.Value("FI_RECEIVER_ROOT")
	ingestRoot := config.Value("FI_INGEST_ROOT")
	sorRoot := config.Value("FI_SOR_DB_ROOT")

	jailSpecs := []jailDirectorySpec{
		{
			Dataset: roots[0],
			Name:    "receiver jail directories",
			Role:    "receiver",
			Root:    receiverRoot,
			Paths: []managedDirectorySpec{
				directorySpec(receiverRoot, "var/db/fi", 0, 0, 0o755),
				directorySpec(receiverRoot, "var/db/fi/custody", 0, 0, 0o755),
				directorySpec(receiverRoot, "var/db/fi/custody/generation", 0, 0, 0o755),
				directorySpec(receiverRoot, "var/db/fi/custody/transport", 0, 0, 0o755),
				directorySpec(receiverRoot, "var/db/fi/custody/recorded", 0, 0, 0o755),
				directorySpec(receiverRoot, "var/db/fi/custody/ready", 0, 0, 0o755),
				directorySpec(receiverRoot, "usr/local/etc/fi", 0, 0, 0o755),
				directorySpec(receiverRoot, "var/run/fi", uid, gid, 0o700),
			},
		},
		{
			Dataset: roots[1],
			Name:    "ingest jail directories",
			Role:    "ingest",
			Root:    ingestRoot,
			Paths: []managedDirectorySpec{
				directorySpec(ingestRoot, "var/db/fi", 0, 0, 0o755),
				directorySpec(ingestRoot, "var/db/fi/custody", 0, 0, 0o755),
				directorySpec(ingestRoot, "var/db/fi/custody/generation", 0, 0, 0o755),
				directorySpec(ingestRoot, "var/db/fi/custody/recorded", 0, 0, 0o755),
				directorySpec(ingestRoot, "var/db/fi/custody/ready", 0, 0, 0o755),
				directorySpec(ingestRoot, "usr/local/etc/fi", 0, 0, 0o755),
				directorySpec(ingestRoot, "var/run/fi", uid, gid, 0o700),
			},
		},
		{
			Dataset: roots[2],
			Name:    "System-of-Record jail directories",
			Role:    "sor",
			Root:    sorRoot,
			Paths: []managedDirectorySpec{
				directorySpec(sorRoot, "var/db/fi", 0, 0, 0o755),
				directorySpec(sorRoot, "var/db/fi/sor", 0, 0, 0o755),
				directorySpec(sorRoot, "var/db/fi/sor/postgres", 0, 0, 0o755),
			},
		},
	}

	return hostSpecs, jailSpecs, nil
}

func directorySpec(
	root string,
	relative string,
	uid uint64,
	gid uint64,
	mode os.FileMode,
) managedDirectorySpec {
	return managedDirectorySpec{
		GID:  gid,
		Mode: mode,
		Path: filepath.Join(
			root,
			relative,
		),
		UID: uid,
	}
}

// -----------------------------------------------------------------------------
// Mutation
// -----------------------------------------------------------------------------

type systemDirectoryMutator struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
}

func (mutator systemDirectoryMutator) CreateJailPaths(
	spec jailDirectorySpec,
) error {
	for _, directory := range spec.Paths {
		_, err := os.Lstat(directory.Path)

		switch {
		case err == nil:
			return fmt.Errorf(
				"directory already exists immediately before creation: %s",
				directory.Path,
			)

		case os.IsNotExist(err):

		default:
			return fmt.Errorf(
				"inspect directory immediately before creation %s: %w",
				directory.Path,
				err,
			)
		}

		if err := os.Mkdir(
			directory.Path,
			directory.Mode,
		); err != nil {
			return fmt.Errorf(
				"create directory %s: %w",
				directory.Path,
				err,
			)
		}

		if err := os.Chown(
			directory.Path,
			int(directory.UID),
			int(directory.GID),
		); err != nil {
			return fmt.Errorf(
				"chown directory %s: %w",
				directory.Path,
				err,
			)
		}

		if err := os.Chmod(
			directory.Path,
			directory.Mode,
		); err != nil {
			return fmt.Errorf(
				"chmod directory %s: %w",
				directory.Path,
				err,
			)
		}

		exact, err := directoryPathExact(directory)
		if err != nil {
			return fmt.Errorf(
				"verify directory %s: %w",
				directory.Path,
				err,
			)
		}

		if !exact {
			return fmt.Errorf(
				"new directory metadata did not verify: %s",
				directory.Path,
			)
		}
	}

	return mutator.SetMarker(
		spec.Dataset.Target,
	)
}

func (mutator systemDirectoryMutator) InitializeHost(
	spec hostDirectorySpec,
) error {
	info, err := os.Lstat(spec.Path)
	if err != nil {
		return fmt.Errorf(
			"inspect host source immediately before initialization %s: %w",
			spec.Path,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return fmt.Errorf(
			"host source is not an exact directory: %s",
			spec.Path,
		)
	}

	if err := os.Chown(
		spec.Path,
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"chown host source %s: %w",
			spec.Path,
			err,
		)
	}

	if err := os.Chmod(
		spec.Path,
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"chmod host source %s: %w",
			spec.Path,
			err,
		)
	}

	exact, err := directoryPathExact(
		managedDirectorySpec{
			GID:  spec.GID,
			Mode: spec.Mode,
			Path: spec.Path,
			UID:  spec.UID,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"verify host source %s: %w",
			spec.Path,
			err,
		)
	}

	if !exact {
		return fmt.Errorf(
			"host source metadata did not verify: %s",
			spec.Path,
		)
	}

	return mutator.SetMarker(
		spec.Dataset.Target,
	)
}

func (mutator systemDirectoryMutator) SetMarker(
	dataset string,
) error {
	commandPath, err := systemCommandPath("zfs")
	if err != nil {
		return err
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

	output, err := execute(
		commandPath,
		"set",
		directorySchemaProperty+"="+directorySchemaVersion,
		dataset,
	)
	if err == nil {
		return nil
	}

	message := strings.TrimSpace(
		string(output),
	)

	if message == "" {
		return err
	}

	return fmt.Errorf(
		"%w: %s",
		err,
		message,
	)
}
