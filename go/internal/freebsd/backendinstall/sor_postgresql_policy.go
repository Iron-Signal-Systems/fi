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

// -----------------------------------------------------------------------------
// PostgreSQL policy contract
// -----------------------------------------------------------------------------

const (
	sorPostgreSQLPolicyMarker = "# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-v1"
	sorPostgreSQLPolicyRole   = "# FI-ROLE: postgresql-rc-policy"

	sorPostgreSQLPolicyContent = "" +
		"# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-v1\n" +
		"# FI-ROLE: postgresql-rc-policy\n" +
		"\n" +
		"postgresql_enable=\"YES\"\n" +
		"postgresql_user=\"postgres\"\n" +
		"postgresql_data=\"/var/db/fi/sor/postgres\"\n" +
		"postgresql_initdb_flags=\"--encoding=UTF8 --locale=C --data-checksums\"\n"
)

type sorPostgreSQLPolicyState string

const (
	sorPostgreSQLPolicyAbsent           sorPostgreSQLPolicyState = "ABSENT"
	sorPostgreSQLPolicyForeignCollision sorPostgreSQLPolicyState = "FOREIGN_COLLISION"
	sorPostgreSQLPolicyOwnedDrift       sorPostgreSQLPolicyState = "OWNED_DRIFT"
	sorPostgreSQLPolicyOwnedMatch       sorPostgreSQLPolicyState = "OWNED_MATCH"
	sorPostgreSQLPolicyUnknown          sorPostgreSQLPolicyState = "UNKNOWN"
)

type sorPostgreSQLPolicySpec struct {
	Content []byte
	GID     uint64
	Mode    os.FileMode
	Target  string
	UID     uint64
}

// -----------------------------------------------------------------------------
// Public operations
// -----------------------------------------------------------------------------

func ApplySORPostgreSQL(config Config) error {
	probe := systemHostProbe{}

	if err := requireSORPostgreSQLPolicyHost(
		config,
		probe,
	); err != nil {
		return err
	}

	if err := requireSORDatabaseStopped(
		probe,
	); err != nil {
		return err
	}

	if err := requireSORPostgreSQLPolicyPrerequisites(
		config,
		probe,
	); err != nil {
		return err
	}

	spec := sorPostgreSQLPolicySpecForConfig(config)

	state := classifySORPostgreSQLPolicy(spec)

	switch state {
	case sorPostgreSQLPolicyOwnedMatch:
		return nil

	case sorPostgreSQLPolicyAbsent:

	case sorPostgreSQLPolicyOwnedDrift:
		return fmt.Errorf(
			"OWNED_DRIFT: PostgreSQL rc policy is FI-owned but has drifted",
		)

	case sorPostgreSQLPolicyForeignCollision:
		return fmt.Errorf(
			"FOREIGN_COLLISION: PostgreSQL rc policy collides with non-FI state",
		)

	case sorPostgreSQLPolicyUnknown:
		return fmt.Errorf(
			"UNKNOWN: PostgreSQL rc policy could not be classified safely",
		)

	default:
		return fmt.Errorf(
			"invalid PostgreSQL policy state: %s",
			state,
		)
	}

	mutator := systemSORPostgreSQLPolicyMutator{}

	if err := mutator.PublishAbsent(spec); err != nil {
		return fmt.Errorf(
			"publish PostgreSQL rc policy: %w",
			err,
		)
	}

	state = classifySORPostgreSQLPolicy(spec)

	if state != sorPostgreSQLPolicyOwnedMatch {
		return fmt.Errorf(
			"created PostgreSQL rc policy failed verification: %s",
			state,
		)
	}

	return nil
}

func VerifySORPostgreSQL(config Config) error {
	probe := systemHostProbe{}

	if err := requireSORPostgreSQLPolicyHost(
		config,
		probe,
	); err != nil {
		return err
	}

	if err := requireSORPostgreSQLPolicyPrerequisites(
		config,
		probe,
	); err != nil {
		return err
	}

	spec := sorPostgreSQLPolicySpecForConfig(config)
	state := classifySORPostgreSQLPolicy(spec)

	if state != sorPostgreSQLPolicyOwnedMatch {
		return fmt.Errorf(
			"PostgreSQL rc policy is not OWNED_MATCH: %s",
			state,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

func classifySORPostgreSQLPolicy(
	spec sorPostgreSQLPolicySpec,
) sorPostgreSQLPolicyState {
	info, err := os.Lstat(spec.Target)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return sorPostgreSQLPolicyAbsent

	default:
		return sorPostgreSQLPolicyUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return sorPostgreSQLPolicyForeignCollision
	}

	content, err := os.ReadFile(spec.Target)
	if err != nil {
		return sorPostgreSQLPolicyUnknown
	}

	if !containsExactLine(
		content,
		sorPostgreSQLPolicyMarker,
	) {
		return sorPostgreSQLPolicyForeignCollision
	}

	if !containsExactLine(
		content,
		sorPostgreSQLPolicyRole,
	) {
		return sorPostgreSQLPolicyOwnedDrift
	}

	if !bytes.Equal(
		content,
		spec.Content,
	) {
		return sorPostgreSQLPolicyOwnedDrift
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return sorPostgreSQLPolicyUnknown
	}

	if uint64(stat.Uid) != spec.UID ||
		uint64(stat.Gid) != spec.GID ||
		info.Mode().Perm() != spec.Mode.Perm() ||
		uint64(stat.Nlink) != 1 {
		return sorPostgreSQLPolicyOwnedDrift
	}

	return sorPostgreSQLPolicyOwnedMatch
}

func containsExactLine(
	content []byte,
	expected string,
) bool {
	for _, line := range strings.Split(
		string(content),
		"\n",
	) {
		if line == expected {
			return true
		}
	}

	return false
}

// -----------------------------------------------------------------------------
// Prerequisites
// -----------------------------------------------------------------------------

func requireSORPostgreSQLPolicyHost(
	config Config,
	probe hostProbe,
) error {
	if probe.EUID() != 0 {
		return fmt.Errorf(
			"PostgreSQL policy operation requires root",
		)
	}

	kernel, err := probe.Run(
		"uname",
		"-s",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect operating system before PostgreSQL policy operation: %w",
			err,
		)
	}

	if strings.TrimSpace(kernel) != "FreeBSD" {
		return fmt.Errorf(
			"PostgreSQL policy operation requires FreeBSD",
		)
	}

	hostname, err := probe.Run(
		"hostname",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect hostname before PostgreSQL policy operation: %w",
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

func requireSORPostgreSQLPolicyPrerequisites(
	config Config,
	probe hostProbe,
) error {
	jailSpec, err := sorDatabaseJailSpec(config)
	if err != nil {
		return err
	}

	state := inspectJailDatasetState(
		probe,
		jailSpec,
	)

	if state != jailDatasetOwnedMatch {
		return fmt.Errorf(
			"PostgreSQL policy requires matching SOR jail root: %s (%s)",
			jailSpec.Target,
			state,
		)
	}

	root := config.Value("FI_SOR_DB_ROOT")

	if err := requireExactDirectoryPath(
		root,
		"System-of-Record jail root",
	); err != nil {
		return err
	}

	spec := sorPostgreSQLPolicySpecForConfig(config)

	if err := requireExactDirectoryPath(
		filepath.Dir(spec.Target),
		"PostgreSQL rc.conf.d parent",
	); err != nil {
		return err
	}

	service := filepath.Join(
		root,
		"usr/local/etc/rc.d/postgresql",
	)

	if err := requireRegularFile(
		service,
		false,
		"PostgreSQL rc.d service",
	); err != nil {
		return err
	}

	pgctl := filepath.Join(
		root,
		"usr/local/bin/pg_ctl",
	)

	if err := requireRegularFile(
		pgctl,
		true,
		"PostgreSQL pg_ctl",
	); err != nil {
		return err
	}

	identity, err := inspectSORPostgreSQLIdentity(root)
	if err != nil {
		return fmt.Errorf(
			"inspect PostgreSQL service identity: %w",
			err,
		)
	}

	pgdata := config.Value("FI_SOR_POSTGRES_HOST")

	exact, err := directoryPathExact(
		managedDirectorySpec{
			GID:  identity.GID,
			Mode: 0o700,
			Path: pgdata,
			UID:  identity.UID,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"inspect authoritative PostgreSQL data path: %w",
			err,
		)
	}

	if !exact {
		return fmt.Errorf(
			"authoritative PostgreSQL data path metadata mismatch: expected %d:%d:700",
			identity.UID,
			identity.GID,
		)
	}

	return nil
}

func requireExactDirectoryPath(
	target string,
	description string,
) error {
	info, err := os.Lstat(target)
	if err != nil {
		return fmt.Errorf(
			"%s unavailable: %s: %w",
			description,
			target,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return fmt.Errorf(
			"%s is not an exact directory: %s",
			description,
			target,
		)
	}

	return nil
}

func requireRegularFile(
	target string,
	executable bool,
	description string,
) error {
	info, err := os.Lstat(target)
	if err != nil {
		return fmt.Errorf(
			"%s unavailable: %s: %w",
			description,
			target,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return fmt.Errorf(
			"%s is not a regular file: %s",
			description,
			target,
		)
	}

	if executable &&
		info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf(
			"%s is not executable: %s",
			description,
			target,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Specification
// -----------------------------------------------------------------------------

func sorPostgreSQLPolicySpecForConfig(
	config Config,
) sorPostgreSQLPolicySpec {
	return sorPostgreSQLPolicySpec{
		Content: []byte(
			sorPostgreSQLPolicyContent,
		),
		GID:  0,
		Mode: 0o644,
		Target: filepath.Join(
			config.Value("FI_SOR_DB_ROOT"),
			"etc/rc.conf.d/postgresql",
		),
		UID: 0,
	}
}

// -----------------------------------------------------------------------------
// Mutation
// -----------------------------------------------------------------------------

type systemSORPostgreSQLPolicyMutator struct{}

func (systemSORPostgreSQLPolicyMutator) PublishAbsent(
	spec sorPostgreSQLPolicySpec,
) error {
	state := classifySORPostgreSQLPolicy(spec)

	if state != sorPostgreSQLPolicyAbsent {
		return fmt.Errorf(
			"PostgreSQL policy changed before creation: %s",
			state,
		)
	}

	parent := filepath.Dir(spec.Target)

	file, err := os.CreateTemp(
		parent,
		".postgresql.fi.*",
	)
	if err != nil {
		return fmt.Errorf(
			"create PostgreSQL policy temporary file: %w",
			err,
		)
	}

	temp := file.Name()
	published := false

	defer func() {
		if !published {
			file.Close()
			os.Remove(temp)
		}
	}()

	if _, err := file.Write(spec.Content); err != nil {
		return fmt.Errorf(
			"populate PostgreSQL policy temporary file: %w",
			err,
		)
	}

	if spec.UID > uint64(^uint32(0)) ||
		spec.GID > uint64(^uint32(0)) {
		return fmt.Errorf(
			"PostgreSQL policy UID/GID exceeds supported range",
		)
	}

	if err := file.Chown(
		int(spec.UID),
		int(spec.GID),
	); err != nil {
		return fmt.Errorf(
			"set PostgreSQL policy ownership: %w",
			err,
		)
	}

	if err := file.Chmod(
		spec.Mode,
	); err != nil {
		return fmt.Errorf(
			"set PostgreSQL policy mode: %w",
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync PostgreSQL policy temporary file: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close PostgreSQL policy temporary file: %w",
			err,
		)
	}

	tempSpec := spec
	tempSpec.Target = temp

	if state := classifySORPostgreSQLPolicy(
		tempSpec,
	); state != sorPostgreSQLPolicyOwnedMatch {
		return fmt.Errorf(
			"PostgreSQL policy temporary file failed verification: %s",
			state,
		)
	}

	if state := classifySORPostgreSQLPolicy(
		spec,
	); state != sorPostgreSQLPolicyAbsent {
		return fmt.Errorf(
			"PostgreSQL policy changed before publication: %s",
			state,
		)
	}

	if err := os.Link(
		temp,
		spec.Target,
	); err != nil {
		return fmt.Errorf(
			"publish PostgreSQL policy without overwrite: %w",
			err,
		)
	}

	published = true

	if err := os.Remove(temp); err != nil {
		return fmt.Errorf(
			"remove PostgreSQL policy temporary link: %w",
			err,
		)
	}

	if state := classifySORPostgreSQLPolicy(
		spec,
	); state != sorPostgreSQLPolicyOwnedMatch {
		return fmt.Errorf(
			"published PostgreSQL policy failed verification: %s",
			state,
		)
	}

	return nil
}
