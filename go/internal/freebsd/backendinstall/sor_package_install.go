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
)

// -----------------------------------------------------------------------------
// SOR PostgreSQL package contract
// -----------------------------------------------------------------------------

const (
	sorPostgreSQLClientOrigin  = "databases/postgresql18-client"
	sorPostgreSQLClientPackage = "postgresql18-client"
	sorPostgreSQLMajor         = "18"
	sorPostgreSQLServerOrigin  = "databases/postgresql18-server"
	sorPostgreSQLServerPackage = "postgresql18-server"
)

type sorPostgreSQLIdentity struct {
	GID uint64
	UID uint64
}

type sorPostgreSQLVersionProbe func(string) (string, error)

// -----------------------------------------------------------------------------
// Public operation
// -----------------------------------------------------------------------------

func ApplySORPackage(config Config) error {
	probe := systemHostProbe{}

	if _, _, err := requireJailInstallHost(
		config,
		probe,
	); err != nil {
		return fmt.Errorf(
			"SOR package host prerequisite failed: %w",
			err,
		)
	}

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
			"SOR package apply requires matching production jail root: %s (%s)",
			jailSpec.Target,
			state,
		)
	}

	if err := requireSORDatabaseStopped(probe); err != nil {
		return err
	}

	root := config.Value("FI_SOR_DB_ROOT")
	pgdata := config.Value("FI_SOR_POSTGRES_HOST")

	installed, _, err := inspectSORPostgreSQL(
		root,
		pgdata,
		systemSORPostgreSQLVersion,
	)
	if err != nil {
		return err
	}

	if installed {
		return nil
	}

	if err := requireInitialSORPackageState(
		root,
		pgdata,
	); err != nil {
		return err
	}

	mutator := systemSORPackageMutator{}

	if err := applySORPostgreSQLPackage(
		root,
		pgdata,
		mutator,
	); err != nil {
		return err
	}

	installed, _, err = inspectSORPostgreSQL(
		root,
		pgdata,
		systemSORPostgreSQLVersion,
	)
	if err != nil {
		return err
	}

	if !installed {
		return fmt.Errorf(
			"new SOR PostgreSQL package state did not verify as installed",
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Apply orchestration
// -----------------------------------------------------------------------------

func applySORPostgreSQLPackage(
	root string,
	pgdata string,
	mutator systemSORPackageMutator,
) (resultErr error) {
	resolverCreated := false
	devfsMounted := false

	defer func() {
		cleanupErr := cleanupSORPackageProvisioning(
			root,
			mutator,
			resolverCreated,
			devfsMounted,
		)

		if cleanupErr == nil {
			return
		}

		if resultErr == nil {
			resultErr = cleanupErr
			return
		}

		resultErr = fmt.Errorf(
			"%w; cleanup failed: %v",
			resultErr,
			cleanupErr,
		)
	}()

	if err := mutator.CreateResolver(root); err != nil {
		return fmt.Errorf(
			"create temporary SOR resolver: %w",
			err,
		)
	}

	resolverCreated = true

	if err := mutator.MountDevfs(root); err != nil {
		return fmt.Errorf(
			"mount temporary SOR devfs: %w",
			err,
		)
	}

	devfsMounted = true

	if err := requireSORNullDevice(root); err != nil {
		return err
	}

	if err := mutator.BootstrapPkg(root); err != nil {
		return fmt.Errorf(
			"bootstrap pkg inside SOR root: %w",
			err,
		)
	}

	if err := mutator.UpdateCatalog(root); err != nil {
		return fmt.Errorf(
			"update SOR package catalogue: %w",
			err,
		)
	}

	if err := mutator.InstallPostgreSQL(root); err != nil {
		return fmt.Errorf(
			"install PostgreSQL 18 inside SOR root: %w",
			err,
		)
	}

	packageOutput, err := mutator.QueryPackages(root)
	if err != nil {
		return fmt.Errorf(
			"query installed SOR packages: %w",
			err,
		)
	}

	if err := validateSORPostgreSQLPackages(
		packageOutput,
	); err != nil {
		return err
	}

	identity, err := inspectSORPostgreSQLIdentity(root)
	if err != nil {
		return err
	}

	if err := requireInitialPGDATA(pgdata); err != nil {
		return fmt.Errorf(
			"PGDATA changed during package provisioning: %w",
			err,
		)
	}

	if err := mutator.EstablishPGDATA(
		pgdata,
		identity,
	); err != nil {
		return fmt.Errorf(
			"establish PostgreSQL PGDATA authority: %w",
			err,
		)
	}

	installed, _, err := inspectSORPostgreSQL(
		root,
		pgdata,
		systemSORPostgreSQLVersion,
	)
	if err != nil {
		return err
	}

	if !installed {
		return fmt.Errorf(
			"PostgreSQL installation did not verify",
		)
	}

	return nil
}

func cleanupSORPackageProvisioning(
	root string,
	mutator systemSORPackageMutator,
	resolverCreated bool,
	devfsMounted bool,
) error {
	failures := make(
		[]string,
		0,
		2,
	)

	if resolverCreated {
		if err := mutator.RemoveResolver(root); err != nil {
			failures = append(
				failures,
				"remove temporary resolver: "+err.Error(),
			)
		}
	}

	if devfsMounted {
		if err := mutator.UnmountDevfs(root); err != nil {
			failures = append(
				failures,
				"unmount temporary devfs: "+err.Error(),
			)
		}
	}

	if len(failures) != 0 {
		return fmt.Errorf(
			"%s",
			strings.Join(
				failures,
				"; ",
			),
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// State inspection
// -----------------------------------------------------------------------------

func inspectSORPostgreSQL(
	root string,
	pgdata string,
	versionProbe sorPostgreSQLVersionProbe,
) (bool, sorPostgreSQLIdentity, error) {
	filesPresent, filesComplete, err := inspectSORPostgreSQLFiles(root)
	if err != nil {
		return false, sorPostgreSQLIdentity{}, err
	}

	users, err := readPasswdRecords(
		filepath.Join(
			root,
			"etc/master.passwd",
		),
	)
	if err != nil {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"inspect SOR user database: %w",
			err,
		)
	}

	groups, err := readGroupRecords(
		filepath.Join(
			root,
			"etc/group",
		),
	)
	if err != nil {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"inspect SOR group database: %w",
			err,
		)
	}

	postgresUsers := matchingUsers(
		users,
		func(record passwdRecord) bool {
			return record.Name == "postgres"
		},
	)

	postgresGroups := matchingGroups(
		groups,
		func(record groupRecord) bool {
			return record.Name == "postgres"
		},
	)

	if len(postgresUsers) == 0 &&
		len(postgresGroups) == 0 {
		if filesPresent {
			return false, sorPostgreSQLIdentity{}, fmt.Errorf(
				"OWNED_DRIFT: PostgreSQL files exist without package-created postgres identity",
			)
		}

		return false, sorPostgreSQLIdentity{}, nil
	}

	if len(postgresUsers) != 1 ||
		len(postgresGroups) != 1 {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"FOREIGN_COLLISION: postgres identity is not uniquely defined",
		)
	}

	user := postgresUsers[0]
	group := postgresGroups[0]

	if user.UID == 0 ||
		user.GID == 0 ||
		user.GID != group.GID ||
		user.Home != "/var/db/postgres" ||
		user.Shell != "/bin/sh" ||
		!strings.HasPrefix(
			user.Password,
			"*",
		) {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"FOREIGN_COLLISION: postgres identity differs from FreeBSD package contract",
		)
	}

	usersByUID := matchingUsers(
		users,
		func(record passwdRecord) bool {
			return record.UID == user.UID
		},
	)

	groupsByGID := matchingGroups(
		groups,
		func(record groupRecord) bool {
			return record.GID == group.GID
		},
	)

	if len(usersByUID) != 1 ||
		len(groupsByGID) != 1 {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"FOREIGN_COLLISION: postgres UID or GID collides with another identity",
		)
	}

	if !filesComplete {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"OWNED_DRIFT: PostgreSQL package files are incomplete",
		)
	}

	version, err := versionProbe(root)
	if err != nil {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"inspect PostgreSQL version: %w",
			err,
		)
	}

	if !acceptedPostgreSQL18Version(version) {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"OWNED_DRIFT: unsupported PostgreSQL version: %s",
			version,
		)
	}

	exact, err := directoryPathExact(
		managedDirectorySpec{
			GID:  group.GID,
			Mode: 0o700,
			Path: pgdata,
			UID:  user.UID,
		},
	)
	if err != nil {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"inspect PostgreSQL PGDATA: %w",
			err,
		)
	}

	if !exact {
		return false, sorPostgreSQLIdentity{}, fmt.Errorf(
			"OWNED_DRIFT: PostgreSQL PGDATA metadata differs from package identity",
		)
	}

	return true, sorPostgreSQLIdentity{
		GID: group.GID,
		UID: user.UID,
	}, nil
}

func inspectSORPostgreSQLFiles(
	root string,
) (bool, bool, error) {
	definitions := []struct {
		executable bool
		relative   string
	}{
		{
			executable: true,
			relative:   "usr/local/bin/pg_ctl",
		},
		{
			executable: true,
			relative:   "usr/local/bin/postgres",
		},
		{
			executable: true,
			relative:   "usr/local/bin/psql",
		},
		{
			executable: true,
			relative:   "usr/local/etc/rc.d/postgresql",
		},
	}

	present := 0

	for _, definition := range definitions {
		target := filepath.Join(
			root,
			definition.relative,
		)

		info, err := os.Lstat(target)

		switch {
		case err == nil:
		case os.IsNotExist(err):
			continue
		default:
			return false, false, fmt.Errorf(
				"inspect PostgreSQL package file %s: %w",
				target,
				err,
			)
		}

		present++

		if info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() {
			return true, false, fmt.Errorf(
				"FOREIGN_COLLISION: PostgreSQL package path is not a regular file: %s",
				target,
			)
		}

		if definition.executable &&
			info.Mode().Perm()&0o111 == 0 {
			return true, false, fmt.Errorf(
				"OWNED_DRIFT: PostgreSQL package file is not executable: %s",
				target,
			)
		}
	}

	return present != 0, present == len(definitions), nil
}

func inspectSORPostgreSQLIdentity(
	root string,
) (sorPostgreSQLIdentity, error) {
	users, err := readPasswdRecords(
		filepath.Join(
			root,
			"etc/master.passwd",
		),
	)
	if err != nil {
		return sorPostgreSQLIdentity{}, fmt.Errorf(
			"inspect SOR postgres user: %w",
			err,
		)
	}

	groups, err := readGroupRecords(
		filepath.Join(
			root,
			"etc/group",
		),
	)
	if err != nil {
		return sorPostgreSQLIdentity{}, fmt.Errorf(
			"inspect SOR postgres group: %w",
			err,
		)
	}

	postgresUsers := matchingUsers(
		users,
		func(record passwdRecord) bool {
			return record.Name == "postgres"
		},
	)

	postgresGroups := matchingGroups(
		groups,
		func(record groupRecord) bool {
			return record.Name == "postgres"
		},
	)

	if len(postgresUsers) != 1 ||
		len(postgresGroups) != 1 {
		return sorPostgreSQLIdentity{}, fmt.Errorf(
			"package-created postgres identity is not uniquely defined",
		)
	}

	user := postgresUsers[0]
	group := postgresGroups[0]

	if user.UID == 0 ||
		user.GID == 0 ||
		user.GID != group.GID ||
		user.Home != "/var/db/postgres" ||
		user.Shell != "/bin/sh" ||
		!strings.HasPrefix(
			user.Password,
			"*",
		) {
		return sorPostgreSQLIdentity{}, fmt.Errorf(
			"package-created postgres identity differs from accepted contract",
		)
	}

	return sorPostgreSQLIdentity{
		GID: group.GID,
		UID: user.UID,
	}, nil
}

// -----------------------------------------------------------------------------
// Prerequisites
// -----------------------------------------------------------------------------

func requireInitialSORPackageState(
	root string,
	pgdata string,
) error {
	resolver := filepath.Join(
		root,
		"etc/resolv.conf",
	)

	_, err := os.Lstat(resolver)

	switch {
	case err == nil:
		return fmt.Errorf(
			"FOREIGN_COLLISION: SOR resolver already exists before package provisioning: %s",
			resolver,
		)

	case os.IsNotExist(err):

	default:
		return fmt.Errorf(
			"inspect SOR resolver: %w",
			err,
		)
	}

	nullDevice := filepath.Join(
		root,
		"dev/null",
	)

	_, err = os.Lstat(nullDevice)

	switch {
	case err == nil:
		return fmt.Errorf(
			"FOREIGN_COLLISION: SOR /dev is already populated before package provisioning",
		)

	case os.IsNotExist(err):

	default:
		return fmt.Errorf(
			"inspect SOR /dev: %w",
			err,
		)
	}

	dev := filepath.Join(
		root,
		"dev",
	)

	exact, err := directoryPathExact(
		managedDirectorySpec{
			GID:  0,
			Mode: 0o755,
			Path: dev,
			UID:  0,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"inspect SOR /dev directory: %w",
			err,
		)
	}

	if !exact {
		return fmt.Errorf(
			"FOREIGN_COLLISION: SOR /dev directory differs from root:wheel 0755",
		)
	}

	return requireInitialPGDATA(pgdata)
}

func requireInitialPGDATA(
	pgdata string,
) error {
	exact, err := directoryPathExact(
		managedDirectorySpec{
			GID:  0,
			Mode: 0o755,
			Path: pgdata,
			UID:  0,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"inspect initial PGDATA metadata: %w",
			err,
		)
	}

	if !exact {
		return fmt.Errorf(
			"initial PGDATA must be exact root:wheel 0755",
		)
	}

	entries, err := os.ReadDir(pgdata)
	if err != nil {
		return fmt.Errorf(
			"inspect initial PGDATA contents: %w",
			err,
		)
	}

	if len(entries) != 0 {
		return fmt.Errorf(
			"initial PGDATA must be empty before package provisioning",
		)
	}

	return nil
}

func requireSORDatabaseStopped(
	probe hostProbe,
) error {
	output, err := probe.Run(
		"jls",
		"-n",
		"name",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect active jails before SOR package apply: %w",
			err,
		)
	}

	for _, line := range strings.Split(
		output,
		"\n",
	) {
		if strings.TrimSpace(line) == "name=fi-sor-db" {
			return fmt.Errorf(
				"SOR package apply requires fi-sor-db to be stopped",
			)
		}
	}

	return nil
}

func requireSORNullDevice(
	root string,
) error {
	target := filepath.Join(
		root,
		"dev/null",
	)

	info, err := os.Lstat(target)
	if err != nil {
		return fmt.Errorf(
			"inspect temporary SOR /dev/null: %w",
			err,
		)
	}

	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf(
			"temporary SOR /dev/null is not a character device",
		)
	}

	return nil
}

func sorDatabaseJailSpec(
	config Config,
) (jailDatasetSpec, error) {
	for _, spec := range jailRootSpecs(config) {
		if spec.Role == "jail-root-sor-db" {
			return spec, nil
		}
	}

	return jailDatasetSpec{}, fmt.Errorf(
		"SOR database jail specification is unavailable",
	)
}

// -----------------------------------------------------------------------------
// PostgreSQL package verification
// -----------------------------------------------------------------------------

func acceptedPostgreSQL18Version(
	version string,
) bool {
	version = strings.TrimSpace(version)

	return version == sorPostgreSQLMajor ||
		strings.HasPrefix(
			version,
			sorPostgreSQLMajor+".",
		)
}

func validateSORPostgreSQLPackages(
	output string,
) error {
	expected := map[string]string{
		sorPostgreSQLClientPackage: sorPostgreSQLClientOrigin,
		sorPostgreSQLServerPackage: sorPostgreSQLServerOrigin,
	}

	observedVersions := make(
		map[string]string,
	)

	for _, line := range strings.Split(
		strings.TrimSpace(output),
		"\n",
	) {
		if line == "" {
			continue
		}

		fields := strings.Split(
			line,
			"|",
		)

		if len(fields) != 3 {
			return fmt.Errorf(
				"malformed pkg query output: %q",
				line,
			)
		}

		expectedOrigin, wanted := expected[fields[0]]
		if !wanted {
			continue
		}

		if fields[2] != expectedOrigin {
			return fmt.Errorf(
				"unexpected PostgreSQL package origin for %s: %s",
				fields[0],
				fields[2],
			)
		}

		if !acceptedPostgreSQL18Version(fields[1]) {
			return fmt.Errorf(
				"unexpected PostgreSQL package version for %s: %s",
				fields[0],
				fields[1],
			)
		}

		if _, exists := observedVersions[fields[0]]; exists {
			return fmt.Errorf(
				"duplicate PostgreSQL package record: %s",
				fields[0],
			)
		}

		observedVersions[fields[0]] = fields[1]
	}

	clientVersion, clientFound := observedVersions[sorPostgreSQLClientPackage]

	serverVersion, serverFound := observedVersions[sorPostgreSQLServerPackage]

	if !clientFound ||
		!serverFound {
		return fmt.Errorf(
			"required PostgreSQL 18 client/server packages are not both installed",
		)
	}

	if clientVersion != serverVersion {
		return fmt.Errorf(
			"PostgreSQL client/server version mismatch: client=%s server=%s",
			clientVersion,
			serverVersion,
		)
	}

	return nil
}

func systemSORPostgreSQLVersion(
	root string,
) (string, error) {
	output, err := exec.Command(
		"/usr/sbin/chroot",
		root,
		"/usr/local/bin/postgres",
		"--version",
	).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(
			string(output),
		)

		if message == "" {
			return "", err
		}

		return "", fmt.Errorf(
			"%w: %s",
			err,
			message,
		)
	}

	fields := strings.Fields(
		strings.TrimSpace(
			string(output),
		),
	)

	if len(fields) == 0 {
		return "", fmt.Errorf(
			"empty PostgreSQL version output",
		)
	}

	return fields[len(fields)-1], nil
}

// -----------------------------------------------------------------------------
// System mutation
// -----------------------------------------------------------------------------

type systemSORPackageMutator struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
}

func (mutator systemSORPackageMutator) BootstrapPkg(
	root string,
) error {
	target := filepath.Join(
		root,
		"usr/local/sbin/pkg",
	)

	info, err := os.Lstat(target)

	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() ||
			info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf(
				"existing pkg executable is not an exact regular executable: %s",
				target,
			)
		}

		return nil

	case os.IsNotExist(err):

	default:
		return fmt.Errorf(
			"inspect pkg executable: %w",
			err,
		)
	}

	return mutator.run(
		"/usr/sbin/chroot",
		root,
		"/usr/bin/env",
		"ASSUME_ALWAYS_YES=yes",
		"/usr/sbin/pkg",
		"bootstrap",
		"-y",
	)
}

func (mutator systemSORPackageMutator) CreateResolver(
	root string,
) error {
	source := "/etc/resolv.conf"
	target := filepath.Join(
		root,
		"etc/resolv.conf",
	)

	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf(
			"inspect host resolver: %w",
			err,
		)
	}

	if sourceInfo.Mode()&os.ModeSymlink != 0 ||
		!sourceInfo.Mode().IsRegular() {
		return fmt.Errorf(
			"host resolver is not a regular file",
		)
	}

	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf(
			"read host resolver: %w",
			err,
		)
	}

	file, err := os.OpenFile(
		target,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o644,
	)
	if err != nil {
		return err
	}

	keep := false

	defer func() {
		file.Close()

		if !keep {
			os.Remove(target)
		}
	}()

	if _, err := file.Write(content); err != nil {
		return err
	}

	if err := file.Chown(
		0,
		0,
	); err != nil {
		return err
	}

	if err := file.Chmod(
		0o644,
	); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	keep = true

	return nil
}

func (mutator systemSORPackageMutator) EstablishPGDATA(
	pgdata string,
	identity sorPostgreSQLIdentity,
) error {
	if identity.UID > uint64(^uint32(0)) ||
		identity.GID > uint64(^uint32(0)) {
		return fmt.Errorf(
			"postgres UID/GID exceeds supported range",
		)
	}

	if err := os.Chown(
		pgdata,
		int(identity.UID),
		int(identity.GID),
	); err != nil {
		return err
	}

	if err := os.Chmod(
		pgdata,
		0o700,
	); err != nil {
		return err
	}

	return nil
}

func (mutator systemSORPackageMutator) InstallPostgreSQL(
	root string,
) error {
	return mutator.run(
		"/usr/sbin/chroot",
		root,
		"/usr/local/sbin/pkg",
		"install",
		"-y",
		sorPostgreSQLServerPackage,
	)
}

func (mutator systemSORPackageMutator) MountDevfs(
	root string,
) error {
	return mutator.run(
		"/sbin/mount",
		"-t",
		"devfs",
		"devfs",
		filepath.Join(
			root,
			"dev",
		),
	)
}

func (mutator systemSORPackageMutator) QueryPackages(
	root string,
) (string, error) {
	output, err := mutator.runOutput(
		"/usr/sbin/chroot",
		root,
		"/usr/local/sbin/pkg",
		"query",
		"-a",
		"%n|%v|%o",
	)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (mutator systemSORPackageMutator) RemoveResolver(
	root string,
) error {
	return os.Remove(
		filepath.Join(
			root,
			"etc/resolv.conf",
		),
	)
}

func (mutator systemSORPackageMutator) UnmountDevfs(
	root string,
) error {
	return mutator.run(
		"/sbin/umount",
		filepath.Join(
			root,
			"dev",
		),
	)
}

func (mutator systemSORPackageMutator) UpdateCatalog(
	root string,
) error {
	return mutator.run(
		"/usr/sbin/chroot",
		root,
		"/usr/local/sbin/pkg",
		"update",
		"-f",
	)
}

func (mutator systemSORPackageMutator) run(
	executable string,
	args ...string,
) error {
	_, err := mutator.runOutput(
		executable,
		args...,
	)

	return err
}

func (mutator systemSORPackageMutator) runOutput(
	executable string,
	args ...string,
) ([]byte, error) {
	execute := mutator.execute

	if execute == nil {
		execute = func(
			path string,
			arguments ...string,
		) ([]byte, error) {
			return exec.Command(
				path,
				arguments...,
			).CombinedOutput()
		}
	}

	output, err := execute(
		executable,
		args...,
	)
	if err == nil {
		return output, nil
	}

	message := strings.TrimSpace(
		string(output),
	)

	if message == "" {
		return nil, err
	}

	return nil, fmt.Errorf(
		"%w: %s",
		err,
		message,
	)
}
