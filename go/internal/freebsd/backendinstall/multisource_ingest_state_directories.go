// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const m1InstalledIngestStateRoot = "/var/db/fi/ingest"

var m1IngestStateChildren = [...]string{
	"quarantine",
	"history",
}

func m1InstalledIngestStateIdentity(
	config Config,
) (uint64, uint64, error) {
	uid, err := parsePositiveDecimal(
		"FI_RUNTIME_UID",
		config.Value("FI_RUNTIME_UID"),
	)
	if err != nil {
		return 0, 0, err
	}

	gid, err := parsePositiveDecimal(
		"FI_RUNTIME_GID",
		config.Value("FI_RUNTIME_GID"),
	)
	if err != nil {
		return 0, 0, err
	}

	return uid, gid, nil
}

func m1PrecheckInstalledIngestStateChildren(
	config Config,
) error {
	uid, gid, err := m1InstalledIngestStateIdentity(config)
	if err != nil {
		return err
	}

	return m1ProvisionIngestStateChildren(
		m1InstalledIngestStateRoot,
		uid,
		gid,
		false,
	)
}

func m1ApplyInstalledIngestStateChildren(
	config Config,
) error {
	uid, gid, err := m1InstalledIngestStateIdentity(config)
	if err != nil {
		return err
	}

	return m1ProvisionIngestStateChildren(
		m1InstalledIngestStateRoot,
		uid,
		gid,
		true,
	)
}

func m1ExactIngestDirectory(
	stat *unix.Stat_t,
	uid uint64,
	gid uint64,
) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		stat.Mode&0777 == 0700 &&
		uint64(stat.Uid) == uid &&
		uint64(stat.Gid) == gid
}

// m1ProvisionIngestStateChildren performs either a read-only
// precheck (apply=false) or installer provisioning (apply=true).
//
// All child inspection and mutation is relative to an open,
// no-follow directory descriptor for the persistent dataset root.
func m1ProvisionIngestStateChildren(
	root string,
	uid uint64,
	gid uint64,
	apply bool,
) error {
	if root == "" ||
		!filepath.IsAbs(root) ||
		filepath.Clean(root) != root {
		return errors.New(
			"FI ingest-state root must be a clean absolute path",
		)
	}

	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf(
			"resolve persistent FI ingest-state root: %w",
			err,
		)
	}

	if resolved != root {
		return errors.New(
			"FI ingest-state root traverses symlinks",
		)
	}

	before, err := os.Lstat(root)
	if err != nil {
		return err
	}

	if !before.IsDir() ||
		before.Mode()&os.ModeSymlink != 0 {
		return errors.New(
			"FI ingest-state root is not a real directory",
		)
	}

	fd, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|
			unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf(
			"open persistent FI ingest-state root: %w",
			err,
		)
	}
	defer unix.Close(fd)

	var rootStat unix.Stat_t

	if err := unix.Fstat(fd, &rootStat); err != nil {
		return err
	}

	originalStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok ||
		uint64(originalStat.Ino) != uint64(rootStat.Ino) ||
		uint64(originalStat.Dev) != uint64(rootStat.Dev) {
		return errors.New(
			"FI ingest-state root changed while opening",
		)
	}

	if apply && !m1ExactIngestDirectory(
		&rootStat, uid, gid,
	) {
		return errors.New(
			"FI ingest-state dataset root ownership or mode mismatch",
		)
	}

	missing := make([]bool, len(m1IngestStateChildren))

	// Complete preclassification: no child modifications until both
	// existing objects have been inspected.
	for index, name := range m1IngestStateChildren {
		var child unix.Stat_t

		err := unix.Fstatat(
			fd,
			name,
			&child,
			unix.AT_SYMLINK_NOFOLLOW,
		)

		if errors.Is(err, unix.ENOENT) {
			missing[index] = true
			continue
		}

		if err != nil {
			return fmt.Errorf(
				"inspect FI ingest-state child %q: %w",
				name, err,
			)
		}

		if !m1ExactIngestDirectory(
			&child, uid, gid,
		) {
			return fmt.Errorf(
				"FI ingest-state child %q is not worker-owned 0700 storage",
				name,
			)
		}
	}

	if !apply {
		return nil
	}

	created := false

	for index, name := range m1IngestStateChildren {
		if !missing[index] {
			continue
		}

		if err := unix.Mkdirat(
			fd, name, 0700,
		); err != nil {
			return fmt.Errorf(
				"create FI ingest-state child %q: %w",
				name, err,
			)
		}

		created = true

		childFD, err := unix.Openat(
			fd,
			name,
			unix.O_RDONLY|unix.O_DIRECTORY|
				unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return fmt.Errorf(
				"open newly created FI state child %q: %w",
				name, err,
			)
		}

		var child unix.Stat_t

		if err := unix.Fstat(childFD, &child); err != nil {
			_ = unix.Close(childFD)
			return err
		}

		if uint64(child.Uid) != uid ||
			uint64(child.Gid) != gid {
			if err := unix.Fchown(
				childFD,
				int(uid),
				int(gid),
			); err != nil {
				_ = unix.Close(childFD)
				return fmt.Errorf(
					"set FI ingest-state child ownership: %w",
					err,
				)
			}
		}

		if err := unix.Fchmod(childFD, 0700); err != nil {
			_ = unix.Close(childFD)
			return err
		}

		if err := unix.Fsync(childFD); err != nil {
			_ = unix.Close(childFD)
			return err
		}

		if err := unix.Close(childFD); err != nil {
			return err
		}
	}

	// Confirm exact postconditions for both children, whether
	// newly created or already present.
	for _, name := range m1IngestStateChildren {
		var child unix.Stat_t

		if err := unix.Fstatat(
			fd,
			name,
			&child,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil {
			return err
		}

		if !m1ExactIngestDirectory(
			&child, uid, gid,
		) {
			return fmt.Errorf(
				"FI ingest-state child %q failed final verification",
				name,
			)
		}
	}

	if created {
		if err := unix.Fsync(fd); err != nil {
			return fmt.Errorf(
				"synchronize persistent FI state directory: %w",
				err,
			)
		}
	}

	return nil
}
