// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	KeeperSocketDirectory = "/var/run/fi-keeper"
	KeeperSocketName      = "worker.sock"
)

type SocketAuthority struct {
	Directory string
	KeeperUID uint32
	WorkerUID uint32
	WorkerGID uint32
}

// VerifySocketAuthority verifies an existing directory and either:
//
// bound=false: requires the socket pathname to be absent.
// bound=true: requires the exact keeper-owned socket.
//
// This function does not create, remove, chmod, or chown anything.
// The directory's parent must itself be protected against replacement.
func VerifySocketAuthority(
	policy SocketAuthority,
	bound bool,
) error {
	if policy.KeeperUID == 0 ||
		policy.WorkerUID == 0 ||
		policy.KeeperUID == policy.WorkerUID {
		return errors.New(
			"keeper and worker require distinct non-root identities",
		)
	}

	directory := policy.Directory
	socketPath := filepath.Join(directory, KeeperSocketName)

	if directory == "" ||
		!filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory ||
		len(socketPath) >= 104 {
		return errors.New("invalid keeper socket directory")
	}

	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return fmt.Errorf(
			"resolve keeper socket directory: %w", err,
		)
	}

	if resolved != directory {
		return errors.New(
			"keeper socket path traverses a symbolic link",
		)
	}

	parent := filepath.Dir(directory)

	parentFD, err := unix.Open(
		parent,
		unix.O_RDONLY|unix.O_DIRECTORY|
			unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf(
			"open keeper socket parent: %w", err,
		)
	}
	defer unix.Close(parentFD)

	var parentStat unix.Stat_t

	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return err
	}

	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		parentStat.Mode&0022 != 0 ||
		(parentStat.Uid != 0 &&
			parentStat.Uid != policy.KeeperUID) {
		return errors.New(
			"keeper socket parent is not protected",
		)
	}

	fd, err := unix.Openat(
		parentFD,
		filepath.Base(directory),
		unix.O_SEARCH|unix.O_DIRECTORY|
			unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf(
			"open keeper-owned socket directory: %w", err,
		)
	}
	defer unix.Close(fd)

	var root unix.Stat_t

	if err := unix.Fstat(fd, &root); err != nil {
		return err
	}

	if root.Mode&unix.S_IFMT != unix.S_IFDIR ||
		root.Mode&07777 != 0710 ||
		root.Uid != policy.KeeperUID ||
		root.Gid != policy.WorkerGID {
		return errors.New(
			"keeper socket directory ownership or mode mismatch",
		)
	}

	var endpoint unix.Stat_t

	err = unix.Fstatat(
		fd,
		KeeperSocketName,
		&endpoint,
		unix.AT_SYMLINK_NOFOLLOW,
	)

	if !bound {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return fmt.Errorf(
				"inspect keeper socket pathname: %w", err,
			)
		}
		return errors.New(
			"keeper socket pathname already occupied",
		)
	}

	if err != nil {
		return fmt.Errorf(
			"keeper socket endpoint unavailable: %w", err,
		)
	}

	if endpoint.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		endpoint.Mode&07777 != 0660 ||
		endpoint.Uid != policy.KeeperUID ||
		endpoint.Gid != policy.WorkerGID {
		return errors.New(
			"keeper socket endpoint ownership, type, or mode mismatch",
		)
	}

	return nil
}
