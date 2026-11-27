// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package workerlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// AcquireProtectedAsKeeper acquires the exact inode used by the worker's
// AcquireProtected. The worker is never permitted to authorize this call.
// A trusted keeper may acquire the lock only under its own primary UID/GID.
func AcquireProtectedAsKeeper(policy ProtectedLockPolicy, keeperGID uint32) (*Lock, error) {
	return acquireProtectedAsKeeperAt(ProtectedLockDirectory, policy, keeperGID)
}

// acquireProtectedAsKeeperAt allows isolated FreeBSD filesystem tests without
// creating or changing production lock paths.
func acquireProtectedAsKeeperAt(directory string, policy ProtectedLockPolicy, keeperGID uint32) (*Lock, error) {
	if policy.KeeperUID == 0 || keeperGID == 0 || policy.WorkerUID == 0 ||
		policy.WorkerGID == 0 || policy.WorkerUID == policy.KeeperUID ||
		uint32(os.Geteuid()) != policy.KeeperUID ||
		uint32(os.Getegid()) != keeperGID {
		return nil, errors.New("keeper protected lock requires independently pinned keeper and worker identities")
	}
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("invalid protected keeper lock directory")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve keeper lock directory: %w", err)
	}
	if resolved != directory {
		return nil, errors.New("keeper lock path traverses symlinks")
	}

	parentFD, err := unix.Open(filepath.Dir(directory),
		unix.O_SEARCH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil {
		return nil, err
	}
	if !isProtectedParent(parent, policy.KeeperUID) {
		return nil, errors.New("protected keeper lock parent ownership or mode mismatch")
	}

	dirFD, err := unix.Openat(parentFD, filepath.Base(directory),
		unix.O_SEARCH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	var actualDir unix.Stat_t
	if err := unix.Fstat(dirFD, &actualDir); err != nil {
		return nil, err
	}
	if !isProtectedDirectory(actualDir, policy) {
		return nil, errors.New("protected keeper lock directory ownership or mode mismatch")
	}
	lockPath := filepath.Join(directory, ProtectedLockName)
	fd, err := unix.Openat(dirFD, ProtectedLockName,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open protected keeper lock inode: %w", err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create keeper lock handle")
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, err
	}
	if !isProtectedLockFile(opened, policy) {
		return nil, errors.New("protected keeper lock inode ownership, mode, or links invalid")
	}
	verify := func() error {
		if err := unix.Fstatat(dirFD, ProtectedLockName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if opened.Dev != named.Dev || opened.Ino != named.Ino || !isProtectedLockFile(named, policy) {
			return errors.New("protected keeper lock pathname identity changed")
		}
		return nil
	}
	if err := verify(); err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyHeld, lockPath)
		}
		return nil, fmt.Errorf("acquire protected keeper release lock: %w", err)
	}
	if err := verify(); err != nil {
		return nil, err
	}
	closeOnError = false
	return &Lock{file: file, path: lockPath}, nil
}
