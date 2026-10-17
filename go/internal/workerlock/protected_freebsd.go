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

// ProtectedLockDirectory must be a separately owned directory with no
// worker write permission. It is also the keeper's IPC directory.
const (
	ProtectedLockDirectory = "/var/run/fi-keeper"
	ProtectedLockName      = "fi-ingest-worker.lock"
	ProtectedLockPath      = ProtectedLockDirectory + "/" + ProtectedLockName
)

// ProtectedLockPolicy pins the identities validated by the kernel. UID/GID
// values must come from the runtime accounts, never an untrusted request.
type ProtectedLockPolicy struct {
	KeeperUID uint32
	WorkerUID uint32
	WorkerGID uint32
}

// AcquireProtected opens an already-provisioned keeper-owned inode without
// creating, truncating, unlinking or modifying it. The worker requires only
// read/search permission; the exclusive flock protects cooperative workers.
// Do not use this as a security boundary without pinning every operational
// worker mode to this same lock and rejecting legacy lock overrides.
func AcquireProtected(policy ProtectedLockPolicy) (*Lock, error) {
	if err := validateProtectedIdentity(policy); err != nil {
		return nil, err
	}

	resolved, err := filepath.EvalSymlinks(ProtectedLockDirectory)
	if err != nil {
		return nil, fmt.Errorf("resolve FI keeper lock directory: %w", err)
	}
	if resolved != ProtectedLockDirectory {
		return nil, errors.New("FI keeper lock directory traverses a symbolic link")
	}

	// Pin the parent and the keeper-owned directory by descriptors so the
	// pathname lookup and authority validation inspect the same inodes.
	parentFD, err := unix.Open(
		filepath.Dir(ProtectedLockDirectory),
		unix.O_SEARCH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open FI keeper lock parent: %w", err)
	}
	defer unix.Close(parentFD)

	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil {
		return nil, err
	}
	if !isProtectedParent(parent, policy.KeeperUID) {
		return nil, errors.New("FI keeper lock parent is not protected")
	}

	directoryFD, err := unix.Openat(
		parentFD,
		filepath.Base(ProtectedLockDirectory),
		unix.O_SEARCH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open keeper-owned lock directory: %w", err)
	}
	defer unix.Close(directoryFD)

	var directory unix.Stat_t
	if err := unix.Fstat(directoryFD, &directory); err != nil {
		return nil, err
	}
	if !isProtectedDirectory(directory, policy) {
		return nil, errors.New("keeper lock directory ownership or mode mismatch")
	}

	fd, err := unix.Openat(
		directoryFD,
		ProtectedLockName,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open immutable FI keeper lock inode: %w", err)
	}

	file := os.NewFile(uintptr(fd), ProtectedLockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open FI keeper lock handle")
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()

	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, err
	}
	if !isProtectedLockFile(opened, policy) {
		return nil, errors.New("keeper lock inode ownership, link count or mode mismatch")
	}

	var named unix.Stat_t
	if err := unix.Fstatat(
		directoryFD, ProtectedLockName, &named, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nil, fmt.Errorf("verify keeper lock pathname: %w", err)
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino ||
		!isProtectedLockFile(named, policy) {
		return nil, errors.New("FI keeper lock pathname changed during acquisition")
	}

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyHeld, ProtectedLockPath)
		}
		return nil, fmt.Errorf("acquire protected FI singleton lock: %w", err)
	}

	// Validate the pinned pathname after lock acquisition too. Only the
	// keeper/root should be able to replace it, but unexpected replacement
	// must still fail closed instead of reporting successful authority.
	if err := unix.Fstatat(
		directoryFD, ProtectedLockName, &named, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nil, fmt.Errorf("recheck protected FI lock pathname: %w", err)
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino ||
		!isProtectedLockFile(named, policy) {
		return nil, errors.New("protected FI singleton pathname changed while locking")
	}

	closeOnError = false
	return &Lock{file: file, path: ProtectedLockPath}, nil
}

func isProtectedDirectory(stat unix.Stat_t, policy ProtectedLockPolicy) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		stat.Mode&07777 == 0710 &&
		stat.Uid == policy.KeeperUID &&
		stat.Gid == policy.WorkerGID
}

func isProtectedLockFile(stat unix.Stat_t, policy ProtectedLockPolicy) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Mode&07777 == 0640 &&
		stat.Uid == policy.KeeperUID &&
		stat.Gid == policy.WorkerGID &&
		stat.Nlink == 1 && stat.Size == 0
}

func isProtectedParent(stat unix.Stat_t, keeperUID uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		stat.Mode&0022 == 0 &&
		(stat.Uid == 0 || stat.Uid == keeperUID)
}

func validateProtectedIdentity(policy ProtectedLockPolicy) error {
	if policy.KeeperUID == 0 || policy.WorkerUID == 0 ||
		policy.WorkerGID == 0 || policy.KeeperUID == policy.WorkerUID ||
		uint32(os.Geteuid()) != policy.WorkerUID ||
		uint32(os.Getegid()) != policy.WorkerGID {
		return errors.New("protected FI lock requires distinct, pinned non-root keeper and worker identities")
	}
	return nil
}
