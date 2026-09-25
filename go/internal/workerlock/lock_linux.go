// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package workerlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrAlreadyHeld = errors.New("FI ingest worker singleton lock is already held")

type Lock struct {
	file *os.File
	path string
}

func Acquire(path string) (*Lock, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("FI ingest worker singleton lock path is required")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("FI ingest worker singleton lock path must be absolute")
	}

	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)

	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, fmt.Errorf("resolve FI ingest worker singleton lock parent: %w", err)
	}
	if filepath.Clean(resolvedParent) != parent {
		return nil, errors.New("FI ingest worker singleton lock parent must not traverse symlinks")
	}

	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect FI ingest worker singleton lock parent: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return nil, errors.New("FI ingest worker singleton lock parent must be a real directory")
	}
	if parentInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf(
			"FI ingest worker singleton lock parent must not be group- or other-writable: mode=%04o",
			parentInfo.Mode().Perm(),
		)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("FI ingest worker singleton lock parent ownership is unavailable")
	}
	if int(parentStat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf(
			"FI ingest worker singleton lock parent uid=%d does not match process euid=%d",
			parentStat.Uid,
			os.Geteuid(),
		)
	}

	fd, err := unix.Open(
		clean,
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("open FI ingest worker singleton lock %q: %w", clean, err)
	}

	file := os.NewFile(uintptr(fd), clean)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create FI ingest worker singleton lock file handle")
	}

	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened FI ingest worker singleton lock %q: %w", clean, err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf(
			"FI ingest worker singleton lock %q must be a 0600 regular file",
			clean,
		)
	}
	openedStat, ok := openedInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("FI ingest worker singleton lock ownership is unavailable")
	}
	if int(openedStat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf(
			"FI ingest worker singleton lock uid=%d does not match process euid=%d",
			openedStat.Uid,
			os.Geteuid(),
		)
	}

	pathInfo, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("reinspect FI ingest worker singleton lock %q: %w", clean, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return nil, errors.New("FI ingest worker singleton lock changed while being opened")
	}

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyHeld, clean)
		}
		return nil, fmt.Errorf("acquire FI ingest worker singleton lock %q: %w", clean, err)
	}

	closeOnError = false
	return &Lock{file: file, path: clean}, nil
}

func (lock *Lock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}

	file := lock.file
	lock.file = nil

	unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	closeErr := file.Close()
	if err := errors.Join(unlockErr, closeErr); err != nil {
		return fmt.Errorf("release FI ingest worker singleton lock %q: %w", lock.path, err)
	}
	return nil
}

func (lock *Lock) Path() string {
	if lock == nil {
		return ""
	}
	return lock.path
}
