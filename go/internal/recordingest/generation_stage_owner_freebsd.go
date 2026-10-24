// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package recordingest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const generationStagePrefix = "fi-relational-ingest-generation-"

// newGenerationStageLease marks a newly-created private staging directory and
// keeps an advisory exclusive lock for the entire generation load/ingest lifetime.
// The caller must remove the directory BEFORE closing the returned file.
func newGenerationStageLease(directory string) (*os.File, error) {
	path := filepath.Join(directory, generationStageLeaseName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("create FI stage ownership marker: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(fmt.Errorf("lock FI stage ownership marker: %w", err), file.Close())
	}
	return file, nil
}

// ReclaimAbandonedGenerationStages removes only old, FI-marked directories
// owned by this service account, and only when their exclusive lease can be
// acquired. It ignores unmarked legacy directories and every active ingester.
// A minimum age defends the narrow window between mkdir and lease creation.
// It must never be invoked with a minimum age below one hour.
func ReclaimAbandonedGenerationStages(root string, minimumAge time.Duration) (int, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || minimumAge < time.Hour {
		return 0, errors.New("FI stage cleanup requires a clean absolute root and at least one-hour grace")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return 0, fmt.Errorf("inspect FI stage root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("FI stage cleanup root must be a real directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, fmt.Errorf("enumerate FI stage root: %w", err)
	}

	now := time.Now()
	removed := 0
	var failures error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), generationStagePrefix) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		ok, err := reclaimOneGenerationStage(path, now, minimumAge)
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		if ok {
			removed++
		}
	}
	return removed, failures
}

func reclaimOneGenerationStage(directory string, now time.Time, minimumAge time.Duration) (bool, error) {
	info, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || !ownedByStageUser(info) ||
		now.Sub(info.ModTime()) < minimumAge {
		return false, nil
	}
	path := filepath.Join(directory, generationStageLeaseName)
	markerInfo, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	} // Legacy/unmarked stage: never delete.
	if err != nil {
		return false, err
	}
	if !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm() != 0600 || !ownedByStageUser(markerInfo) {
		return false, nil
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open FI stage marker %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return false, err
	}
	if !os.SameFile(markerInfo, openedInfo) {
		return false, nil
	}

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return false, nil
		}
		return false, fmt.Errorf("test FI stage lease %q: %w", path, err)
	}
	// Recheck after claiming the lease. Never delete a directory that has
	// been replaced or modified, even if it has an old-looking name.
	current, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !os.SameFile(info, current) || !current.IsDir() || current.Mode().Perm() != 0700 ||
		!ownedByStageUser(current) || now.Sub(current.ModTime()) < minimumAge {
		return false, nil
	}
	currentMarker, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !os.SameFile(openedInfo, currentMarker) {
		return false, nil
	}

	if err := removeGenerationStageDirectory(directory); err != nil {
		return false, fmt.Errorf("remove abandoned FI stage %q: %w", directory, err)
	}
	return true, nil
}

func ownedByStageUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
