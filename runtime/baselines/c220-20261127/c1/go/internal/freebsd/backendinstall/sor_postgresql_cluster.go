// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type sorPostgreSQLClusterState string

const (
	sorPostgreSQLClusterAbsent      sorPostgreSQLClusterState = "ABSENT"
	sorPostgreSQLClusterEmpty       sorPostgreSQLClusterState = "EMPTY"
	sorPostgreSQLClusterInitialized sorPostgreSQLClusterState = "INITIALIZED"
	sorPostgreSQLClusterPartial     sorPostgreSQLClusterState = "PARTIAL"
	sorPostgreSQLClusterUnknown     sorPostgreSQLClusterState = "UNKNOWN"
)

type sorPostgreSQLClusterSpec struct {
	GID          uint64
	MajorVersion string
	PGData       string
	UID          uint64
}

func classifySORPostgreSQLCluster(
	spec sorPostgreSQLClusterSpec,
) sorPostgreSQLClusterState {
	info, err := os.Lstat(spec.PGData)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return sorPostgreSQLClusterAbsent

	default:
		return sorPostgreSQLClusterUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return sorPostgreSQLClusterPartial
	}

	if !sorPostgreSQLClusterMetadataMatches(
		info,
		spec.UID,
		spec.GID,
		true,
	) {
		return sorPostgreSQLClusterPartial
	}

	entries, err := os.ReadDir(spec.PGData)
	if err != nil {
		return sorPostgreSQLClusterUnknown
	}

	if len(entries) == 0 {
		return sorPostgreSQLClusterEmpty
	}

	if _, err := os.Lstat(
		filepath.Join(
			spec.PGData,
			"postmaster.pid",
		),
	); err == nil {
		return sorPostgreSQLClusterPartial
	} else if !os.IsNotExist(err) {
		return sorPostgreSQLClusterUnknown
	}

	requiredDirectories := []string{
		"base",
		"global",
		"pg_wal",
	}

	for _, relative := range requiredDirectories {
		state := inspectSORPostgreSQLClusterResource(
			filepath.Join(
				spec.PGData,
				relative,
			),
			spec.UID,
			spec.GID,
			true,
		)

		if state != sorPostgreSQLClusterInitialized {
			return state
		}
	}

	requiredFiles := []string{
		"PG_VERSION",
		"postgresql.conf",
		"pg_hba.conf",
		"pg_ident.conf",
		filepath.Join(
			"global",
			"pg_control",
		),
	}

	for _, relative := range requiredFiles {
		state := inspectSORPostgreSQLClusterResource(
			filepath.Join(
				spec.PGData,
				relative,
			),
			spec.UID,
			spec.GID,
			false,
		)

		if state != sorPostgreSQLClusterInitialized {
			return state
		}
	}

	version, err := os.ReadFile(
		filepath.Join(
			spec.PGData,
			"PG_VERSION",
		),
	)
	if err != nil {
		return sorPostgreSQLClusterUnknown
	}

	if strings.TrimSpace(
		string(version),
	) != spec.MajorVersion {
		return sorPostgreSQLClusterPartial
	}

	return sorPostgreSQLClusterInitialized
}

func inspectSORPostgreSQLClusterResource(
	target string,
	uid uint64,
	gid uint64,
	directory bool,
) sorPostgreSQLClusterState {
	info, err := os.Lstat(target)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return sorPostgreSQLClusterPartial

	default:
		return sorPostgreSQLClusterUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return sorPostgreSQLClusterPartial
	}

	if directory {
		if !info.IsDir() {
			return sorPostgreSQLClusterPartial
		}
	} else {
		if !info.Mode().IsRegular() {
			return sorPostgreSQLClusterPartial
		}
	}

	if !sorPostgreSQLClusterMetadataMatches(
		info,
		uid,
		gid,
		directory,
	) {
		return sorPostgreSQLClusterPartial
	}

	return sorPostgreSQLClusterInitialized
}

func sorPostgreSQLClusterMetadataMatches(
	info os.FileInfo,
	uid uint64,
	gid uint64,
	directory bool,
) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	if uint64(stat.Uid) != uid ||
		uint64(stat.Gid) != gid {
		return false
	}

	if info.Mode().Perm()&0o077 != 0 {
		return false
	}

	if !directory &&
		uint64(stat.Nlink) != 1 {
		return false
	}

	return true
}
