// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"os"
	"strings"
	"syscall"
)

type sorPostgreSQLClusterPolicyState string

const (
	sorPostgreSQLClusterPolicyUnmanaged        sorPostgreSQLClusterPolicyState = "UNMANAGED"
	sorPostgreSQLClusterPolicyOwnedMatch       sorPostgreSQLClusterPolicyState = "OWNED_MATCH"
	sorPostgreSQLClusterPolicyOwnedDrift       sorPostgreSQLClusterPolicyState = "OWNED_DRIFT"
	sorPostgreSQLClusterPolicyForeignCollision sorPostgreSQLClusterPolicyState = "FOREIGN_COLLISION"
	sorPostgreSQLClusterPolicyUnknown          sorPostgreSQLClusterPolicyState = "UNKNOWN"
)

type sorPostgreSQLClusterPolicyResourceState string

const (
	sorPostgreSQLClusterPolicyResourceAbsent           sorPostgreSQLClusterPolicyResourceState = "ABSENT"
	sorPostgreSQLClusterPolicyResourceUnmanaged        sorPostgreSQLClusterPolicyResourceState = "UNMANAGED"
	sorPostgreSQLClusterPolicyResourceOwnedMatch       sorPostgreSQLClusterPolicyResourceState = "OWNED_MATCH"
	sorPostgreSQLClusterPolicyResourceOwnedDrift       sorPostgreSQLClusterPolicyResourceState = "OWNED_DRIFT"
	sorPostgreSQLClusterPolicyResourceForeignCollision sorPostgreSQLClusterPolicyResourceState = "FOREIGN_COLLISION"
	sorPostgreSQLClusterPolicyResourceUnknown          sorPostgreSQLClusterPolicyResourceState = "UNKNOWN"
)

func classifySORPostgreSQLClusterPolicy(
	policy sorPostgreSQLClusterPolicy,
	uid uint64,
	gid uint64,
) sorPostgreSQLClusterPolicyState {
	authority := classifySORPostgreSQLClusterPolicyFile(
		policy.AuthorityPath,
		policy.AuthorityContent,
		sorPostgreSQLClusterAuthorityMarker,
		sorPostgreSQLClusterAuthorityRole,
		uid,
		gid,
		false,
	)

	runtime := classifySORPostgreSQLClusterPolicyFile(
		policy.RuntimePath,
		policy.RuntimeContent,
		sorPostgreSQLRuntimePolicyMarker,
		sorPostgreSQLRuntimePolicyRole,
		uid,
		gid,
		false,
	)

	hba := classifySORPostgreSQLClusterHBAFile(
		policy,
		uid,
		gid,
	)

	mainConfig := classifySORPostgreSQLMainConfig(
		policy,
		uid,
		gid,
	)

	states := []sorPostgreSQLClusterPolicyResourceState{
		authority,
		runtime,
		hba,
		mainConfig,
	}

	for _, state := range states {
		if state == sorPostgreSQLClusterPolicyResourceUnknown {
			return sorPostgreSQLClusterPolicyUnknown
		}
	}

	for _, state := range states {
		if state ==
			sorPostgreSQLClusterPolicyResourceForeignCollision {
			return sorPostgreSQLClusterPolicyForeignCollision
		}
	}

	if authority ==
		sorPostgreSQLClusterPolicyResourceAbsent &&
		runtime ==
			sorPostgreSQLClusterPolicyResourceAbsent &&
		hba ==
			sorPostgreSQLClusterPolicyResourceUnmanaged &&
		mainConfig ==
			sorPostgreSQLClusterPolicyResourceUnmanaged {
		return sorPostgreSQLClusterPolicyUnmanaged
	}

	if authority ==
		sorPostgreSQLClusterPolicyResourceOwnedMatch &&
		runtime ==
			sorPostgreSQLClusterPolicyResourceOwnedMatch &&
		hba ==
			sorPostgreSQLClusterPolicyResourceOwnedMatch &&
		mainConfig ==
			sorPostgreSQLClusterPolicyResourceOwnedMatch {
		return sorPostgreSQLClusterPolicyOwnedMatch
	}

	return sorPostgreSQLClusterPolicyOwnedDrift
}

func classifySORPostgreSQLClusterPolicyFile(
	target string,
	expected []byte,
	marker string,
	role string,
	uid uint64,
	gid uint64,
	allowUnmanaged bool,
) sorPostgreSQLClusterPolicyResourceState {
	info, err := os.Lstat(target)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return sorPostgreSQLClusterPolicyResourceAbsent

	default:
		return sorPostgreSQLClusterPolicyResourceUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return sorPostgreSQLClusterPolicyResourceForeignCollision
	}

	content, err := os.ReadFile(target)
	if err != nil {
		return sorPostgreSQLClusterPolicyResourceUnknown
	}

	hasMarker := containsExactLine(
		content,
		marker,
	)

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return sorPostgreSQLClusterPolicyResourceUnknown
	}

	metadataExact :=
		uint64(stat.Uid) == uid &&
			uint64(stat.Gid) == gid &&
			info.Mode().Perm() == 0o600 &&
			uint64(stat.Nlink) == 1

	if !hasMarker {
		if allowUnmanaged && metadataExact {
			return sorPostgreSQLClusterPolicyResourceUnmanaged
		}

		return sorPostgreSQLClusterPolicyResourceForeignCollision
	}

	if !metadataExact {
		return sorPostgreSQLClusterPolicyResourceOwnedDrift
	}

	if !containsExactLine(
		content,
		role,
	) {
		return sorPostgreSQLClusterPolicyResourceOwnedDrift
	}

	if !bytes.Equal(
		content,
		expected,
	) {
		return sorPostgreSQLClusterPolicyResourceOwnedDrift
	}

	return sorPostgreSQLClusterPolicyResourceOwnedMatch
}

func classifySORPostgreSQLClusterHBAFile(
	policy sorPostgreSQLClusterPolicy,
	uid uint64,
	gid uint64,
) sorPostgreSQLClusterPolicyResourceState {
	initialState :=
		classifySORPostgreSQLClusterPolicyFile(
			policy.HBAPath,
			policy.HBAContent,
			sorPostgreSQLHBAMarker,
			sorPostgreSQLHBARole,
			uid,
			gid,
			true,
		)

	if initialState ==
		sorPostgreSQLClusterPolicyResourceOwnedMatch {
		return initialState
	}

	databaseReadyState :=
		classifySORPostgreSQLClusterPolicyFile(
			policy.HBAPath,
			policy.HBADatabaseReadyContent,
			sorPostgreSQLHBAMarker,
			sorPostgreSQLHBARole,
			uid,
			gid,
			true,
		)

	if databaseReadyState ==
		sorPostgreSQLClusterPolicyResourceOwnedMatch {
		return databaseReadyState
	}

	if initialState ==
		sorPostgreSQLClusterPolicyResourceUnknown ||
		databaseReadyState ==
			sorPostgreSQLClusterPolicyResourceUnknown {
		return sorPostgreSQLClusterPolicyResourceUnknown
	}

	if initialState ==
		sorPostgreSQLClusterPolicyResourceForeignCollision ||
		databaseReadyState ==
			sorPostgreSQLClusterPolicyResourceForeignCollision {
		return sorPostgreSQLClusterPolicyResourceForeignCollision
	}

	if initialState ==
		sorPostgreSQLClusterPolicyResourceAbsent &&
		databaseReadyState ==
			sorPostgreSQLClusterPolicyResourceAbsent {
		return sorPostgreSQLClusterPolicyResourceAbsent
	}

	if initialState ==
		sorPostgreSQLClusterPolicyResourceUnmanaged &&
		databaseReadyState ==
			sorPostgreSQLClusterPolicyResourceUnmanaged {
		return sorPostgreSQLClusterPolicyResourceUnmanaged
	}

	return sorPostgreSQLClusterPolicyResourceOwnedDrift
}

func classifySORPostgreSQLMainConfig(
	policy sorPostgreSQLClusterPolicy,
	uid uint64,
	gid uint64,
) sorPostgreSQLClusterPolicyResourceState {
	info, err := os.Lstat(
		policy.MainConfigPath,
	)

	switch {
	case err == nil:

	case os.IsNotExist(err):
		return sorPostgreSQLClusterPolicyResourceAbsent

	default:
		return sorPostgreSQLClusterPolicyResourceUnknown
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return sorPostgreSQLClusterPolicyResourceForeignCollision
	}

	content, err := os.ReadFile(
		policy.MainConfigPath,
	)
	if err != nil {
		return sorPostgreSQLClusterPolicyResourceUnknown
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return sorPostgreSQLClusterPolicyResourceUnknown
	}

	metadataExact :=
		uint64(stat.Uid) == uid &&
			uint64(stat.Gid) == gid &&
			info.Mode().Perm() == 0o600 &&
			uint64(stat.Nlink) == 1

	hasBegin := containsExactLine(
		content,
		sorPostgreSQLIncludeBegin,
	)

	hasInclude := containsExactLine(
		content,
		sorPostgreSQLIncludeLine,
	)

	hasEnd := containsExactLine(
		content,
		sorPostgreSQLIncludeEnd,
	)

	referencesRuntime := strings.Contains(
		string(content),
		"fi-postgresql.conf",
	)

	if !hasBegin &&
		!hasInclude &&
		!hasEnd &&
		!referencesRuntime {
		if metadataExact {
			return sorPostgreSQLClusterPolicyResourceUnmanaged
		}

		return sorPostgreSQLClusterPolicyResourceForeignCollision
	}

	if !hasBegin &&
		!hasEnd &&
		referencesRuntime {
		return sorPostgreSQLClusterPolicyResourceForeignCollision
	}

	if !metadataExact {
		return sorPostgreSQLClusterPolicyResourceOwnedDrift
	}

	if bytes.Count(
		content,
		[]byte(sorPostgreSQLIncludeBegin),
	) != 1 ||
		bytes.Count(
			content,
			[]byte(sorPostgreSQLIncludeLine),
		) != 1 ||
		bytes.Count(
			content,
			[]byte(sorPostgreSQLIncludeEnd),
		) != 1 {
		return sorPostgreSQLClusterPolicyResourceOwnedDrift
	}

	if !bytes.Contains(
		content,
		policy.IncludeBlock,
	) {
		return sorPostgreSQLClusterPolicyResourceOwnedDrift
	}

	return sorPostgreSQLClusterPolicyResourceOwnedMatch
}
