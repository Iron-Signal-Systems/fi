// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type sorPostgreSQLUnmanagedFileSnapshot struct {
	Content []byte
	Device  uint64
	GID     uint64
	Inode   uint64
	Mode    os.FileMode
	Nlink   uint64
	Path    string
	UID     uint64
}

func publishSORPostgreSQLClusterPolicy(
	policy sorPostgreSQLClusterPolicy,
	uid uint64,
	gid uint64,
) error {
	if state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	); state != sorPostgreSQLClusterPolicyUnmanaged {
		return fmt.Errorf(
			"PostgreSQL policy publication requires exact UNMANAGED state: %s",
			state,
		)
	}

	parent := filepath.Dir(
		policy.MainConfigPath,
	)

	for _, target := range []string{
		policy.AuthorityPath,
		policy.RuntimePath,
		policy.HBAPath,
	} {
		if filepath.Dir(target) != parent {
			return fmt.Errorf(
				"PostgreSQL policy resources do not share one PGDATA directory",
			)
		}
	}

	hbaSnapshot, err :=
		captureSORPostgreSQLUnmanagedFileSnapshot(
			policy.HBAPath,
			uid,
			gid,
		)
	if err != nil {
		return fmt.Errorf(
			"capture unmanaged pg_hba.conf: %w",
			err,
		)
	}

	mainSnapshot, err :=
		captureSORPostgreSQLUnmanagedFileSnapshot(
			policy.MainConfigPath,
			uid,
			gid,
		)
	if err != nil {
		return fmt.Errorf(
			"capture unmanaged postgresql.conf: %w",
			err,
		)
	}

	mainContent :=
		buildSORPostgreSQLManagedMainConfig(
			mainSnapshot.Content,
			policy.IncludeBlock,
		)

	authorityTemp, err :=
		stageSORPostgreSQLPolicyFile(
			policy.AuthorityPath,
			policy.AuthorityContent,
			uid,
			gid,
		)
	if err != nil {
		return fmt.Errorf(
			"stage FI PostgreSQL cluster authority: %w",
			err,
		)
	}

	defer removeSORPostgreSQLPolicyTemp(
		authorityTemp,
	)

	runtimeTemp, err :=
		stageSORPostgreSQLPolicyFile(
			policy.RuntimePath,
			policy.RuntimeContent,
			uid,
			gid,
		)
	if err != nil {
		return fmt.Errorf(
			"stage FI PostgreSQL runtime policy: %w",
			err,
		)
	}

	defer removeSORPostgreSQLPolicyTemp(
		runtimeTemp,
	)

	hbaTemp, err :=
		stageSORPostgreSQLPolicyFile(
			policy.HBAPath,
			policy.HBAContent,
			uid,
			gid,
		)
	if err != nil {
		return fmt.Errorf(
			"stage FI PostgreSQL HBA policy: %w",
			err,
		)
	}

	defer removeSORPostgreSQLPolicyTemp(
		hbaTemp,
	)

	mainTemp, err :=
		stageSORPostgreSQLPolicyFile(
			policy.MainConfigPath,
			mainContent,
			uid,
			gid,
		)
	if err != nil {
		return fmt.Errorf(
			"stage FI PostgreSQL main configuration: %w",
			err,
		)
	}

	defer removeSORPostgreSQLPolicyTemp(
		mainTemp,
	)

	if state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	); state != sorPostgreSQLClusterPolicyUnmanaged {
		return fmt.Errorf(
			"PostgreSQL policy state changed before first publication: %s",
			state,
		)
	}

	if err := publishAbsentSORPostgreSQLPolicyFile(
		runtimeTemp,
		policy.RuntimePath,
		policy.RuntimeContent,
		uid,
		gid,
	); err != nil {
		return fmt.Errorf(
			"publish FI PostgreSQL runtime policy: %w",
			err,
		)
	}

	if err := replaceUnmanagedSORPostgreSQLPolicyFile(
		hbaTemp,
		hbaSnapshot,
		policy.HBAContent,
		uid,
		gid,
	); err != nil {
		return fmt.Errorf(
			"publish FI PostgreSQL HBA policy: %w",
			err,
		)
	}

	if err := replaceUnmanagedSORPostgreSQLPolicyFile(
		mainTemp,
		mainSnapshot,
		mainContent,
		uid,
		gid,
	); err != nil {
		return fmt.Errorf(
			"publish FI PostgreSQL main configuration: %w",
			err,
		)
	}

	if err := publishAbsentSORPostgreSQLPolicyFile(
		authorityTemp,
		policy.AuthorityPath,
		policy.AuthorityContent,
		uid,
		gid,
	); err != nil {
		return fmt.Errorf(
			"publish FI PostgreSQL cluster authority: %w",
			err,
		)
	}

	if state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	); state != sorPostgreSQLClusterPolicyOwnedMatch {
		return fmt.Errorf(
			"published FI PostgreSQL policy failed exact verification: %s",
			state,
		)
	}

	return nil
}

func buildSORPostgreSQLManagedMainConfig(
	current []byte,
	includeBlock []byte,
) []byte {
	managed := append(
		[]byte(nil),
		current...,
	)

	if len(managed) > 0 &&
		managed[len(managed)-1] != '\n' {
		managed = append(
			managed,
			'\n',
		)
	}

	managed = append(
		managed,
		includeBlock...,
	)

	return managed
}

func captureSORPostgreSQLUnmanagedFileSnapshot(
	target string,
	uid uint64,
	gid uint64,
) (sorPostgreSQLUnmanagedFileSnapshot, error) {
	info, err := os.Lstat(target)
	if err != nil {
		return sorPostgreSQLUnmanagedFileSnapshot{},
			err
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return sorPostgreSQLUnmanagedFileSnapshot{},
			fmt.Errorf(
				"unmanaged PostgreSQL file is not a regular non-symlink file",
			)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return sorPostgreSQLUnmanagedFileSnapshot{},
			fmt.Errorf(
				"unmanaged PostgreSQL file does not expose syscall.Stat_t",
			)
	}

	if uint64(stat.Uid) != uid ||
		uint64(stat.Gid) != gid ||
		info.Mode().Perm() != 0o600 ||
		uint64(stat.Nlink) != 1 {
		return sorPostgreSQLUnmanagedFileSnapshot{},
			fmt.Errorf(
				"unmanaged PostgreSQL file metadata is not exact",
			)
	}

	content, err := os.ReadFile(
		target,
	)
	if err != nil {
		return sorPostgreSQLUnmanagedFileSnapshot{},
			err
	}

	return sorPostgreSQLUnmanagedFileSnapshot{
		Content: content,
		Device:  uint64(stat.Dev),
		GID:     uint64(stat.Gid),
		Inode:   uint64(stat.Ino),
		Mode:    info.Mode().Perm(),
		Nlink:   uint64(stat.Nlink),
		Path:    target,
		UID:     uint64(stat.Uid),
	}, nil
}

func requireSORPostgreSQLUnmanagedFileSnapshot(
	snapshot sorPostgreSQLUnmanagedFileSnapshot,
) error {
	info, err := os.Lstat(
		snapshot.Path,
	)
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return fmt.Errorf(
			"unmanaged PostgreSQL file type changed",
		)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf(
			"unmanaged PostgreSQL file does not expose syscall.Stat_t",
		)
	}

	if uint64(stat.Dev) != snapshot.Device ||
		uint64(stat.Ino) != snapshot.Inode ||
		uint64(stat.Uid) != snapshot.UID ||
		uint64(stat.Gid) != snapshot.GID ||
		info.Mode().Perm() != snapshot.Mode ||
		uint64(stat.Nlink) != snapshot.Nlink {
		return fmt.Errorf(
			"unmanaged PostgreSQL file identity or metadata changed",
		)
	}

	content, err := os.ReadFile(
		snapshot.Path,
	)
	if err != nil {
		return err
	}

	if !bytes.Equal(
		content,
		snapshot.Content,
	) {
		return fmt.Errorf(
			"unmanaged PostgreSQL file content changed",
		)
	}

	return nil
}

func stageSORPostgreSQLPolicyFile(
	target string,
	content []byte,
	uid uint64,
	gid uint64,
) (string, error) {
	maxInt := uint64(
		^uint(0) >> 1,
	)

	if uid > maxInt ||
		gid > maxInt {
		return "", fmt.Errorf(
			"PostgreSQL policy UID/GID exceeds supported range",
		)
	}

	parent := filepath.Dir(
		target,
	)

	file, err := os.CreateTemp(
		parent,
		".fi-postgresql-stage-*",
	)
	if err != nil {
		return "", err
	}

	temp := file.Name()
	closed := false
	keep := false

	defer func() {
		if !closed {
			_ = file.Close()
		}

		if !keep {
			_ = os.Remove(temp)
		}
	}()

	if _, err := file.Write(
		content,
	); err != nil {
		return "", fmt.Errorf(
			"write temporary PostgreSQL policy: %w",
			err,
		)
	}

	if err := file.Chown(
		int(uid),
		int(gid),
	); err != nil {
		return "", fmt.Errorf(
			"set temporary PostgreSQL policy ownership: %w",
			err,
		)
	}

	if err := file.Chmod(
		0o600,
	); err != nil {
		return "", fmt.Errorf(
			"set temporary PostgreSQL policy mode: %w",
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return "", fmt.Errorf(
			"sync temporary PostgreSQL policy: %w",
			err,
		)
	}

	if err := file.Close(); err != nil {
		return "", fmt.Errorf(
			"close temporary PostgreSQL policy: %w",
			err,
		)
	}

	closed = true

	if err := verifySORPostgreSQLExactPolicyFile(
		temp,
		content,
		uid,
		gid,
	); err != nil {
		return "", fmt.Errorf(
			"temporary PostgreSQL policy failed verification: %w",
			err,
		)
	}

	keep = true

	return temp, nil
}

func publishAbsentSORPostgreSQLPolicyFile(
	temp string,
	target string,
	content []byte,
	uid uint64,
	gid uint64,
) error {
	_, err := os.Lstat(
		target,
	)

	switch {
	case err == nil:
		return fmt.Errorf(
			"destination appeared before publication",
		)

	case os.IsNotExist(err):

	default:
		return fmt.Errorf(
			"inspect absent PostgreSQL policy destination: %w",
			err,
		)
	}

	if err := os.Link(
		temp,
		target,
	); err != nil {
		return fmt.Errorf(
			"publish PostgreSQL policy without overwrite: %w",
			err,
		)
	}

	if err := os.Remove(
		temp,
	); err != nil {
		return fmt.Errorf(
			"remove temporary PostgreSQL publication link: %w",
			err,
		)
	}

	if err := verifySORPostgreSQLExactPolicyFile(
		target,
		content,
		uid,
		gid,
	); err != nil {
		return fmt.Errorf(
			"published PostgreSQL policy failed verification: %w",
			err,
		)
	}

	return nil
}

func replaceUnmanagedSORPostgreSQLPolicyFile(
	temp string,
	snapshot sorPostgreSQLUnmanagedFileSnapshot,
	content []byte,
	uid uint64,
	gid uint64,
) error {
	if err :=
		requireSORPostgreSQLUnmanagedFileSnapshot(
			snapshot,
		); err != nil {
		return fmt.Errorf(
			"unmanaged PostgreSQL file changed before replacement: %w",
			err,
		)
	}

	if err := os.Rename(
		temp,
		snapshot.Path,
	); err != nil {
		return fmt.Errorf(
			"atomically replace unmanaged PostgreSQL file: %w",
			err,
		)
	}

	if err := verifySORPostgreSQLExactPolicyFile(
		snapshot.Path,
		content,
		uid,
		gid,
	); err != nil {
		return fmt.Errorf(
			"replaced PostgreSQL policy failed verification: %w",
			err,
		)
	}

	return nil
}

func verifySORPostgreSQLExactPolicyFile(
	target string,
	content []byte,
	uid uint64,
	gid uint64,
) error {
	info, err := os.Lstat(
		target,
	)
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return fmt.Errorf(
			"PostgreSQL policy is not a regular non-symlink file",
		)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf(
			"PostgreSQL policy does not expose syscall.Stat_t",
		)
	}

	if uint64(stat.Uid) != uid ||
		uint64(stat.Gid) != gid ||
		info.Mode().Perm() != 0o600 ||
		uint64(stat.Nlink) != 1 {
		return fmt.Errorf(
			"PostgreSQL policy metadata is not exact",
		)
	}

	actual, err := os.ReadFile(
		target,
	)
	if err != nil {
		return err
	}

	if !bytes.Equal(
		actual,
		content,
	) {
		return fmt.Errorf(
			"PostgreSQL policy content is not exact",
		)
	}

	return nil
}

func removeSORPostgreSQLPolicyTemp(
	target string,
) {
	err := os.Remove(
		target,
	)

	if err == nil ||
		os.IsNotExist(err) {
		return
	}
}
