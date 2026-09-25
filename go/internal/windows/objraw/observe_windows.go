// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package objraw

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnraw"
)

// backupObservationMu serializes the process-token SeBackupPrivilege window.
// AdjustTokenPrivileges changes the process token, so overlapping scopes could
// otherwise restore privilege state out of order.
var backupObservationMu sync.Mutex

// ObserveObject performs one exact governed NTFS File-ID observation while
// SeBackupPrivilege is enabled for the bounded collection interval.
//
// The existing NTFS collector remains authoritative for object identity,
// containment, metadata, security, streams, reparse state, content hashes,
// bounded prefix collection, and consistency checks. FIObjReader supplies local
// SACL authority through usnraw.ReadSACL while SeBackupPrivilege remains active.
func ObserveObject(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	objectIdentity records.NTFSObjectIdentity,
) (observation ntfs.Observation, err error) {
	if err := observationContextError(ctx); err != nil {
		return ntfs.Observation{}, err
	}

	backupObservationMu.Lock()
	defer backupObservationMu.Unlock()

	if err := observationContextError(ctx); err != nil {
		return ntfs.Observation{}, err
	}

	privilegeScope, err := enableBackupPrivilege()
	if err != nil {
		return ntfs.Observation{}, err
	}
	defer func() {
		restoreErr := restoreBackupPrivilege(privilegeScope)
		if restoreErr != nil {
			observation = ntfs.Observation{}
			err = errors.Join(err, restoreErr)
		}
	}()

	observation, err = ntfs.CollectFileReferenceWithSACLReader(
		ctx,
		scopeID,
		governedRoot,
		objectIdentity,
		readSACL,
	)
	if err != nil {
		return ntfs.Observation{}, err
	}

	observation.CollectionMethod = records.CollectionBackupAuthorityWindowsNTFS
	if err := ntfs.ValidateObservation(observation); err != nil {
		return ntfs.Observation{}, fmt.Errorf(
			"validate FIObjReader backup-authority observation: %w",
			err,
		)
	}

	return observation, nil
}

func observationContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func readSACL(
	ctx context.Context,
	governedRoot string,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
) ([]byte, error) {
	if err := observationContextError(ctx); err != nil {
		return nil, err
	}

	data, err := usnraw.ReadSACL(
		governedRoot,
		fileReferenceNumber,
		sequenceNumber,
	)
	if err != nil {
		return nil, err
	}

	if err := observationContextError(ctx); err != nil {
		return nil, err
	}
	return data, nil
}
