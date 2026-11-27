// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

// ProtectedAdminReleaseHandler is supplied only to the independent,
// root-peer-authenticated admin listener. It never serves worker IPC.
// Both keeper and worker acquire the same immutable protected lock inode.
// The lock is held until durable audit and marker retirement complete.
func ProtectedAdminReleaseHandler(
	store *KeeperStore, historyRoot string,
	policy workerlock.ProtectedLockPolicy, keeperGID uint32,
) AdminReleaseHandler {
	return func(ctx context.Context, request KeeperReleaseRequest) (string, error) {
		if store == nil || ctx == nil {
			return "", errors.New("missing keeper release authority")
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := validateKeeperReleaseRequest(request); err != nil {
			return "", err
		}
		if store.keeperUID != policy.KeeperUID || store.keeperGID != keeperGID {
			return "", errors.New("keeper store and singleton authority identity mismatch")
		}
		lock, err := workerlock.AcquireProtectedAsKeeper(policy, keeperGID)
		if err != nil {
			return "", fmt.Errorf("release blocked by protected worker singleton: %w", err)
		}
		defer lock.Close()
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return store.releaseTransaction(ctx, historyRoot, request)
	}
}
