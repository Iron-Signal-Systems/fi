// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import "golang.org/x/sys/unix"

// VerifyReleaseHistory checks exact keeper-owned, private durable history
// storage before administrative release is enabled. It never creates paths.
func (store *KeeperStore) VerifyReleaseHistory(root string) error {
	if store == nil {
		return unix.EINVAL
	}
	fd, err := store.openReleaseHistory(root)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}
