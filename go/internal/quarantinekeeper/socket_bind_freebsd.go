// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// BindWorkerSocket binds a worker-facing Unix stream socket inside
// a preprovisioned, independently owned directory.
//
// It never creates or repairs the directory, replaces an existing
// pathname, or removes a stale endpoint.
//
// Automatic unlink-on-close is disabled. Safe endpoint retirement
// is a separate lifecycle operation, not part of binding.
func BindWorkerSocket(
	policy SocketAuthority,
) (*net.UnixListener, error) {
	if uint32(os.Geteuid()) != policy.KeeperUID {
		return nil, errors.New(
			"keeper binding requires the configured keeper identity",
		)
	}

	if err := VerifySocketAuthority(
		policy, false,
	); err != nil {
		return nil, fmt.Errorf(
			"keeper socket preflight: %w",
			err,
		)
	}

	path := filepath.Join(
		policy.Directory,
		KeeperSocketName,
	)

	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{
			Name: path,
			Net:  "unix",
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"bind keeper worker socket: %w",
			err,
		)
	}

	// A close must not unlink an endpoint whose pathname might
	// have been replaced. This intentionally leaves a pathname
	// requiring separate, verified retirement.
	listener.SetUnlinkOnClose(false)

	// Only the keeper owns the containing directory. The worker
	// has traversal permission, not directory-write permission.
	//
	// No ownership changes are performed here: the socket must
	// inherit the exact configured group from its directory.
	if err := os.Chmod(path, 0660); err != nil {
		_ = listener.Close()

		return nil, fmt.Errorf(
			"set keeper socket mode: %w",
			err,
		)
	}

	if err := VerifySocketAuthority(
		policy, true,
	); err != nil {
		_ = listener.Close()

		return nil, fmt.Errorf(
			"keeper socket post-bind verification: %w",
			err,
		)
	}

	return listener, nil
}
