// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ServeAdminReleaseConnections serializes administrative release attempts.
// The handler must be ProtectedAdminReleaseHandler, which holds the same
// protected singleton inode used by every namespaced worker.
// Each connection is kernel-authenticated before its request is parsed.
func ServeAdminReleaseConnections(
	ctx context.Context,
	listener *net.UnixListener,
	handler AdminReleaseHandler,
	report FailureReporter,
) error {
	if ctx == nil || listener == nil || handler == nil || report == nil {
		return errors.New("administrative release server requires context, listener, protected handler, and reporter")
	}
	defer listener.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := listener.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return fmt.Errorf("administrative socket accept deadline: %w", err)
		}
		client, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("administrative socket accept: %w", err)
		}
		if err := ctx.Err(); err != nil {
			_ = client.Close()
			return err
		}
		// One authenticated release at a time. No secondary release queue.
		// HandleAdminReleaseConnection enforces its own request deadline.
		if err := HandleAdminReleaseConnection(client, handler); err != nil {
			report(err)
		}
	}
}
