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
	"sync"
	"time"
)

const (
	MaxWorkerConnections = 8
	keeperAcceptInterval = 200 * time.Millisecond
)

var ErrKeeperBusy = errors.New(
	"quarantine keeper active connection limit reached",
)

type FailureReporter func(error)

// ServeWorkerConnections accepts connections only from an already
// established Unix listener.
//
// The caller remains responsible for creating the socket in a
// protected directory with independently verified ownership.
//
// Each accepted connection undergoes kernel peer authentication.
//
// The reporter must not block indefinitely. The handler must
// honor its per-request context deadline.
func ServeWorkerConnections(
	ctx context.Context,
	listener *net.UnixListener,
	expected WorkerIdentity,
	handler WorkerHandler,
	report FailureReporter,
	maxActive int,
) error {
	if ctx == nil {
		return errors.New("missing keeper server context")
	}

	if listener == nil {
		return errors.New("missing keeper listener")
	}

	if expected.UID == 0 {
		return errors.New(
			"keeper worker UID must not be root",
		)
	}

	if handler == nil {
		return errors.New("missing keeper storage handler")
	}

	if report == nil {
		return errors.New("missing keeper failure reporter")
	}

	if maxActive < 1 ||
		maxActive > MaxWorkerConnections {
		return fmt.Errorf(
			"invalid keeper connection limit: %d",
			maxActive,
		)
	}

	slots := make(chan struct{}, maxActive)

	var workers sync.WaitGroup

	// No accepted worker goroutine may outlive orderly shutdown.
	// Production handlers must honor their context deadline.
	defer func() {
		_ = listener.Close()
		workers.Wait()
	}()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := listener.SetDeadline(
			time.Now().Add(keeperAcceptInterval),
		); err != nil {
			return fmt.Errorf(
				"set keeper accept deadline: %w",
				err,
			)
		}

		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			var netErr net.Error

			if errors.As(err, &netErr) &&
				netErr.Timeout() {
				continue
			}

			return fmt.Errorf(
				"accept keeper Unix connection: %w",
				err,
			)
		}

		if err := ctx.Err(); err != nil {
			_ = conn.Close()
			return err
		}

		select {
		case slots <- struct{}{}:
			workers.Add(1)

			go func(client *net.UnixConn) {
				defer workers.Done()
				defer func() {
					<-slots
				}()

				if err := HandleWorkerConnection(
					client,
					expected,
					handler,
				); err != nil {
					report(err)
				}
			}(conn)

		default:
			// Do not allocate another worker goroutine and
			// do not queue an excess request in application memory.
			_ = conn.Close()
			report(ErrKeeperBusy)
		}
	}
}
