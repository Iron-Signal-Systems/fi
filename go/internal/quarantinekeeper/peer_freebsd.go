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

	"golang.org/x/sys/unix"
)

const (
	keeperRequestTimeout = 3 * time.Second

	// FreeBSD sys/sys/ucred.h: XUCRED_VERSION.
	keeperXucredVersion = 0
)

type WorkerIdentity struct {
	UID uint32
	GID uint32
}

// WorkerHandler must validate source enrollment, use durable
// keeper-owned storage, and honor context cancellation.
// It is not yet connected to an operational storage handler.
type WorkerHandler func(
	context.Context,
	Request,
) (Response, error)

// VerifyWorkerPeer obtains credentials from the FreeBSD kernel.
// The request body is never used to establish process identity.
func VerifyWorkerPeer(
	conn *net.UnixConn,
	expected WorkerIdentity,
) error {
	if conn == nil {
		return errors.New("missing keeper Unix connection")
	}

	// The ingestion worker is never a privileged/root process.
	if expected.UID == 0 {
		return errors.New(
			"keeper worker identity must not be root",
		)
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf(
			"obtain Unix connection descriptor: %w",
			err,
		)
	}

	var credentials *unix.Xucred
	var credentialError error

	if err := raw.Control(func(fd uintptr) {
		credentials, credentialError = unix.GetsockoptXucred(
			int(fd),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERCRED,
		)
	}); err != nil {
		return fmt.Errorf(
			"inspect kernel peer credentials: %w",
			err,
		)
	}

	if credentialError != nil {
		return fmt.Errorf(
			"read kernel peer credentials: %w",
			credentialError,
		)
	}

	if credentials == nil ||
		credentials.Version != keeperXucredVersion ||
		credentials.Ngroups < 1 ||
		int(credentials.Ngroups) > len(credentials.Groups) {
		return errors.New(
			"invalid FreeBSD kernel peer credentials",
		)
	}

	if credentials.Uid != expected.UID ||
		credentials.Groups[0] != expected.GID {
		return errors.New(
			"Unix peer does not match enrolled FI worker identity",
		)
	}

	return nil
}

// HandleWorkerConnection processes one authenticated request.
// The caller supplies an already accepted Unix stream connection.
//
// No operation is dispatched before kernel credential verification.
// This function owns and closes the accepted connection.
func HandleWorkerConnection(
	conn *net.UnixConn,
	expected WorkerIdentity,
	handler WorkerHandler,
) error {
	if conn == nil {
		return errors.New("missing keeper connection")
	}

	defer conn.Close()

	if handler == nil {
		return errors.New("missing keeper storage handler")
	}

	deadline := time.Now().Add(keeperRequestTimeout)

	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf(
			"set keeper connection deadline: %w",
			err,
		)
	}

	if err := VerifyWorkerPeer(conn, expected); err != nil {
		return err
	}

	request, err := ReadRequest(conn)
	if err != nil {
		return fmt.Errorf(
			"read authenticated keeper request: %w",
			err,
		)
	}

	ctx, cancel := context.WithDeadline(
		context.Background(),
		deadline,
	)
	defer cancel()

	response, err := handler(ctx, request)
	if err != nil {
		return fmt.Errorf(
			"keeper storage operation failed: %w",
			err,
		)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"keeper storage operation exceeded deadline: %w",
			err,
		)
	}

	if response.SourceID != request.SourceID {
		return errors.New(
			"keeper response source differs from request",
		)
	}

	if request.Operation == OperationPublish &&
		response.Status == StatusClear {
		return errors.New(
			"keeper publication cannot return clear status",
		)
	}

	if err := WriteResponse(conn, response); err != nil {
		return fmt.Errorf(
			"write authenticated keeper response: %w",
			err,
		)
	}

	return nil
}
