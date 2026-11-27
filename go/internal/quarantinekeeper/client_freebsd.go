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
	"os"
	"path/filepath"
	"time"
)

// WorkerClient can only request read or publication over an authenticated,
// keeper-owned Unix endpoint. It has no operation for releasing markers.
type WorkerClient struct {
	Socket SocketAuthority
}

func (client WorkerClient) Call(ctx context.Context, request Request) (Response, error) {
	if ctx == nil {
		return Response{}, errors.New("missing keeper client context")
	}
	if err := request.Validate(); err != nil {
		return Response{}, err
	}
	if uint32(os.Geteuid()) != client.Socket.WorkerUID {
		return Response{}, errors.New("keeper client requires enrolled worker UID")
	}
	if err := VerifySocketAuthority(client.Socket, true); err != nil {
		return Response{}, fmt.Errorf("verify keeper endpoint: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, keeperRequestTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(callCtx, "unix",
		filepath.Join(client.Socket.Directory, KeeperSocketName))
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	deadline, ok := callCtx.Deadline()
	if !ok {
		deadline = time.Now().Add(keeperRequestTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	if err := WriteRequest(conn, request); err != nil {
		return Response{}, err
	}
	response, err := ReadResponse(conn)
	if err != nil {
		return Response{}, err
	}
	if response.SourceID != request.SourceID || response.Status == StatusError ||
		(request.Operation == OperationPublish && response.Status != StatusQuarantined) {
		return Response{}, errors.New("keeper response does not acknowledge requested source state")
	}
	if err := callCtx.Err(); err != nil {
		return Response{}, err
	}
	return response, nil
}

func (client WorkerClient) Read(ctx context.Context, source string) (Status, error) {
	response, err := client.Call(ctx, Request{
		Version:   ProtocolVersion,
		Operation: OperationRead,
		SourceID:  source,
	})
	if err != nil {
		return "", err
	}
	return response.Status, nil
}

func (client WorkerClient) Publish(ctx context.Context, source, reason, generation, detail string) error {
	_, err := client.Call(ctx, Request{
		Version:      ProtocolVersion,
		Operation:    OperationPublish,
		SourceID:     source,
		Reason:       reason,
		GenerationID: generation,
		Detail:       detail,
	})
	return err
}
