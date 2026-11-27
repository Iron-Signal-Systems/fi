// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func keeperTestConnection(
	t *testing.T,
) (*net.UnixConn, *net.UnixConn) {
	t.Helper()

	root := t.TempDir()

	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(root, "keeper.sock")

	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	client, err := net.DialUnix(
		"unix",
		nil,
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}

	server, err := listener.AcceptUnix()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	return client, server
}

func keeperTestIdentity(t *testing.T) WorkerIdentity {
	t.Helper()

	uid := os.Geteuid()

	if uid == 0 {
		t.Skip("keeper worker tests require unprivileged execution")
	}

	return WorkerIdentity{
		UID: uint32(uid),
		GID: uint32(os.Getegid()),
	}
}

func TestKeeperPeerAcceptsKernelVerifiedWorker(
	t *testing.T,
) {
	expected := keeperTestIdentity(t)
	client, server := keeperTestConnection(t)

	result := make(chan error, 1)

	go func() {
		result <- HandleWorkerConnection(
			server,
			expected,
			func(
				ctx context.Context,
				request Request,
			) (Response, error) {
				return Response{
					Version:  ProtocolVersion,
					SourceID: request.SourceID,
					Status:   StatusQuarantined,
				}, nil
			},
		)
	}()

	request := Request{
		Version:   ProtocolVersion,
		Operation: OperationRead,
		SourceID:  testSource,
	}

	if err := WriteRequest(client, request); err != nil {
		t.Fatal(err)
	}

	response, err := ReadResponse(client)
	if err != nil {
		t.Fatal(err)
	}

	if response.SourceID != testSource ||
		response.Status != StatusQuarantined {
		t.Fatalf("unexpected keeper response: %+v", response)
	}

	if err := <-result; err != nil {
		t.Fatal(err)
	}

	t.Log("PASS: Kernel UID/GID verified before dispatch")
}

func TestKeeperPeerRejectsDifferentIdentity(
	t *testing.T,
) {
	expected := keeperTestIdentity(t)
	_, server := keeperTestConnection(t)

	expected.UID++

	called := make(chan struct{}, 1)

	err := HandleWorkerConnection(
		server,
		expected,
		func(
			ctx context.Context,
			request Request,
		) (Response, error) {
			called <- struct{}{}
			return Response{}, nil
		},
	)

	if err == nil {
		t.Fatal("unauthorized peer accepted")
	}

	select {
	case <-called:
		t.Fatal("handler ran before worker authorization")
	default:
	}

	t.Log("PASS: Wrong worker UID rejected before dispatch")
}

func TestKeeperPeerRejectsPublicationClear(
	t *testing.T,
) {
	expected := keeperTestIdentity(t)
	client, server := keeperTestConnection(t)

	result := make(chan error, 1)

	go func() {
		result <- HandleWorkerConnection(
			server,
			expected,
			func(
				ctx context.Context,
				request Request,
			) (Response, error) {
				return Response{
					Version:  ProtocolVersion,
					SourceID: request.SourceID,
					Status:   StatusClear,
				}, nil
			},
		)
	}()

	request := Request{
		Version:      ProtocolVersion,
		Operation:    OperationPublish,
		SourceID:     testSource,
		Reason:       "RELATIONAL_CONFLICT",
		GenerationID: "m1-conflict",
		Detail:       "receipt mismatch",
	}

	if err := WriteRequest(client, request); err != nil {
		t.Fatal(err)
	}

	if err := <-result; err == nil {
		t.Fatal("publication returned clear without quarantine")
	}

	if _, err := ReadResponse(client); err == nil {
		t.Fatal("invalid clear response reached the worker")
	}

	t.Log("PASS: Publication cannot be acknowledged as clear")
}

func TestKeeperPeerRejectsReleaseBeforeHandler(
	t *testing.T,
) {
	expected := keeperTestIdentity(t)
	client, server := keeperTestConnection(t)

	called := make(chan struct{}, 1)
	result := make(chan error, 1)

	go func() {
		result <- HandleWorkerConnection(
			server,
			expected,
			func(
				ctx context.Context,
				request Request,
			) (Response, error) {
				called <- struct{}{}
				return Response{}, nil
			},
		)
	}()

	raw := wireJSON(
		`{"version":1,"operation":"release","source_id":"` +
			testSource + `"}`,
	)

	if _, err := client.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}

	if err := <-result; err == nil {
		t.Fatal("release reached the keeper handler")
	}

	select {
	case <-called:
		t.Fatal("release request dispatched to storage")
	default:
	}

	t.Log("PASS: Release excluded from worker-facing IPC")
}
