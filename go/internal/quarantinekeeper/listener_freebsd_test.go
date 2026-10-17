// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func keeperServerTestListener(
	t *testing.T,
) (*net.UnixListener, string) {
	t.Helper()

	root := t.TempDir()

	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(root, "keeper.sock")

	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{
			Name: path,
			Net:  "unix",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	return listener, path
}

func keeperServerTestDial(
	t *testing.T,
	path string,
) *net.UnixConn {
	t.Helper()

	conn, err := net.DialUnix(
		"unix",
		nil,
		&net.UnixAddr{
			Name: path,
			Net:  "unix",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := conn.SetDeadline(
		time.Now().Add(2 * time.Second),
	); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
	})

	return conn
}

func keeperServerTestRequest() Request {
	return Request{
		Version:   ProtocolVersion,
		Operation: OperationRead,
		SourceID:  testSource,
	}
}

func TestKeeperServerRejectsConnectionOverload(
	t *testing.T,
) {
	identity := keeperTestIdentity(t)
	listener, path := keeperServerTestListener(t)

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	reported := make(chan error, 8)
	result := make(chan error, 1)

	var dispatched atomic.Int32

	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	handler := func(
		ctx context.Context,
		request Request,
	) (Response, error) {
		dispatched.Add(1)

		select {
		case entered <- struct{}{}:
		default:
		}

		select {
		case <-release:
		case <-ctx.Done():
			return Response{}, ctx.Err()
		}

		return Response{
			Version:  ProtocolVersion,
			SourceID: request.SourceID,
			Status:   StatusQuarantined,
		}, nil
	}

	go func() {
		result <- ServeWorkerConnections(
			ctx,
			listener,
			identity,
			handler,
			func(err error) {
				select {
				case reported <- err:
				default:
				}
			},
			1,
		)
	}()

	first := keeperServerTestDial(t, path)

	if err := WriteRequest(
		first,
		keeperServerTestRequest(),
	); err != nil {
		t.Fatal(err)
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first keeper request never entered handler")
	}

	second := keeperServerTestDial(t, path)

	// A connection refused at capacity may close before writing.
	_ = WriteRequest(
		second,
		keeperServerTestRequest(),
	)

	if _, err := ReadResponse(second); err == nil {
		t.Fatal("overloaded keeper accepted a second request")
	}

	select {
	case err := <-reported:
		if !errors.Is(err, ErrKeeperBusy) {
			t.Fatalf("unexpected overload error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("keeper did not report connection overload")
	}

	if got := dispatched.Load(); got != 1 {
		t.Fatalf(
			"handler dispatch count = %d, want 1",
			got,
		)
	}

	close(release)

	response, err := ReadResponse(first)
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != StatusQuarantined {
		t.Fatalf(
			"first accepted request failed: %+v",
			response,
		)
	}

	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("keeper server did not stop")
	}

	t.Log("PASS: No connection queue beyond configured capacity")
	t.Log("PASS: Excess connection cannot reach handler")
	t.Log("PASS: Accepted request completes normally")
}

func TestKeeperServerRejectsUnauthorizedPeer(
	t *testing.T,
) {
	identity := keeperTestIdentity(t)
	identity.UID++

	listener, path := keeperServerTestListener(t)

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	reported := make(chan error, 1)
	result := make(chan error, 1)

	var dispatched atomic.Bool

	go func() {
		result <- ServeWorkerConnections(
			ctx,
			listener,
			identity,
			func(
				ctx context.Context,
				request Request,
			) (Response, error) {
				dispatched.Store(true)
				return Response{
					Version:  ProtocolVersion,
					SourceID: request.SourceID,
					Status:   StatusClear,
				}, nil
			},
			func(err error) {
				select {
				case reported <- err:
				default:
				}
			},
			1,
		)
	}()

	client := keeperServerTestDial(t, path)

	_ = WriteRequest(
		client,
		keeperServerTestRequest(),
	)

	if _, err := ReadResponse(client); err == nil {
		t.Fatal("unauthorized peer received keeper response")
	}

	select {
	case <-reported:
	case <-time.After(2 * time.Second):
		t.Fatal("unauthorized connection was not reported")
	}

	if dispatched.Load() {
		t.Fatal("unauthorized peer reached storage handler")
	}

	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("keeper server did not stop")
	}

	t.Log("PASS: Listener delegates peer authentication to kernel boundary")
}

func TestKeeperServerStopsWhenCanceled(
	t *testing.T,
) {
	identity := keeperTestIdentity(t)
	listener, _ := keeperServerTestListener(t)

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	result := make(chan error, 1)

	go func() {
		result <- ServeWorkerConnections(
			ctx,
			listener,
			identity,
			func(
				ctx context.Context,
				request Request,
			) (Response, error) {
				return Response{}, errors.New(
					"unexpected handler dispatch",
				)
			},
			func(error) {},
			1,
		)
	}()

	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle keeper listener did not stop")
	}

	t.Log("PASS: Idle listener exits on cancellation")
}

func TestKeeperServerRejectsInvalidConfiguration(
	t *testing.T,
) {
	identity := keeperTestIdentity(t)
	listener, _ := keeperServerTestListener(t)

	handler := func(
		context.Context,
		Request,
	) (Response, error) {
		return Response{}, nil
	}

	report := func(error) {}

	if err := ServeWorkerConnections(
		context.Background(),
		nil,
		identity,
		handler,
		report,
		1,
	); err == nil {
		t.Fatal("missing listener accepted")
	}

	if err := ServeWorkerConnections(
		context.Background(),
		listener,
		identity,
		handler,
		report,
		0,
	); err == nil {
		t.Fatal("zero connection limit accepted")
	}

	if err := ServeWorkerConnections(
		context.Background(),
		listener,
		identity,
		handler,
		report,
		MaxWorkerConnections+1,
	); err == nil {
		t.Fatal("unbounded connection limit accepted")
	}

	identity.UID = 0

	if err := ServeWorkerConnections(
		context.Background(),
		listener,
		identity,
		handler,
		report,
		1,
	); err == nil {
		t.Fatal("root worker identity accepted")
	}

	t.Log("PASS: Invalid listener and capacity configurations rejected")
}
