// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdminServerRejectsMissingAuthority(t *testing.T) {
	if err := ServeAdminReleaseConnections(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("admin server accepted absent protected handler")
	}
}

func TestAdminServerRejectsNonRootWithoutDispatch(t *testing.T) {
	policy := adminSocketFixture(t)
	listener, err := BindAdminSocket(policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	reports := make(chan error, 1)
	result := make(chan error, 1)
	go func() {
		result <- ServeAdminReleaseConnections(ctx, listener,
			func(context.Context, KeeperReleaseRequest) (string, error) {
				calls.Add(1)
				return "", nil
			}, func(err error) { reports <- err })
	}()
	client, err := net.DialTimeout("unix", filepath.Join(policy.Directory, AdminSocketName), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var response [1]byte
	if n, err := client.Read(response[:]); err == nil || n != 0 {
		t.Fatalf("unauthorized peer unexpectedly received data: bytes=%d error=%v", n, err)
	}
	_ = client.Close()
	select {
	case <-reports:
	case <-time.After(3 * time.Second):
		t.Fatal("admin server failed to report unauthorized connection")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil && err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admin server failed to stop after cancellation")
	}
	if calls.Load() != 0 {
		t.Fatalf("unauthorized connection dispatched: calls=%d", calls.Load())
	}
}

func TestKeeperHistoryPreflight(t *testing.T) {
	store, _, history := keeperReleaseFixture(t)
	if err := store.VerifyReleaseHistory(history); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyReleaseHistory(history + "-absent"); err == nil {
		t.Fatal("missing audit history accepted")
	}
}
