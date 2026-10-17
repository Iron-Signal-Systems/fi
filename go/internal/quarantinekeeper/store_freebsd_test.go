// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	keeperTestSourceA = "iss-fs-2019.iss.local"
	keeperTestSourceB = "iss-fs-22.iss.local"
)

func keeperTestStore(t *testing.T) (*KeeperStore, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("keeper storage tests require an unprivileged FreeBSD user")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "quarantine")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewKeeperStore(root, uint32(os.Geteuid()),
		uint32(os.Getegid()), []string{keeperTestSourceA, keeperTestSourceB})
	if err != nil {
		t.Fatal(err)
	}
	return store, root
}

func keeperPublishFixture() Request {
	return Request{
		Version:      ProtocolVersion,
		Operation:    OperationPublish,
		SourceID:     keeperTestSourceA,
		Reason:       "RELATIONAL_CONFLICT",
		GenerationID: "m1-conflict-1",
		Detail:       "independently detected receipt conflict",
	}
}

func TestKeeperStorePublishPersistsAndDoesNotOverwrite(t *testing.T) {
	store, root := keeperTestStore(t)
	ctx := context.Background()
	readA := Request{Version: ProtocolVersion, Operation: OperationRead,
		SourceID: keeperTestSourceA}
	readB := Request{Version: ProtocolVersion, Operation: OperationRead,
		SourceID: keeperTestSourceB}
	if response, err := store.Handle(ctx, readA); err != nil || response.Status != StatusClear {
		t.Fatalf("initial source status: %+v %v", response, err)
	}
	initial, err := store.Handle(ctx, keeperPublishFixture())
	if err != nil || initial.Status != StatusQuarantined {
		t.Fatalf("publish: %+v %v", initial, err)
	}
	filename := filepath.Join(root, keeperTestSourceA+".json")
	before, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
		t.Fatalf("invalid marker permissions: %v", info.Mode())
	}
	repeat := keeperPublishFixture()
	repeat.Detail = "attempted overwrite"
	if response, err := store.Handle(ctx, repeat); err != nil || response.Status != StatusQuarantined {
		t.Fatalf("idempotent publication: %+v %v", response, err)
	}
	after, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("keeper overwrote immutable marker")
	}
	if response, err := store.Handle(ctx, readB); err != nil || response.Status != StatusClear {
		t.Fatalf("healthy source incorrectly blocked: %+v %v", response, err)
	}
	restarted, err := NewKeeperStore(root, uint32(os.Geteuid()),
		uint32(os.Getegid()), []string{keeperTestSourceA, keeperTestSourceB})
	if err != nil {
		t.Fatal(err)
	}
	if response, err := restarted.Handle(ctx, readA); err != nil || response.Status != StatusQuarantined {
		t.Fatalf("durable restart restore: %+v %v", response, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("unexpected keeper directory entries: %d", len(entries))
	}
}

func TestKeeperStoreRejectsUnknownSourceAndReason(t *testing.T) {
	store, root := keeperTestStore(t)
	request := keeperPublishFixture()
	request.SourceID = "unregistered-fs.local"
	if _, err := store.Handle(context.Background(), request); err == nil {
		t.Fatal("unregistered source accepted")
	}
	request = keeperPublishFixture()
	request.Reason = "OPERATOR_RELEASE"
	if _, err := store.Handle(context.Background(), request); err == nil {
		t.Fatal("unapproved quarantine reason accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid request mutated keeper state: %v %v", entries, err)
	}
}

func TestKeeperStoreFailsClosedOnUnexpectedObjects(t *testing.T) {
	store, root := keeperTestStore(t)
	file := filepath.Join(root, "unknown-source.json")
	if err := os.WriteFile(file, []byte("unexpected"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationRead,
		SourceID: keeperTestSourceB,
	}); err == nil {
		t.Fatal("unknown marker did not fail closed")
	}
	if _, err := NewKeeperStore(root, uint32(os.Geteuid()),
		uint32(os.Getegid()), []string{keeperTestSourceA, keeperTestSourceB}); err == nil {
		t.Fatal("restart accepted unrecognized keeper inventory")
	}
}

func TestKeeperStoreRejectsUnsafeRootAndSymlinkMarker(t *testing.T) {
	store, root := keeperTestStore(t)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationRead,
		SourceID: keeperTestSourceA,
	}); err == nil {
		t.Fatal("nonprivate root accepted")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, keeperTestSourceA+".json")
	if err := os.Symlink(filepath.Join(root, "missing"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationRead,
		SourceID: keeperTestSourceB,
	}); err == nil {
		t.Fatal("symlink marker accepted")
	}
}

func TestKeeperStoreRejectsMalformedMarker(t *testing.T) {
	store, root := keeperTestStore(t)
	if err := os.WriteFile(filepath.Join(root, keeperTestSourceA+".json"),
		[]byte(`{"source_id":"`+keeperTestSourceB+`"}`), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationRead,
		SourceID: keeperTestSourceB,
	}); err == nil {
		t.Fatal("incorrect source marker accepted")
	}
}

func TestKeeperStoreConcurrentPublishIsIdempotent(t *testing.T) {
	store, root := keeperTestStore(t)
	var wg sync.WaitGroup
	errorsFound := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Handle(context.Background(), keeperPublishFixture())
			errorsFound <- err
		}()
	}
	wg.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".json") {
		t.Fatalf("concurrent publish left unexpected inventory: %v", entries)
	}
}

func TestKeeperStoreRejectsAbandonedPendingPublication(t *testing.T) {
	store, root := keeperTestStore(t)
	if err := os.WriteFile(filepath.Join(root, ".keeper-abandoned.pending"),
		[]byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationRead,
		SourceID: keeperTestSourceB,
	}); err == nil {
		t.Fatal("abandoned pending file silently accepted")
	}
}

func TestKeeperStoreRejectsDuplicateMarkerProperties(t *testing.T) {
	store, root := keeperTestStore(t)
	request := keeperPublishFixture()
	if _, err := store.Handle(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(root, keeperTestSourceA+".json")
	raw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately substitute two reason keys. The last value could
	// otherwise silently override the original reason in encoding/json.
	changed := strings.Replace(string(raw), `"reason":"RELATIONAL_CONFLICT"`,
		`"reason":"RELATIONAL_CONFLICT","reason":"RECORDED_RECEIPT_INVALID"`, 1)
	if changed == string(raw) {
		t.Fatal("reason field not found")
	}
	if err := os.Chmod(markerPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerPath, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationRead,
		SourceID: keeperTestSourceB,
	}); err == nil {
		t.Fatal("duplicate marker property accepted")
	}
}
