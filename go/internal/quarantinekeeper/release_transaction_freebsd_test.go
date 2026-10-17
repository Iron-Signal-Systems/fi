// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const releaseFixtureSource = "m1-release-fixture.local"

func keeperReleaseFixture(t *testing.T) (*KeeperStore, string, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("keeper fixture requires nonroot identity")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "quarantine")
	history := filepath.Join(parent, "history")
	for _, directory := range []string{root, history} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(directory, -1, os.Getegid()); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewKeeperStore(root, uint32(os.Geteuid()),
		uint32(os.Getegid()), []string{releaseFixtureSource})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationPublish,
		SourceID: releaseFixtureSource, Reason: "RELATIONAL_CONFLICT",
		GenerationID: "synthetic-1", Detail: "test conflict",
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, root, history
}

func validKeeperReleaseFixture() KeeperReleaseRequest {
	return KeeperReleaseRequest{
		SourceID: releaseFixtureSource, ConfirmSource: releaseFixtureSource,
		Reference: "TEST-12345", Justification: "deliberate synthetic release review",
		OperatorUID: 0,
	}
}

func TestKeeperReleaseTransactionAuditBeforeRetirement(t *testing.T) {
	store, root, history := keeperReleaseFixture(t)
	auditPath, err := store.releaseTransaction(context.Background(),
		history, validKeeperReleaseFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, releaseFixtureSource+".json")); !os.IsNotExist(err) {
		t.Fatalf("released marker persists: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("stranded release guard: %v", entries)
	}
	historyEntries, err := os.ReadDir(history)
	if err != nil {
		t.Fatal(err)
	}
	if len(historyEntries) != 2 {
		t.Fatalf("audit files=%d, want 2", len(historyEntries))
	}
	if !strings.HasSuffix(auditPath, ".complete.json") {
		t.Fatal("no completion audit")
	}
	var intent, complete keeperReleaseAudit
	for _, entry := range historyEntries {
		info, err := os.Lstat(filepath.Join(history, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
			t.Fatal("unsafe audit mode")
		}
		raw, err := os.ReadFile(filepath.Join(history, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var record keeperReleaseAudit
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		if record.SourceID != releaseFixtureSource || record.Reference != "TEST-12345" ||
			record.OperatorUID != 0 || record.OriginalMarker.SourceID != releaseFixtureSource ||
			record.Version != keeperReleaseAuditVersion {
			t.Fatalf("bad audit: %+v", record)
		}
		if record.Phase == "intent" {
			intent = record
		} else if record.Phase == "complete" {
			complete = record
		} else {
			t.Fatal("unknown audit phase")
		}
	}
	if intent.RequestedAtUTC == "" || intent.ReleasedAtUTC != "" || complete.ReleasedAtUTC == "" {
		t.Fatal("intent and completion timestamps are inconsistent")
	}
	if intent.OperationID == "" || intent.OperationID != complete.OperationID ||
		intent.OriginalMarkerSHA256 != complete.OriginalMarkerSHA256 ||
		(len(intent.OriginalMarkerSHA256) != sha256.Size*2 || intent.OriginalMarkerSHA256 == strings.Repeat("0", sha256.Size*2)) {
		t.Fatal("audit pair does not preserve marker identity")
	}
	response, err := store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationRead, SourceID: releaseFixtureSource,
	})
	if err != nil || response.Status != StatusClear {
		t.Fatalf("post-release state: %+v %v", response, err)
	}
	_, err = NewKeeperStore(root, uint32(os.Geteuid()), uint32(os.Getegid()), []string{releaseFixtureSource})
	if err != nil {
		t.Fatalf("reopen after complete audit: %v", err)
	}
}

func TestKeeperReleaseTransactionRejectsFalseConfirmation(t *testing.T) {
	store, root, history := keeperReleaseFixture(t)
	req := validKeeperReleaseFixture()
	req.ConfirmSource = "m1-other-fixture.local"
	if _, err := store.releaseTransaction(context.Background(), history, req); err == nil {
		t.Fatal("incorrect source confirmation was accepted")
	}
	req = validKeeperReleaseFixture()
	req.OperatorUID = 61232
	if _, err := store.releaseTransaction(context.Background(), history, req); err == nil {
		t.Fatal("worker UID was accepted as release operator")
	}
	if _, err := os.Stat(filepath.Join(root, releaseFixtureSource+".json")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(history)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("invalid request produced release audit")
	}
}

func TestKeeperReleaseTransactionAuditFailurePreservesMarker(t *testing.T) {
	store, root, history := keeperReleaseFixture(t)
	if err := os.Chmod(history, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.releaseTransaction(context.Background(), history, validKeeperReleaseFixture()); err == nil {
		t.Fatal("unsafe history directory accepted")
	}
	if _, err := os.Stat(filepath.Join(root, releaseFixtureSource+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestKeeperReleaseTransactionGuardsInterruptedRelease(t *testing.T) {
	store, root, _ := keeperReleaseFixture(t)
	guard := filepath.Join(root, ".release-0123456789abcdef.pending")
	if err := os.WriteFile(guard, []byte("interrupted synthetic release\n"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Handle(context.Background(), Request{
		Version: ProtocolVersion, Operation: OperationRead, SourceID: releaseFixtureSource,
	}); err == nil {
		t.Fatal("keeper silently ignored an interrupted release guard")
	}
	if _, err := NewKeeperStore(root, uint32(os.Geteuid()), uint32(os.Getegid()),
		[]string{releaseFixtureSource}); err == nil {
		t.Fatal("keeper restarted with unresolved release guard")
	}
	if _, err := os.Stat(filepath.Join(root, releaseFixtureSource+".json")); err != nil {
		t.Fatal(err)
	}
}
