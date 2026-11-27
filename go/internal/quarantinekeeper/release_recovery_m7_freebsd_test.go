// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const m7FixtureOperationID = "f135e77c423a4a4b8db75bca5e979c23"

// m7StageReleaseIntent records the same immutable first audit as a normal
// keeper release, without invoking releaseTransaction or altering live storage.
// The caller selects which subsequent crash-window steps to simulate.
func m7StageReleaseIntent(t *testing.T, store *KeeperStore, root, history string) (string, string) {
	t.Helper()
	markerPath := filepath.Join(root, releaseFixtureSource+".json")
	raw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var marker QuarantineMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	intent := keeperReleaseAudit{
		Version:              keeperReleaseAuditVersion,
		OperationID:          m7FixtureOperationID,
		Phase:                "intent",
		SourceID:             releaseFixtureSource,
		OperatorUID:          0,
		Reference:            "FI-M7-SYNTHETIC-FAULT",
		Reason:               "deliberately simulated interrupted keeper release",
		RequestedAtUTC:       "2026-10-16T00:00:00Z",
		OriginalMarker:       marker,
		OriginalMarkerSHA256: hex.EncodeToString(hash[:]),
	}
	historyFD, err := store.openReleaseHistory(history)
	if err != nil {
		t.Fatal(err)
	}
	intentName := "release-" + m7FixtureOperationID + ".intent.json"
	publishErr := keeperPublishAudit(historyFD, intentName, intent)
	closeErr := unix.Close(historyFD)
	if publishErr != nil {
		t.Fatal(publishErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return filepath.Join(history, intentName), markerPath
}

func m7StageGuard(t *testing.T, root string) string {
	t.Helper()
	guardPath := filepath.Join(root, ".release-"+m7FixtureOperationID+".pending")
	fd, err := os.OpenFile(guardPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fd.WriteString(m7FixtureOperationID + "\n"); err != nil {
		_ = fd.Close()
		t.Fatal(err)
	}
	if err := fd.Sync(); err != nil {
		_ = fd.Close()
		t.Fatal(err)
	}
	if err := fd.Close(); err != nil {
		t.Fatal(err)
	}
	m7SyncDirectory(t, root)
	return guardPath
}

func m7SyncDirectory(t *testing.T, path string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := unix.Fsync(fd)
	closeErr := unix.Close(fd)
	if syncErr != nil {
		t.Fatal(syncErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func m7VerifyFailedClosed(t *testing.T, store *KeeperStore, root string) {
	t.Helper()
	for _, operation := range []Operation{OperationRead, OperationPublish} {
		request := Request{
			Version:   ProtocolVersion,
			Operation: operation,
			SourceID:  releaseFixtureSource,
		}
		if operation == OperationPublish {
			request.Reason = "RELATIONAL_CONFLICT"
			request.GenerationID = "m7-synthetic-retry"
			request.Detail = "must not override interrupted release"
		}
		if response, err := store.Handle(context.Background(), request); err == nil {
			t.Fatalf("%s reported a successful state after interrupted release: %+v", operation, response)
		}
	}
	if _, err := NewKeeperStore(root, uint32(os.Geteuid()), uint32(os.Getegid()), []string{releaseFixtureSource}); err == nil {
		t.Fatal("keeper startup accepted incomplete release inventory")
	}
}

func TestM7ReleaseCrashAfterIntentBeforeGuardKeepsSourceQuarantined(t *testing.T) {
	store, root, history := keeperReleaseFixture(t)
	auditPath, markerPath := m7StageReleaseIntent(t, store, root, history)
	if _, err := os.Stat(auditPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewKeeperStore(root, uint32(os.Geteuid()), uint32(os.Getegid()), []string{releaseFixtureSource})
	if err != nil {
		t.Fatal(err)
	}
	response, err := reopened.Handle(context.Background(), Request{
		Version:   ProtocolVersion,
		Operation: OperationRead,
		SourceID:  releaseFixtureSource,
	})
	if err != nil || response.Status != StatusQuarantined {
		t.Fatalf("intent-only crash window lost quarantine: %+v %v", response, err)
	}
	t.Log("PASS: intent-only interruption preserves the original quarantined marker")
}

func TestM7ReleaseCrashAfterMarkerUnlinkFailsClosed(t *testing.T) {
	store, root, history := keeperReleaseFixture(t)
	intentPath, markerPath := m7StageReleaseIntent(t, store, root, history)
	guardPath := m7StageGuard(t, root)
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	m7SyncDirectory(t, root)
	m7VerifyFailedClosed(t, store, root)
	if _, err := os.Stat(guardPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(intentPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
		t.Fatalf("immutable intent unavailable after synthetic crash: %v %v", info, err)
	}
	if _, err := os.Lstat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("synthetic crash marker unexpectedly restored: %v", err)
	}
	t.Log("PASS: marker-unlinked interruption blocks reads, publication and keeper restart")
}

func TestM7ReleaseCrashAfterCompletionBeforeGuardRetirementFailsClosed(t *testing.T) {
	store, root, history := keeperReleaseFixture(t)
	intentPath, markerPath := m7StageReleaseIntent(t, store, root, history)
	guardPath := m7StageGuard(t, root)
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	m7SyncDirectory(t, root)
	raw, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	var complete keeperReleaseAudit
	if err := json.Unmarshal(raw, &complete); err != nil {
		t.Fatal(err)
	}
	complete.Phase = "complete"
	complete.ReleasedAtUTC = "2026-10-16T00:00:01Z"
	historyFD, err := store.openReleaseHistory(history)
	if err != nil {
		t.Fatal(err)
	}
	publishErr := keeperPublishAudit(historyFD,
		"release-"+m7FixtureOperationID+".complete.json", complete)
	closeErr := unix.Close(historyFD)
	if publishErr != nil {
		t.Fatal(publishErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	m7VerifyFailedClosed(t, store, root)
	if _, err := os.Stat(guardPath); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(history)
	if err != nil || len(entries) != 2 {
		t.Fatalf("audit records changed after interrupted completion: %d %v", len(entries), err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			t.Fatalf("unexpected audit object %q", entry.Name())
		}
	}
	t.Log("PASS: completed audit with stranded guard is never automatically treated as clear")
}
