// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// newWindowsCreationSinkForIsolatedTests exists ONLY in the Windows test
// binary. It retains the earlier native CREATE_NEW/write/sync/recovery tests
// in disposable, ordinary temp directories, where owner/DACL are not an FI
// installer trust boundary. Shipping code must use newWindowsCreationSink,
// which always verifies the retained protected parent handle first.
func newWindowsCreationSinkForIsolatedTests(path string) *windowsCreationSink {
	return &windowsCreationSink{
		parentPath: path,
		skipProtectedParentForTests: true,
	}
}

func TestProtectedNativeJournalWriterRejectsUntrustedParentBeforeCREATE_NEW(t *testing.T) {
	dir := t.TempDir()
	// A runner temp directory is normally inherited and intentionally not
	// configured as an approved installer parent. Inspect it independently
	// so this test does not assume particular runner image ACL defaults.
	parentPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil { t.Fatal(err) }
	handle, err := windows.CreateFile(
		parentPtr, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil { t.Fatal(err) }
	policyErr := verifyJournalParentHandle(handle)
	if err := windows.CloseHandle(handle); err != nil { t.Fatal(err) }
	if policyErr == nil {
		t.Skip("runner temp directory unexpectedly matches canonical FI installer owner/DACL; cannot exercise rejection")
	}

	sink := newWindowsCreationSink(dir) // normal, non-test-bypass constructor
	if err := sink.ReserveNew(testInstallID); !errors.Is(err, ErrUntrustedJournalParent) {
		_ = sink.Close()
		t.Fatalf("untrusted journal parent reached create-new boundary: %v", err)
	}
	if err := sink.Close(); err != nil { t.Fatal(err) }
	if _, err := os.Lstat(filepath.Join(dir, nativeCreationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted journal parent left newly created FI evidence: %v", err)
	}
}

func TestWindowsCreationJournalDurablyRecordsAllEvents(t *testing.T) {
	dir := t.TempDir() // isolated test directory, NEVER a live FI installation
	sink := newWindowsCreationSinkForIsolatedTests(dir)
	creator := &recordingCreator{}
	if err := executeCreation(sink, creator, testCreationIdentity); err != nil {
		_ = sink.Close()
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, nativeCreationJournalName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	status, err := InspectCreationJournal(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !status.Complete || status.InDoubt || status.CreationIdentity != testCreationIdentity ||
		status.CreatedSteps != len(creationSteps) || len(creator.steps) != len(creationSteps) {
		t.Fatalf("native disk journal did not roundtrip complete protocol: %+v", status)
	}
}

func TestWindowsCreationJournalRefusesExistingFileWithoutModification(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, nativeCreationJournalName)
	before := []byte("previous installation evidence, never replace")
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	sink := newWindowsCreationSinkForIsolatedTests(dir)
	creator := &recordingCreator{}
	if err := executeCreation(sink, creator, testCreationIdentity); !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("existing journal accepted for replacement: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || len(creator.steps) != 0 {
		t.Fatalf("existing journal modified or native creation started")
	}
}

func TestWindowsCreationJournalNativeMutationFailurePreservesPartialCustody(t *testing.T) {
	dir := t.TempDir()
	sink := newWindowsCreationSinkForIsolatedTests(dir)
	backend := &recordingCreator{failAt: 3}
	if err := executeCreation(sink, backend, testCreationIdentity); !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("native partial creation did not fail closed: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, nativeCreationJournalName))
	if err != nil {
		t.Fatal(err)
	}
	status, err := InspectCreationJournal(bytes.NewReader(raw))
	if !errors.Is(err, ErrCreationInDoubt) || !status.InDoubt || status.Complete ||
		status.CreatedSteps != 2 || status.NextStep != creationSteps[2] {
		t.Fatalf("partial native creation was interpreted as complete: %+v %v", status, err)
	}
	second := newWindowsCreationSinkForIsolatedTests(dir)
	retryBackend := &recordingCreator{}
	if err := executeCreation(second, retryBackend, testCreationIdentity); !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("existing incomplete journal accepted by new process: %v", err)
	}
	_ = second.Close()
	if len(retryBackend.steps) != 0 {
		t.Fatal("new process restarted an in-doubt installation")
	}
}

func TestWindowsCreationJournalRejectsBadParentAndClosedSink(t *testing.T) {
	testPaths := []string{
		"",
		"relative",
		t.TempDir() + `\no-longer-exists`,
		filepath.VolumeName(t.TempDir()) + `\`,
	}
	for _, path := range testPaths {
		sink := newWindowsCreationSinkForIsolatedTests(path)
		if err := sink.ReserveNew(testInstallID); err == nil {
			_ = sink.Close()
			t.Fatalf("invalid local journal parent accepted: %q", path)
		}
		_ = sink.Close()
	}
	sink := newWindowsCreationSinkForIsolatedTests(t.TempDir())
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.ReserveNew(testInstallID); err == nil {
		t.Fatal("closed native journal sink could reserve a new installation")
	}
}

func TestWindowsCreationJournalRejectsUnsafeFrames(t *testing.T) {
	dir := t.TempDir()
	sink := newWindowsCreationSinkForIsolatedTests(dir)
	if err := sink.ReserveNew(testInstallID); err != nil {
		t.Fatal(err)
	}
	if err := sink.AppendAndSync([]byte("not-a-newline")); err == nil {
		t.Fatal("unterminated journal frame accepted")
	}
	if err := sink.AppendAndSync([]byte("begin\n")); err == nil {
		t.Fatal("poisoned journal allowed a second write")
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCreationJournalDeniesParentReparseAlias(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual")
	alias := filepath.Join(dir, "alias")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, alias); err != nil {
		// The Windows runner may not be granted symbolic-link creation rights.
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	sink := newWindowsCreationSinkForIsolatedTests(alias)
	if err := sink.ReserveNew(testInstallID); err == nil {
		_ = sink.Close()
		t.Fatal("reparse parent accepted")
	}
	_ = sink.Close()
	if _, err := os.Stat(filepath.Join(actual, nativeCreationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal written through reparse alias: %v", err)
	}
}

func TestWindowsCreationJournalConcurrentInstallReservations(t *testing.T) {
	dir := t.TempDir()
	const attempts = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	release := make(chan struct{})
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sink := newWindowsCreationSinkForIsolatedTests(dir)
			<-start
			err := sink.ReserveNew(testInstallID)
			results <- err
			// Hold successful exclusive file ownership until all contenders
			// have attempted creation. The file remains after closing.
			if err == nil {
				<-release
			}
			_ = sink.Close()
		}()
	}
	close(start)
	// Every result arrives before releasing the winning exclusive handle.
	// Other processes attempting CREATE_NEW must fail even while that handle
	// is still open, not just because a closed journal remains on disk.
	successes := 0
	for i := 0; i < attempts; i++ {
		if err := <-results; err == nil {
			successes++
		}
	}
	close(release)
	wg.Wait()
	close(results)
	if successes != 1 {
		t.Fatalf("exactly one Windows CREATE_NEW reservation must win; got %d", successes)
	}
	if _, err := os.Lstat(filepath.Join(dir, nativeCreationJournalName)); err != nil {
		t.Fatalf("exclusive journal disappeared: %v", err)
	}
}

func TestWindowsCreationJournalHandleHasNoFileShareUntilClose(t *testing.T) {
	dir := t.TempDir()
	sink := newWindowsCreationSinkForIsolatedTests(dir)
	if err := sink.ReserveNew(testInstallID); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, nativeCreationJournalName)
	reader, err := os.Open(path)
	if err == nil {
		_ = reader.Close()
		_ = sink.Close()
		t.Fatal("journal admitted concurrent filesystem reader while exclusive native handle was held")
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err = os.Open(path)
	if err != nil {
		t.Fatalf("journal should remain available as recovery evidence after close: %v", err)
	}
	_ = reader.Close()
}

func TestWindowsCreationJournalRejectsPreexistingFileReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "separate-evidence.bin")
	alias := filepath.Join(dir, nativeCreationJournalName)
	if err := os.WriteFile(target, []byte("sensitive previous evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("Windows symlink creation not available: %v", err)
	}
	sink := newWindowsCreationSinkForIsolatedTests(dir)
	if err := sink.ReserveNew(testInstallID); err == nil {
		_ = sink.Close()
		t.Fatal("CREATE_NEW accepted an existing reparse-point journal target")
	}
	_ = sink.Close()
	actual, err := os.ReadFile(target)
	if err != nil || string(actual) != "sensitive previous evidence" {
		t.Fatalf("reparse target was modified: %q %v", actual, err)
	}
}

func TestWindowsCreationJournalRetainedParentBlocksRename(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "journal-parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	sink := newWindowsCreationSinkForIsolatedTests(parent)
	if err := sink.ReserveNew(testInstallID); err != nil {
		t.Fatal(err)
	}
	moved := parent + "-moved"
	// Windows directory handle is opened without FILE_SHARE_DELETE. Neither
	// the directory nor its journal must be redirected during the transaction.
	if err := os.Rename(parent, moved); err == nil {
		_ = sink.Close()
		t.Fatal("open journal parent was renamed while native handle was retained")
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, moved); err != nil {
		t.Fatalf("test parent remained locked after native handle close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, nativeCreationJournalName)); err != nil {
		t.Fatalf("journal evidence was lost after completed handle release: %v", err)
	}
}
