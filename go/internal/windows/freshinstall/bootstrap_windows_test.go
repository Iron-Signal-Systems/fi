// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectedBootstrapCreationDescriptorIsExactPolicy(t *testing.T) {
	descriptor, err := windows.SecurityDescriptorFromString(nativeBootstrapSDDL)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := journalParentSecurityFromDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJournalParentSecurity(observed); err != nil {
		t.Fatalf("creation-time protected ACL does not match installed journal-parent policy: %+v: %v", observed, err)
	}
	if observed.OwnerSID != journalAdministratorsSID || !observed.DACLProtected {
		t.Fatalf("bootstrap descriptor has unexpected owner or inheritance: %+v", observed)
	}
}

func TestProtectedBootstrapRefusesPreexistingDirectoryWithoutModification(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, nativeBootstrapDirectoryName)
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(child, "retain-prior-evidence.bin")
	if err := os.WriteFile(evidence, []byte("prior FI state must remain"), 0600); err != nil {
		t.Fatal(err)
	}
	reservation, err := reserveProtectedBootstrap(parent)
	if reservation != nil || !errors.Is(err, ErrBootstrapAlreadyExists) {
		if reservation != nil {
			_ = reservation.Close()
		}
		t.Fatalf("existing FI bootstrap was reused: reservation=%v error=%v", reservation, err)
	}
	found, err := os.ReadFile(evidence)
	if err != nil || string(found) != "prior FI state must remain" {
		t.Fatalf("existing installation evidence was modified: %q %v", found, err)
	}
}

func TestProtectedBootstrapRefusesUnsafeParentsBeforeCreate(t *testing.T) {
	parent := t.TempDir()
	for _, path := range []string{
		"", ".", "FI-Installer", filepath.Join(parent, "absent"),
		filepath.Join(parent, nativeBootstrapDirectoryName),
		filepath.VolumeName(parent) + `\`,
	} {
		res, err := reserveProtectedBootstrap(path)
		if res != nil {
			_ = res.Close()
		}
		if err == nil {
			t.Fatalf("unsafe bootstrap parent accepted: %q", path)
		}
	}
	if _, err := os.Stat(filepath.Join(parent, nativeBootstrapDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe parent attempts created bootstrap: %v", err)
	}
}

func TestProtectedBootstrapRefusesAncestorReparsePoint(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "real")
	alias := filepath.Join(root, "alias")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, alias); err != nil {
		t.Skipf("Windows runner cannot create test reparse alias: %v", err)
	}
	res, err := reserveProtectedBootstrap(alias)
	if res != nil {
		_ = res.Close()
	}
	if err == nil {
		t.Fatal("bootstrap created beneath a reparse parent")
	}
	if _, err := os.Lstat(filepath.Join(actual, nativeBootstrapDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reparse parent caused unintended child creation: %v", err)
	}
}

func nativeBootstrapFixture(t *testing.T) (*windowsBootstrapReservation, string) {
	t.Helper()
	parent := t.TempDir()
	res, err := reserveProtectedBootstrap(parent)
	if err != nil {
		// The security descriptor requests BUILTIN Administrators ownership.
		// This may require an elevated token on a particular runner. Lack
		// of that token is not permission for weaker fallback ACLs. Any
		// created in-doubt artifact is a TEST FAILURE, never an accepted skip.
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
			errors.Is(err, windows.ERROR_INVALID_OWNER) ||
			errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			if _, statErr := os.Lstat(filepath.Join(parent, nativeBootstrapDirectoryName)); errors.Is(statErr, os.ErrNotExist) {
				t.Skipf("Windows runner has insufficient privileges for exact owner-at-create policy: %v", err)
			}
		}
		t.Fatalf("cannot create exact protected FI-Installer fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := res.Close(); err != nil {
			t.Errorf("release retained protected bootstrap handles: %v", err)
		}
	})
	return res, parent
}

func TestProtectedBootstrapNativeCreationIsVerifiedAndRetained(t *testing.T) {
	res, parent := nativeBootstrapFixture(t)
	want := filepath.Join(parent, nativeBootstrapDirectoryName)
	if res.path != want {
		t.Fatalf("bootstrap returned wrong exact child path: got=%q want=%q", res.path, want)
	}
	if res.parent == 0 || res.child == 0 {
		t.Fatal("native parent and child handles were not retained")
	}
	if err := verifyJournalParentHandle(res.child); err != nil {
		t.Fatalf("created native directory is not protected: %v", err)
	}
	if err := res.verifyRetained(); err != nil {
		t.Fatalf("newly created native reservation was not stable: %v", err)
	}
	// CREATE_NEW with an existing protected directory must NEVER adopt it.
	retry, err := reserveProtectedBootstrap(parent)
	if retry != nil || !errors.Is(err, ErrBootstrapAlreadyExists) {
		if retry != nil {
			_ = retry.Close()
		}
		t.Fatalf("bootstrap was reused on second attempt: %v", err)
	}
	// The Windows runner has demonstrated that an open directory HANDLE
	// with no FILE_SHARE_DELETE may still admit os.Rename. Do not pretend
	// the requested sharing mode is a path pin; assert the original native
	// identity is no longer accepted if that rename succeeds.
	renameErr := os.Rename(want, want+"-moved")
	if renameErr == nil {
		if err := res.verifyRetained(); !errors.Is(err, ErrBootstrapInDoubt) {
			t.Fatalf("renamed native bootstrap was accepted under the original path: %v", err)
		}
	} else if err := res.verifyRetained(); err != nil {
		t.Fatalf("failed Windows rename destabilized retained reservation: %v", err)
	}
}

func TestProtectedBootstrapCanHostStrictNativeCreationJournal(t *testing.T) {
	res, _ := nativeBootstrapFixture(t)
	sink := newWindowsCreationSink(res.path) // no test-only DACL bypass
	if err := sink.ReserveNew(testInstallID); err != nil {
		_ = sink.Close()
		t.Fatalf("bootstrap did not satisfy native journal parent/file ACL contract: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(res.path, nativeCreationJournalName)); err != nil {
		t.Fatalf("protected creation journal missing: %v", err)
	}
}

func TestProtectedBootstrapConcurrentCreateExactlyOneWinner(t *testing.T) {
	// First prove that this Windows runner permits exact protected owner-at-
	// creation semantics. A runner without that privilege cannot validate
	// concurrent successful creation and must never use a weaker ACL.
	_, _ = nativeBootstrapFixture(t)
	parent := t.TempDir()
	const n = 8
	var wg sync.WaitGroup
	results := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := reserveProtectedBootstrap(parent)
			if res != nil {
				err = errors.Join(err, res.Close())
			}
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins, collisions := 0, 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrBootstrapAlreadyExists):
			collisions++
		default:
			t.Fatalf("unexpected native concurrent bootstrap result: %v", err)
		}
	}
	if wins != 1 || collisions != n-1 {
		t.Fatalf("native CREATE_NEW bootstrap did not exclude competing creators: winners=%d collisions=%d", wins, collisions)
	}
}
