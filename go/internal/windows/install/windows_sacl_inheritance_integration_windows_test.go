// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsSACLInheritanceRollbackIntegration is intentionally opt-in.
// It changes only a fresh Go test temporary directory, never FI governed roots.
// The test exercises the SAME named-SACL APIs used by Approval 2 and checks
// existing descendants after a full root-SACL round trip. It also checks that
// newly created children inherit the rule while the parent is configured.
// Run elevated with FI_SACL_INHERITANCE_INTEGRATION=1.
func TestWindowsSACLInheritanceRollbackIntegration(t *testing.T) {
	if os.Getenv("FI_SACL_LEGACY_ROLLBACK_DIAGNOSTIC") != "1" {
		t.Skip("legacy unsupported byte-exact rollback diagnostic: set FI_SACL_LEGACY_ROLLBACK_DIAGNOSTIC=1")
	}

	root := t.TempDir()
	child := filepath.Join(root, "existing-child")
	nested := filepath.Join(child, "nested")
	existingFile := filepath.Join(nested, "existing-before-install.txt")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existingFile, []byte("baseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	paths := []string{root, child, nested, existingFile}
	baseline := make(map[string]fiSACLSnapshot, len(paths))
	for _, path := range paths {
		snapshot, err := fiQueryRootSACL(path)
		if err != nil {
			t.Fatalf("capture original SACL %q (run as elevated administrator): %v", path, err)
		}
		baseline[path] = snapshot
	}
	previous := baseline[root]
	if previous.hasChange && previous.hasRead {
		t.Fatal("test root already meets both FI audit contracts; cannot exercise a genuine change")
	}

	// Register restoration BEFORE the first mutation, including API failures.
	restored := false
	t.Cleanup(func() {
		if !restored {
			if err := fiSetRootSACL(root, previous.originalSDDL, previous.protected); err != nil {
				t.Errorf("emergency cleanup could not restore test root SACL %q: %v", root, err)
			}
		}
	})

	desired, err := fiSACLWithRequired(previous.originalSDDL, !previous.hasChange, !previous.hasRead)
	if err != nil {
		t.Fatalf("construct temporary SACL: %v", err)
	}
	if err := fiSetRootSACL(root, desired, previous.protected); err != nil {
		t.Fatalf("set temporary test root SACL: %v", err)
	}
	installedRoot, err := fiQueryRootSACL(root)
	if err != nil {
		t.Fatalf("verify temporary root SACL: %v", err)
	}
	if !installedRoot.hasChange || !installedRoot.hasRead || installedRoot.protected != previous.protected {
		t.Fatalf("temporary root did not acquire both FI audit contracts without changing SACL protection")
	}

	existingDescendantChanged := false
	for _, path := range paths[1:] {
		after, err := fiQueryRootSACL(path)
		if err != nil {
			t.Fatalf("inspect existing descendant %q after root mutation: %v", path, err)
		}
		if after.originalSDDL != baseline[path].originalSDDL {
			existingDescendantChanged = true
		}
	}

	createdWhileEnabled := filepath.Join(nested, "created-during-install.txt")
	if err := os.WriteFile(createdWhileEnabled, []byte("new file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newFileSACL, err := fiQueryRootSACL(createdWhileEnabled)
	if err != nil {
		t.Fatalf("inspect newly created descendant: %v", err)
	}
	// The file created during the temporary policy is retained until rollback
	// so it can be compared with a sibling created AFTER rollback.
	t.Logf("new descendant after FI SACL: SDDL length=%d", len(newFileSACL.originalSDDL))
	t.Logf("existing descendant SACL propagation detected=%t", existingDescendantChanged)

	if err := fiSetRootSACL(root, previous.originalSDDL, previous.protected); err != nil {
		t.Fatalf("restore original test root SACL: %v", err)
	}
	restored = true

	// A root-only rollback must restore ALL existing descendants, not merely
	// the governing root. A mismatch is a release blocker, not a test skip.
	for _, path := range paths {
		after, err := fiQueryRootSACL(path)
		if err != nil {
			t.Fatalf("reinspect SACL after rollback %q: %v", path, err)
		}
		before := baseline[path]
		if after.originalSDDL != before.originalSDDL || after.protected != before.protected {
			t.Errorf("SACL ROLLBACK INCOMPLETE for %q: before_protected=%t after_protected=%t before_sddl=%q after_sddl=%q", path, before.protected, after.protected, before.originalSDDL, after.originalSDDL)
		}
	}
	// A file created while FI auditing was enabled must not retain a stray
	// inherited rule after rollback. Compare with its post-rollback sibling.
	newFileAfterRollback, err := fiQueryRootSACL(createdWhileEnabled)
	if err != nil {
		t.Fatalf("inspect previously created descendant after rollback: %v", err)
	}
	createdAfterRollback := filepath.Join(nested, "created-after-rollback.txt")
	if err := os.WriteFile(createdAfterRollback, []byte("new file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	siblingAfterRollback, err := fiQueryRootSACL(createdAfterRollback)
	if err != nil {
		t.Fatalf("inspect post-rollback sibling: %v", err)
	}
	if newFileAfterRollback.originalSDDL != siblingAfterRollback.originalSDDL || newFileAfterRollback.protected != siblingAfterRollback.protected {
		t.Errorf("SACL ROLLBACK INCOMPLETE for child created during audit mutation: before_created_sddl=%q after_created_sddl=%q", newFileAfterRollback.originalSDDL, siblingAfterRollback.originalSDDL)
	}
	if !existingDescendantChanged {
		t.Error("new inheritable audit rules did not propagate to any existing child; existing-file auditing requires further validation")
	}
	if !strings.Contains(installedRoot.originalSDDL, "S:") {
		t.Error("installed root did not serialize an explicit SACL descriptor")
	}
}
