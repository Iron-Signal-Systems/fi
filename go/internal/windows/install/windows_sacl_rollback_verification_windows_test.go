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

// Synthetic tests cannot prove NTFS inheritance, but they ensure the verifier
// fails closed on unobservable or missing rollback state.
func TestWindowsSACLRollbackVerificationRejectsUnreadableTarget(t *testing.T) {
	expected := fiSACLSnapshot{path: filepath.Join(t.TempDir(), "deleted-object")}
	if err := fiVerifySACLRollback(expected); err == nil {
		t.Fatal("missing SACL target accepted as restored")
	}
}

// An opt-in live test checks rollback of a preexisting unrelated audit ACE and
// protected subtree. This covers the preexisting-ACE case absent from 3E2.
func TestWindowsSACLRollbackVerificationMixedTreeIntegration(t *testing.T) {
	if os.Getenv("FI_SACL_LEGACY_ROLLBACK_DIAGNOSTIC") != "1" {
		t.Skip("legacy unsupported byte-exact rollback diagnostic: set FI_SACL_LEGACY_ROLLBACK_DIAGNOSTIC=1")
	}

	root := t.TempDir()
	openChild := filepath.Join(root, "open-child")
	protectedChild := filepath.Join(root, "protected-child")
	protectedFile := filepath.Join(protectedChild, "protected.txt")
	openFile := filepath.Join(openChild, "open.txt")
	if err := os.Mkdir(openChild, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(protectedChild, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protectedFile, []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openFile, []byte("open"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Explicit SYSTEM audit ACE survives FI's root inheritance transaction.
	if err := fiSetRootSACL(openChild, "S:(AU;OICISAFA;0x00000002;;;SY)", false); err != nil {
		t.Fatal(err)
	}
	// Protected child intentionally must not acquire FI's parent audit ACEs.
	if err := fiSetRootSACL(protectedChild, "S:P(AU;OICISAFA;0x00000020;;;SY)", true); err != nil {
		t.Fatal(err)
	}
	paths := []string{root, openChild, openFile, protectedChild, protectedFile}
	baseline := map[string]fiSACLSnapshot{}
	for _, path := range paths {
		state, err := fiQueryRootSACL(path)
		if err != nil {
			t.Fatal(err)
		}
		baseline[path] = state
	}
	if len(baseline[openChild].auditACEs) == 0 || len(baseline[protectedChild].auditACEs) == 0 {
		t.Fatal("preexisting unrelated audit ACEs missing from fixture")
	}
	old := baseline[root]
	if old.hasChange && old.hasRead {
		t.Skip("temporary root already fully FI-audited")
	}
	changed := false
	restored := false
	t.Cleanup(func() {
		if changed && !restored {
			if err := fiSetRootSACL(root, old.originalSDDL, old.protected); err != nil {
				t.Errorf("emergency temporary-root cleanup: %v", err)
			}
		}
	})
	desired, err := fiSACLWithRequired(old.originalSDDL, !old.hasChange, !old.hasRead)
	if err != nil {
		t.Fatal(err)
	}
	changed = true
	if err := fiSetRootSACL(root, desired, old.protected); err != nil {
		t.Fatal(err)
	}
	duringOpen, err := fiQueryRootSACL(openChild)
	if err != nil {
		t.Fatal(err)
	}
	duringProtected, err := fiQueryRootSACL(protectedChild)
	if err != nil {
		t.Fatal(err)
	}
	if len(duringOpen.auditACEs) <= len(baseline[openChild].auditACEs) {
		t.Errorf("open child did not inherit new FI audit rules")
	}
	if len(duringProtected.auditACEs) != len(baseline[protectedChild].auditACEs) {
		t.Errorf("protected child unexpectedly inherited FI audit rules")
	}

	if err := fiSetRootSACL(root, old.originalSDDL, old.protected); err != nil {
		t.Fatal(err)
	}
	restored = true
	for _, path := range paths {
		if err := fiVerifySACLRollback(baseline[path]); err != nil {
			t.Errorf("rollback audit-ACE or protection failure: %v", err)
		}
		after, err := fiQueryRootSACL(path)
		if err != nil {
			t.Fatal(err)
		}
		if baseline[path].originalSDDL != after.originalSDDL {
			t.Logf("SACL descriptor normalization for %q: before=%q after=%q", path, baseline[path].originalSDDL, after.originalSDDL)
		}
	}
	if !strings.Contains(old.originalSDDL+desired, fiChangeACE) {
		t.Fatal("temporary source did not exercise FI change-audit mutation")
	}
}
