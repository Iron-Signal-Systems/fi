// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/auditpolicy"
	"golang.org/x/sys/windows"
)

// snapshotSACLAuditACEs captures the actual ACE bytes independently of
// serialization flags such as S:AI and S:AINO_ACCESS_CONTROL. It compares
// auditing entries only; it does NOT establish bit-exact descriptor rollback.
func snapshotSACLAuditACEs(path string) ([]string, error) {
	var result []string
	err := auditpolicy.WithSecurityPrivilege(func() error {
		descriptor, err := windows.GetNamedSecurityInfo(
			path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION,
		)
		if err != nil {
			return fmt.Errorf("get SACL %q: %w", path, err)
		}
		sacl, _, err := descriptor.SACL()
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return nil // absent SACL: no audit ACEs
		}
		if err != nil {
			return fmt.Errorf("decode SACL %q: %w", path, err)
		}
		if sacl == nil {
			return nil // null SACL: no audit ACEs
		}
		if sacl.AceCount > 4096 {
			return fmt.Errorf("unexpected ACE count %d at %q", sacl.AceCount, path)
		}
		for i := uint32(0); i < uint32(sacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(sacl, i, &ace); err != nil {
				return fmt.Errorf("get SACL ACE %d at %q: %w", i, path, err)
			}
			if ace == nil || ace.Header.AceSize < 4 {
				return fmt.Errorf("invalid SACL ACE %d at %q", i, path)
			}
			// GetAce points into the security descriptor's allocated SACL;
			// encode the bounded ACE so type, flags, mask and SID survive.
			value := unsafe.Slice(
				(*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize),
			)
			result = append(result, hex.EncodeToString(value))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(result)
	if result == nil {
		result = []string{}
	}
	return result, nil
}

// TestWindowsSACLAuditACEReconciliationIntegration is a separate diagnostic,
// NOT a substitute for TestWindowsSACLInheritanceRollbackIntegration.
// It determines whether the first test failed on leftover audit ACEs, or
// only on auto-inheritance descriptor normalization. It touches ONLY t.TempDir.
func TestWindowsSACLAuditACEReconciliationIntegration(t *testing.T) {
	if os.Getenv("FI_SACL_INHERITANCE_INTEGRATION") != "1" {
		t.Skip("opt-in test: FI_SACL_INHERITANCE_INTEGRATION=1")
	}

	root := t.TempDir()
	child := filepath.Join(root, "existing-child")
	nested := filepath.Join(child, "nested")
	oldFile := filepath.Join(nested, "old.txt")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldFile, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{root, child, nested, oldFile}
	before := make(map[string][]string, len(paths))
	beforeDescriptor := make(map[string]fiSACLSnapshot, len(paths))
	for _, path := range paths {
		value, err := snapshotSACLAuditACEs(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = value
		snapshot, err := fiQueryRootSACL(path)
		if err != nil {
			t.Fatal(err)
		}
		beforeDescriptor[path] = snapshot
	}
	baseline := beforeDescriptor[root]
	if baseline.hasChange && baseline.hasRead {
		t.Skip("test root already has full FI audit coverage")
	}

	mutated := false
	rolledBack := false
	t.Cleanup(func() {
		if mutated && !rolledBack {
			if err := fiSetRootSACL(root, baseline.originalSDDL, baseline.protected); err != nil {
				t.Errorf("emergency temporary-root SACL restore: %v", err)
			}
		}
	})

	desired, err := fiSACLWithRequired(
		baseline.originalSDDL, !baseline.hasChange, !baseline.hasRead,
	)
	if err != nil {
		t.Fatal(err)
	}
	mutated = true // set before calling Windows; partial changes still need cleanup
	if err := fiSetRootSACL(root, desired, baseline.protected); err != nil {
		t.Fatal(err)
	}
	installed, err := fiQueryRootSACL(root)
	if err != nil {
		t.Fatal(err)
	}
	if !installed.hasChange || !installed.hasRead {
		t.Fatal("FI audit ACEs not installed on temporary root")
	}

	propagated := false
	for _, path := range paths[1:] {
		value, err := snapshotSACLAuditACEs(path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(value, before[path]) {
			propagated = true
			t.Logf("audit ACE propagation verified at %q: before=%d during=%d", path, len(before[path]), len(value))
		}
	}
	if !propagated {
		t.Error("no existing descendant acquired any audit ACE; inheritance ineffective")
	}

	createdDuring := filepath.Join(nested, "created-while-audited.txt")
	if err := os.WriteFile(createdDuring, []byte("during"), 0o600); err != nil {
		t.Fatal(err)
	}
	duringACEs, err := snapshotSACLAuditACEs(createdDuring)
	if err != nil {
		t.Fatal(err)
	}
	if len(duringACEs) == 0 {
		t.Error("new descendant did not inherit any audit ACE")
	}

	if err := fiSetRootSACL(root, baseline.originalSDDL, baseline.protected); err != nil {
		t.Fatalf("restore temporary root SACL: %v", err)
	}
	rolledBack = true
	for _, path := range paths {
		after, err := snapshotSACLAuditACEs(path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(after, before[path]) {
			t.Errorf("AUDIT ACE RESIDUE at %q: before=%v after=%v", path, before[path], after)
		}
		state, err := fiQueryRootSACL(path)
		if err != nil {
			t.Fatal(err)
		}
		if state.protected != beforeDescriptor[path].protected {
			t.Errorf("SACL protection changed at %q", path)
		}
		if state.originalSDDL != beforeDescriptor[path].originalSDDL {
			t.Logf("DESCRIPTOR FORM CHANGED at %q: before=%q after=%q (not byte-exact rollback)",
				path, beforeDescriptor[path].originalSDDL, state.originalSDDL)
		}
	}

	createdAfter := filepath.Join(nested, "created-after-rollback.txt")
	if err := os.WriteFile(createdAfter, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldNewACEs, err := snapshotSACLAuditACEs(createdDuring)
	if err != nil {
		t.Fatal(err)
	}
	freshACEs, err := snapshotSACLAuditACEs(createdAfter)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oldNewACEs, freshACEs) {
		t.Errorf("AUDIT ACE RESIDUE in file created during install: during-file=%v post-rollback-file=%v", oldNewACEs, freshACEs)
	}
	if !reflect.DeepEqual(freshACEs, before[oldFile]) {
		t.Errorf("post-rollback new file audit ACEs differ from original sibling: old=%v new=%v", before[oldFile], freshACEs)
	}
	t.Log("NOTE: This test checks audit ACE semantics, NOT exact SACL descriptor restoration. The existing exact-rollback test remains authoritative for byte-for-byte rollback.")
}
