// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsSACLJournalChecksumDetectsTampering(t *testing.T) {
	journal := fiSACLJournal{
		Version:       fiSACLJournalVersion,
		TransactionID: "20261016T090000.000000000Z",
		Roots:         []string{`C:\FI-Test`},
		Entries:       []fiSACLJournalEntry{{Path: `C:\FI-Test`, SDDL: "S:"}},
	}
	before, err := fiSACLJournalChecksum(journal)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	var restored fiSACLJournal
	if err := json.Unmarshal(payload, &restored); err != nil {
		t.Fatal(err)
	}
	after, err := fiSACLJournalChecksum(restored)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("journal checksum changed on JSON round trip")
	}
	restored.Entries[0].SDDL = "S:P"
	changed, err := fiSACLJournalChecksum(restored)
	if err != nil {
		t.Fatal(err)
	}
	if changed == before {
		t.Fatal("journal checksum failed to detect descriptor modification")
	}
}

func TestWindowsSACLInterruptedTransactionBlocksPlan(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "FI", "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ProgramData", root)
	pending := filepath.Join(state, fiSACLJournalPrefix+"20261016T090000.000000000Z.json.incomplete")
	if err := os.WriteFile(pending, []byte("incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fiSACLEnsureNoPending(); err == nil {
		t.Fatal("incomplete rollback journal did not block a new mutation")
	}
	plan := &InstallPlan{}
	planWindowsSACL(plan, Report{WindowsAudit: WindowsAuditState{Known: true}})
	if !plan.HasBlockers() {
		t.Fatal("pending SACL transaction was not surfaced as a planner blocker")
	}
}

// Live opt-in test: no FI governed roots, installed paths or customer SACLs
// are touched. It intentionally uses the real Windows SACL inheritance API.
func TestWindowsSACLJournalSubtreeExactRollbackDiagnostic(t *testing.T) {
	if os.Getenv("FI_SACL_LEGACY_ROLLBACK_DIAGNOSTIC") != "1" {
		t.Skip("legacy byte-exact rollback is unsupported; diagnostic only, requires FI_SACL_LEGACY_ROLLBACK_DIAGNOSTIC=1")
	}
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	if err := os.MkdirAll(filepath.Join(programData, "FI", "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "governed")
	child := filepath.Join(root, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "object.txt"), []byte("baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := fiSACLCaptureTrees([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	initial := entries[fiSACLKey(root)]
	if initial.HasChange && initial.HasRead {
		t.Skip("temporary root already satisfies both audit contracts")
	}
	id := time.Now().UTC().Format("20060102T150405.000000000Z")
	path, err := fiSACLWriteJournal(id, []string{root}, entries)
	if err != nil {
		t.Fatal(err)
	}
	// A failed test must retain its journal until all exact preimages are
	// verified; a temporary test-only directory is removed by testing.T.
	t.Cleanup(func() {
		if _, err := os.Stat(path); err == nil {
			t.Logf("UNRESOLVED test rollback journal: %s", path)
		}
	})
	next, err := fiSACLWithRequired(initial.SDDL, !initial.HasChange, !initial.HasRead)
	if err != nil {
		t.Fatal(err)
	}
	if err := fiSetRootSACL(root, next, initial.Protected); err != nil {
		t.Fatal(err)
	}
	if err := fiSACLRestoreJournal(path); err != nil {
		// This is a hard failure, even if only auto-inheritance control
		// flags were normalized and audit ACEs appear equivalent.
		t.Fatalf("exact SACL subtree rollback failed: %v", err)
	}
	if err := fiSACLRemoveJournal(path); err != nil {
		t.Fatal(err)
	}
	if paths, err := fiSACLPendingJournalPaths(); err != nil || len(paths) != 0 {
		t.Fatalf("journal leaked after verified rollback: paths=%v err=%v", paths, err)
	}
	if strings.EqualFold(initial.SDDL, "not_known") {
		t.Fatal("invalid baseline accepted")
	}
}

// The supported Approval 2 contract is retained, authorized audit state,
// not an impossible byte-exact reversal of a previously absent SACL.
func TestWindowsSACLPersistentApprovedPrerequisiteIntegration(t *testing.T) {
	if os.Getenv("FI_SACL_INHERITANCE_INTEGRATION") != "1" {
		t.Skip("opt-in live Windows audit prerequisite test")
	}
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	if err := os.MkdirAll(filepath.Join(programData, "FI", "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "governed")
	child := filepath.Join(root, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(child, "old.txt")
	if err := os.WriteFile(object, []byte("baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Verify the persistent SACL mutation does not rewrite the DACL.
	getDACL := func(path string) string {
		d, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return d.String()
	}
	beforeDACL := map[string]string{root: getDACL(root), child: getDACL(child), object: getDACL(object)}
	protectedChild := filepath.Join(root, "protected")
	if err := os.MkdirAll(protectedChild, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fiSetRootSACL(protectedChild, "S:P(AU;OICISAFA;0x00000020;;;SY)", true); err != nil {
		t.Fatal(err)
	}
	protectedBefore, err := fiQueryRootSACL(protectedChild)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := fiQueryRootSACL(root)
	if err != nil {
		t.Fatal(err)
	}
	if initial.hasChange && initial.hasRead {
		t.Skip("test directory already audited")
	}
	plan := InstallPlan{Actions: []PlanAction{{
		Action: planActionReconcile, Authority: "WINDOWS SACL", Target: root,
		Detail: "prior_sacl_sha256=" + initial.sha256,
	}}}
	if err := applyApproval2WindowsSACL(plan); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, child, object} {
		state, err := fiQueryRootSACL(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(state.auditACEs) == 0 {
			t.Errorf("auditing did not inherit to %q", path)
		}
	}
	for path, before := range beforeDACL {
		if after := getDACL(path); after != before {
			t.Errorf("DACL modified by FI SACL reconcile at %s: before=%q after=%q", path, before, after)
		}
	}
	if err := fiVerifySACLRollback(protectedBefore); err != nil {
		t.Errorf("protected unrelated child SACL changed: %v", err)
	}
	final, err := fiQueryRootSACL(root)
	if err != nil {
		t.Fatal(err)
	}
	if !final.hasChange || !final.hasRead || final.protected != initial.protected {
		t.Fatal("durable FI audit prerequisites not installed")
	}
	// A plan sealed before the first mutation is stale after success.
	if err := applyApproval2WindowsSACL(plan); err == nil {
		t.Fatal("stale approved preimage accepted after root mutation")
	}
	// Rediscovery produces a NO_CHANGE action; no new mutation is required.
	if err := applyApproval2WindowsSACL(InstallPlan{Actions: []PlanAction{{
		Action: planActionNoChange, Authority: "WINDOWS SACL", Target: root,
	}}}); err != nil {
		t.Fatal(err)
	}
	paths, err := fiSACLPendingJournalPaths()
	if err != nil || len(paths) != 0 {
		t.Fatalf("durable prerequisite created a rollback journal: paths=%v err=%v", paths, err)
	}
}

// Approval is sealed over all governed roots. A stale second root must block
// the transaction BEFORE a first root is changed.
func TestWindowsSACLPersistentMultiRootPreflightIntegration(t *testing.T) {
	if os.Getenv("FI_SACL_INHERITANCE_INTEGRATION") != "1" {
		t.Skip("opt-in live Windows approval preflight test")
	}
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	if err := os.MkdirAll(filepath.Join(programData, "FI", "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	a, b := filepath.Join(base, "A"), filepath.Join(base, "B")
	for _, path := range []string{a, b} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// B has an unrelated explicit SYSTEM audit ACE; FI must preserve it.
	if err := fiSetRootSACL(b, "S:(AU;OICISAFA;0x00000020;;;SY)", false); err != nil {
		t.Fatal(err)
	}
	first, err := fiQueryRootSACL(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fiQueryRootSACL(b)
	if err != nil {
		t.Fatal(err)
	}
	if first.hasChange && first.hasRead {
		t.Skip("test root already has coverage")
	}
	plan := InstallPlan{Actions: []PlanAction{
		{Action: planActionReconcile, Authority: "WINDOWS SACL", Target: a, Detail: "prior_sacl_sha256=" + first.sha256},
		{Action: planActionReconcile, Authority: "WINDOWS SACL", Target: b, Detail: "prior_sacl_sha256=definitely-stale"},
	}}
	if err := applyApproval2WindowsSACL(plan); err == nil {
		t.Fatal("stale second root accepted")
	}
	current, err := fiQueryRootSACL(a)
	if err != nil {
		t.Fatal(err)
	}
	if current.sha256 != first.sha256 {
		t.Fatal("first root changed before second root preflight completed")
	}
	plan.Actions[1].Detail = "prior_sacl_sha256=" + second.sha256
	if err := applyApproval2WindowsSACL(plan); err != nil {
		t.Fatalf("valid multi-root approval failed: %v", err)
	}
	finalB, err := fiQueryRootSACL(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(finalB.auditACEs) < len(second.auditACEs)+1 {
		t.Fatal("unrelated audit ACE was lost after persistent FI SACL reconciliation")
	}
	for _, oldACE := range second.auditACEs {
		found := false
		for _, installed := range finalB.auditACEs {
			if installed == oldACE {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("unrelated audit ACE changed during persistent FI SACL reconcile")
		}
	}
}
