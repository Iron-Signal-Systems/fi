// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testBinaryUpdatePlan(t *testing.T) (applicationBinaryPlan, string) {
	t.Helper()
	directory := t.TempDir()
	prior := t.TempDir()
	// FreeBSD may inherit the parent directory's group.
	// Match the test process identity without relaxing production checks.
	if err := os.Chown(prior, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(prior, 0o700); err != nil {
		t.Fatal(err)
	}
	files := make([]applicationBinaryFileSpec, 0, 2)
	for _, name := range []string{"fi-receiver", "fi-ingest-worker"} {
		target := filepath.Join(directory, name)
		spec := applicationBinaryTestSpec(target)
		spec.Role = name
		spec.Content = []byte("new-" + name)
		if err := os.WriteFile(target, []byte("old-"+name), 0o555); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(prior, name), []byte("old-"+name), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, spec)
	}
	return applicationBinaryPlan{Files: files}, prior
}

func TestUpdateApplicationBinaryPlanAndRetry(t *testing.T) {
	plan, prior := testBinaryUpdatePlan(t)
	checks := 0
	stopped := func() error { checks++; return nil }
	if err := updateApplicationBinaryPlan(plan, prior, stopped); err != nil {
		t.Fatal(err)
	}
	if checks < 2 {
		t.Fatal("service quiescence not rechecked")
	}
	if err := verifyApplicationBinaryPlan(plan); err != nil {
		t.Fatal(err)
	}
	if err := updateApplicationBinaryPlan(plan, prior, stopped); err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
}

func TestUpdateApplicationBinaryPlanRejectsWrongPriorBeforeMutation(t *testing.T) {
	plan, prior := testBinaryUpdatePlan(t)
	if err := os.WriteFile(filepath.Join(prior, "fi-ingest-worker"), []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateApplicationBinaryPlan(plan, prior, func() error { return nil }); err == nil {
		t.Fatal("wrong approved prior was accepted")
	}
	content, err := os.ReadFile(plan.Files[0].Target)
	if err != nil || string(content) != "old-fi-receiver" {
		t.Fatal("first binary changed despite complete-layer rejection")
	}
}

func TestUpdateApplicationBinaryPlanRejectsRunningService(t *testing.T) {
	plan, prior := testBinaryUpdatePlan(t)
	if err := updateApplicationBinaryPlan(plan, prior, func() error { return errors.New("running") }); err == nil {
		t.Fatal("running service was accepted")
	}
	for _, spec := range plan.Files {
		content, err := os.ReadFile(spec.Target)
		if err != nil || string(content) != "old-"+spec.Role {
			t.Fatal("binary mutated while service running")
		}
	}
}

func TestUpdateApplicationBinaryPlanRejectsPriorSymlink(t *testing.T) {
	plan, prior := testBinaryUpdatePlan(t)
	target := filepath.Join(prior, "fi-receiver")
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(prior, "fi-ingest-worker"), target); err != nil {
		t.Fatal(err)
	}
	if err := updateApplicationBinaryPlan(plan, prior, func() error { return nil }); err == nil {
		t.Fatal("prior symlink was accepted")
	}
}
