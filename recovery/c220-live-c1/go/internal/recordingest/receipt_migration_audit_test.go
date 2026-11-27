// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestM1ReceiptMigrationAccounting238(t *testing.T) {
	if os.Getenv("FI_M1_NAMESPACE_READ_TEST") != "1" {
		t.Skip("verified M1 receipt fixture not requested")
	}

	base := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-receipts-20261012",
	)

	report, err := AuditRecordedReceiptMigration(
		filepath.Join(base, "flat"),
		filepath.Join(base, "namespaced"),
		[]string{
			"iss-fs-2019.iss.local",
			"iss-fs-22.iss.local",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if report.Legacy != 238 ||
		report.Namespaced != 238 ||
		report.BySource["iss-fs-2019.iss.local"] != 104 ||
		report.BySource["iss-fs-22.iss.local"] != 134 {
		t.Fatalf("unexpected migration report: %+v", report)
	}

	t.Logf(
		"PASS: legacy=%d namespaced=%d FS2019=%d FS22=%d",
		report.Legacy,
		report.Namespaced,
		report.BySource["iss-fs-2019.iss.local"],
		report.BySource["iss-fs-22.iss.local"],
	)
}

func TestM1ReceiptMigrationAccountingFailureCases(t *testing.T) {
	if os.Getenv("FI_M1_NAMESPACE_READ_TEST") != "1" {
		t.Skip("verified M1 receipt fixture not requested")
	}

	const (
		fs19 = "iss-fs-2019.iss.local"
		fs22 = "iss-fs-22.iss.local"
	)

	base := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-receipts-20261012",
		"namespaced",
		"sources",
	)

	root := t.TempDir()
	flat := filepath.Join(root, "flat")
	named := filepath.Join(root, "named")
	parent := filepath.Join(named, "sources")

	for _, directory := range []string{
		flat,
		named,
		parent,
		filepath.Join(parent, fs19),
		filepath.Join(parent, fs22),
	} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}

	originals := make(map[string]string)

	for _, source := range []string{fs19, fs22} {
		entries, err := os.ReadDir(filepath.Join(base, source))
		if err != nil || len(entries) == 0 {
			t.Fatalf("source fixture %s unavailable: %v", source, err)
		}

		name := entries[0].Name()
		raw, err := os.ReadFile(
			filepath.Join(base, source, name),
		)
		if err != nil {
			t.Fatal(err)
		}

		original := filepath.Join(flat, name)
		linked := filepath.Join(parent, source, name)

		if err := os.WriteFile(original, raw, 0400); err != nil {
			t.Fatal(err)
		}

		if err := os.Link(original, linked); err != nil {
			t.Fatal(err)
		}

		originals[source] = name
	}

	audit := func() error {
		_, err := AuditRecordedReceiptMigration(
			flat,
			named,
			[]string{fs19, fs22},
		)
		return err
	}

	if err := audit(); err != nil {
		t.Fatalf("valid two-source migration failed: %v", err)
	}

	fs19Link := filepath.Join(
		parent, fs19, originals[fs19],
	)

	if err := os.Remove(fs19Link); err != nil {
		t.Fatal(err)
	}

	if err := audit(); err == nil {
		t.Fatal("missing namespaced receipt accepted")
	}

	if err := os.Link(
		filepath.Join(flat, originals[fs19]),
		fs19Link,
	); err != nil {
		t.Fatal(err)
	}

	misplaced := filepath.Join(
		parent, fs22, originals[fs19],
	)

	if err := os.Link(
		filepath.Join(flat, originals[fs19]),
		misplaced,
	); err != nil {
		t.Fatal(err)
	}

	if err := audit(); err == nil {
		t.Fatal("misplaced receipt accepted")
	}

	if err := os.Remove(misplaced); err != nil {
		t.Fatal(err)
	}

	fs22Link := filepath.Join(
		parent, fs22, originals[fs22],
	)

	if err := os.Remove(fs22Link); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(
		filepath.Join(flat, originals[fs22]),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(fs22Link, raw, 0400); err != nil {
		t.Fatal(err)
	}

	if err := audit(); err == nil {
		t.Fatal("separately copied receipt accepted without hard-link identity")
	}

	if err := os.Remove(fs22Link); err != nil {
		t.Fatal(err)
	}

	if err := os.Link(
		filepath.Join(flat, originals[fs22]),
		fs22Link,
	); err != nil {
		t.Fatal(err)
	}

	unexpected := filepath.Join(parent, fs19, "untracked.txt")

	if err := os.WriteFile(
		unexpected,
		[]byte("unexpected object"),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	if err := audit(); err == nil {
		t.Fatal("unexpected source object accepted")
	}

	if err := os.Remove(unexpected); err != nil {
		t.Fatal(err)
	}

	extraSource := filepath.Join(parent, "unregistered-source")

	if err := os.Mkdir(extraSource, 0700); err != nil {
		t.Fatal(err)
	}

	if err := audit(); err == nil {
		t.Fatal("unregistered source directory accepted")
	}

	if err := os.Remove(extraSource); err != nil {
		t.Fatal(err)
	}

	if err := audit(); err != nil {
		t.Fatalf("restored migration fixture failed: %v", err)
	}

	t.Log("PASS: Missing receipt rejected")
	t.Log("PASS: Misplaced receipt rejected")
	t.Log("PASS: Independent copy rejected")
	t.Log("PASS: Unexpected object rejected")
	t.Log("PASS: Unregistered source rejected")
	t.Log("PASS: Repaired fixture accounted for exactly")
}
