// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fi.conf")
	content := "version_id: 1.0\ngoverned_root: D:\\Shares\\Finance\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	value, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.VersionID != Version1 || len(value.GovernedRoots) != 1 {
		t.Fatalf("loaded config = %#v", value)
	}
}

func TestParseVersion1(t *testing.T) {
	input := `# FI configuration
version_id: 1.0

# Finance data
governed_root: D:\Shares\Finance

# HR
governed_root: D:\Shares\HR
`

	value, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if value.VersionID != "1.0" {
		t.Fatalf("version_id = %q, want 1.0", value.VersionID)
	}
	if len(value.GovernedRoots) != 2 {
		t.Fatalf("governed roots = %d, want 2", len(value.GovernedRoots))
	}
	if value.GovernedRoots[0] != `D:\Shares\Finance` {
		t.Fatalf("first governed root = %q", value.GovernedRoots[0])
	}
	if value.GovernedRoots[1] != `D:\Shares\HR` {
		t.Fatalf("second governed root = %q", value.GovernedRoots[1])
	}
}

func TestParseAcceptsUTF8BOM(t *testing.T) {
	input := "\uFEFF# FI configuration\nversion_id: 1.0\ngoverned_root: D:\\Shares\\Finance\n"
	value, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if value.VersionID != Version1 {
		t.Fatalf("version_id = %q, want %q", value.VersionID, Version1)
	}
}

func TestParseRequiresVersionFirst(t *testing.T) {
	input := "governed_root: D:\\Shares\\Finance\nversion_id: 1.0\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "first directive must be version_id") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRejectsUnsupportedVersion(t *testing.T) {
	input := "version_id: 2.0\ngoverned_root: D:\\Shares\\Finance\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "unsupported version_id") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRequiresGovernedRoot(t *testing.T) {
	_, err := Parse(strings.NewReader("version_id: 1.0\n"))
	if err == nil || !strings.Contains(err.Error(), "at least one governed_root is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRejectsUnknownDirective(t *testing.T) {
	input := "version_id: 1.0\ngoverned_roots: D:\\Shares\\Finance\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), `unknown directive "governed_roots"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRejectsDuplicateRootCaseInsensitive(t *testing.T) {
	input := "version_id: 1.0\ngoverned_root: D:\\Shares\\Finance\ngoverned_root: d:\\shares\\finance\\\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "duplicate governed_root") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRejectsRelativeRoot(t *testing.T) {
	input := "version_id: 1.0\ngoverned_root: Shares\\Finance\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "absolute local Windows path") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRejectsUNC(t *testing.T) {
	input := "version_id: 1.0\ngoverned_root: \\\\server\\share\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "absolute local Windows path") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRejectsForwardSlashes(t *testing.T) {
	input := "version_id: 1.0\ngoverned_root: D:/Shares/Finance\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRejectsParentTraversal(t *testing.T) {
	input := "version_id: 1.0\ngoverned_root: D:\\Shares\\..\\Finance\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "must not contain '.' or '..' segments") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRejectsDuplicateVersion(t *testing.T) {
	input := "version_id: 1.0\nversion_id: 1.0\ngoverned_root: D:\\Shares\\Finance\n"
	_, err := Parse(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "duplicate version_id") {
		t.Fatalf("error = %v", err)
	}
}
