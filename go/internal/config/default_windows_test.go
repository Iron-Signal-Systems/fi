// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultPath(t *testing.T) {
	t.Setenv("ProgramData", `C:\ProgramData`)

	path, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	want := `C:\ProgramData\FI\config\fi.conf`
	if path != want {
		t.Fatalf("default path = %q, want %q", path, want)
	}
}

func TestDefaultPathRequiresProgramData(t *testing.T) {
	t.Setenv("ProgramData", "")
	_, err := DefaultPath()
	if err == nil || !strings.Contains(err.Error(), "ProgramData is not set") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadDefault(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)

	path := filepath.Join(programData, "FI", "config", "fi.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	content := "version_id: 1.0\ngoverned_root: D:\\Shares\\Finance\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	value, loadedPath, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != path {
		t.Fatalf("loaded path = %q, want %q", loadedPath, path)
	}
	if len(value.GovernedRoots) != 1 || value.GovernedRoots[0] != `D:\Shares\Finance` {
		t.Fatalf("loaded config = %#v", value)
	}
}
