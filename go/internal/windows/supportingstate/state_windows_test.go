// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package supportingstate

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestSaveLoadAndMerge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supporting.json")

	initial, err := New(
		"SERVER1",
		"server1.example.test",
		"example.test",
		"S-1-5-21-1-2-3",
		[]string{
			"S-1-5-21-1-2-3-1100",
			"S-1-5-21-1-2-3-1200",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(path, initial); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	merged, err := Merge(
		path,
		loaded,
		[]string{
			"S-1-5-21-1-2-3-1200",
			"S-1-5-21-1-2-3-1300",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"S-1-5-21-1-2-3-1100",
		"S-1-5-21-1-2-3-1200",
		"S-1-5-21-1-2-3-1300",
	}
	if !reflect.DeepEqual(merged.RelevantSIDs, want) {
		t.Fatalf("relevant SIDs = %#v, want %#v", merged.RelevantSIDs, want)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.RelevantSIDs, want) {
		t.Fatalf("reloaded relevant SIDs = %#v, want %#v", reloaded.RelevantSIDs, want)
	}
}

func TestNewRejectsOtherDomainSID(t *testing.T) {
	_, err := New(
		"SERVER1",
		"server1.example.test",
		"example.test",
		"S-1-5-21-1-2-3",
		[]string{"S-1-5-21-9-8-7-1100"},
	)
	if err == nil {
		t.Fatal("expected other-domain SID rejection")
	}
}
