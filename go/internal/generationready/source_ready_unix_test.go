// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux || freebsd

package generationready

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceReadyQueuesAreIndependent(
	t *testing.T,
) {
	root := t.TempDir()

	sourceA := "iss-fs-19.iss.local"
	sourceB := "iss-fs-22.iss.local"

	nameA := "generation-aaaaaaaa.record.json"
	nameB := "generation-bbbbbbbb.record.json"

	if _, err := PublishForSource(
		root,
		sourceA,
		nameA,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := PublishForSource(
		root,
		sourceB,
		nameB,
	); err != nil {
		t.Fatal(err)
	}

	namesA, err := ReadReceiptNamesForSource(
		root,
		sourceA,
		64,
	)
	if err != nil {
		t.Fatal(err)
	}

	namesB, err := ReadReceiptNamesForSource(
		root,
		sourceB,
		64,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(namesA) != 1 ||
		namesA[0] != nameA {
		t.Fatalf(
			"source A READY names = %#v",
			namesA,
		)
	}

	if len(namesB) != 1 ||
		namesB[0] != nameB {
		t.Fatalf(
			"source B READY names = %#v",
			namesB,
		)
	}

	if err := RemoveReceiptNamesForSource(
		root,
		sourceA,
		namesA,
	); err != nil {
		t.Fatal(err)
	}

	namesA, err = ReadReceiptNamesForSource(
		root,
		sourceA,
		64,
	)
	if err != nil {
		t.Fatal(err)
	}

	namesB, err = ReadReceiptNamesForSource(
		root,
		sourceB,
		64,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(namesA) != 0 {
		t.Fatalf(
			"source A READY queue not empty: %#v",
			namesA,
		)
	}

	if len(namesB) != 1 ||
		namesB[0] != nameB {
		t.Fatalf(
			"source B READY queue changed: %#v",
			namesB,
		)
	}
}

func TestSourceReadyMissingQueueIsEmpty(
	t *testing.T,
) {
	root := t.TempDir()

	names, err := ReadReceiptNamesForSource(
		root,
		"iss-fs-22.iss.local",
		64,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(names) != 0 {
		t.Fatalf(
			"missing source READY queue = %#v, want empty",
			names,
		)
	}

	present, err := ReceiptNamePresentForSource(
		root,
		"iss-fs-22.iss.local",
		"generation-aaaaaaaa.record.json",
	)
	if err != nil {
		t.Fatal(err)
	}

	if present {
		t.Fatal(
			"missing source READY queue reported marker present",
		)
	}
}

func TestSourceReadyDirectoryContract(
	t *testing.T,
) {
	root := t.TempDir()
	sourceID := "iss-fs-22.iss.local"

	if _, err := PublishForSource(
		root,
		sourceID,
		"generation-aaaaaaaa.record.json",
	); err != nil {
		t.Fatal(err)
	}

	sourceRoot := filepath.Join(
		root,
		sourceID,
	)

	info, err := os.Lstat(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}

	if !info.IsDir() ||
		info.Mode().Perm() != 0o700 {
		t.Fatalf(
			"source READY directory mode = %04o",
			info.Mode().Perm(),
		)
	}
}

func TestSourceReadyRejectsUnsafeSourceID(
	t *testing.T,
) {
	root := t.TempDir()

	if _, err := PublishForSource(
		root,
		"../wrong",
		"generation-aaaaaaaa.record.json",
	); err == nil {
		t.Fatal(
			"unsafe READY source ID was accepted",
		)
	}
}
