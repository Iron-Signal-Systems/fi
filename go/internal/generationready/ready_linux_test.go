// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package generationready

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishReadAndRemove(t *testing.T) {
	root := t.TempDir()
	name := "generation-0123456789abcdef.record.json"

	first, err := Publish(root, name)
	if err != nil {
		t.Fatal(err)
	}
	if first.Disposition != PublishDispositionNew {
		t.Fatalf("first disposition = %q, want NEW", first.Disposition)
	}

	second, err := Publish(root, name)
	if err != nil {
		t.Fatal(err)
	}
	if second.Disposition != PublishDispositionAlreadyPresent {
		t.Fatalf(
			"second disposition = %q, want ALREADY_PRESENT",
			second.Disposition,
		)
	}

	names, err := ReadReceiptNames(root, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != name {
		t.Fatalf("ready names = %#v, want [%q]", names, name)
	}

	if err := RemoveReceiptNames(root, names); err != nil {
		t.Fatal(err)
	}

	names, err = ReadReceiptNames(root, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("ready names after removal = %#v, want empty", names)
	}
}

func TestReadReceiptNamesIsBounded(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < 5; index++ {
		name := filepath.Base(
			"generation-" + string(rune('a'+index)) + ".record.json",
		)
		if _, err := Publish(root, name); err != nil {
			t.Fatal(err)
		}
	}

	names, err := ReadReceiptNames(root, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("bounded ready names = %d, want 2", len(names))
	}
}

func TestReadReceiptNamesRejectsNonMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "unexpected"),
		nil,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadReceiptNames(root, 64); err == nil {
		t.Fatal("non-marker ready entry was accepted")
	}
}

func TestPublishRejectsNonReceiptBasename(t *testing.T) {
	root := t.TempDir()
	if _, err := Publish(root, "../generation-bad.record.json"); err == nil {
		t.Fatal("non-basename ready name was accepted")
	}
}

func TestReceiptNamePresent(t *testing.T) {
	root := t.TempDir()
	name := "generation-0123456789abcdef.record.json"

	present, err := ReceiptNamePresent(root, name)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("missing ready marker reported present")
	}

	if _, err := Publish(root, name); err != nil {
		t.Fatal(err)
	}

	present, err = ReceiptNamePresent(root, name)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("published ready marker reported missing")
	}
}
