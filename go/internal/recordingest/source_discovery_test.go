// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

func TestRecordedSourceDirectoryRejectsUnsafeIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recorded")

	for _, source := range []string{
		"",
		".",
		"..",
		"../escape",
		"source/child",
		`source\child`,
		"source\x00child",
	} {
		if _, err := generationrecorder.RecordedSourceDirectory(
			root,
			source,
		); err == nil {
			t.Errorf("unsafe source %q was accepted", source)
		}
	}

	if _, err := generationrecorder.RecordedSourceDirectory(
		"relative/recorded",
		"iss-fs-22.iss.local",
	); err == nil {
		t.Error("relative recorded root was accepted")
	}
}

func TestM1NamespacedSourceDiscovery(t *testing.T) {
	if os.Getenv("FI_M1_NAMESPACE_READ_TEST") != "1" {
		t.Skip("M1 namespaced fixture not requested")
	}

	root := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-receipts-20261012",
		"namespaced",
	)

	for _, item := range []struct {
		source string
		count  int
	}{
		{"iss-fs-2019.iss.local", 104},
		{"iss-fs-22.iss.local", 134},
	} {
		sourceRoot, err :=
			generationrecorder.RecordedSourceDirectory(
				root,
				item.source,
			)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := os.Lstat(sourceRoot); err != nil {
			t.Fatal(err)
		}

		receipts, err := DiscoverRecordedReceiptsForSource(
			root,
			item.source,
		)
		if err != nil {
			t.Fatal(err)
		}

		if len(receipts) != item.count {
			t.Fatalf(
				"source=%s receipts=%d want=%d",
				item.source,
				len(receipts),
				item.count,
			)
		}

		for _, receipt := range receipts {
			if receipt.SourceID != item.source {
				t.Fatalf(
					"source identity mismatch: %q",
					receipt.SourceID,
				)
			}
		}

		t.Logf(
			"PASS: source=%s receipts=%d",
			item.source,
			len(receipts),
		)
	}

	if _, err := DiscoverRecordedReceiptsForSource(
		root,
		"unregistered-fixture-source.local",
	); err == nil {
		t.Fatal("missing authoritative namespace was accepted")
	}

	t.Log("PASS: Missing namespace fails closed")
}
