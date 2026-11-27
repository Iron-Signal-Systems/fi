// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestM1SourceNamespaceRejectsMisplacedValidReceipt(t *testing.T) {
	if os.Getenv("FI_M1_NAMESPACE_READ_TEST") != "1" {
		t.Skip("verified receipt fixture not requested")
	}

	const (
		fs19 = "iss-fs-2019.iss.local"
		fs22 = "iss-fs-22.iss.local"
	)

	fixture := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-receipts-20261012",
		"namespaced",
		"sources",
		fs19,
	)

	entries, err := os.ReadDir(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 104 {
		t.Fatalf("fixture receipts=%d, want 104", len(entries))
	}

	name := entries[0].Name()

	raw, err := os.ReadFile(filepath.Join(fixture, name))
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "recorded")
	destination := filepath.Join(root, "sources", fs22)

	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(destination, name),
		raw,
		0400,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := DiscoverRecordedReceiptsForSource(
		root,
		fs22,
	); err == nil || !strings.Contains(err.Error(), fs19) {
		t.Fatalf(
			"cross-source receipt not rejected with identity: %v",
			err,
		)
	}

	t.Log("PASS: Misplaced valid FS2019 receipt rejected by FS22 namespace")
}
