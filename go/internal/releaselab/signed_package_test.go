// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releaselab

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyRegularFileAndSHA256(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	source := filepath.Join(
		root,
		"source.bin",
	)
	destination := filepath.Join(
		root,
		"destination.bin",
	)
	value := []byte(
		"FI signed package copy test\n",
	)
	if err := os.WriteFile(
		source,
		value,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := copyRegularFile(
		source,
		destination,
	); err != nil {
		t.Fatal(err)
	}

	hash, err := fileSHA256(
		destination,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(
		value,
	)
	if hash != strings.ToUpper(
		hex.EncodeToString(
			expected[:],
		),
	) {
		t.Fatalf(
			"SHA256=%s",
			hash,
		)
	}
}
