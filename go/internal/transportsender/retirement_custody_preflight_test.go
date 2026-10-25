// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCustodyPreflightCannotAuthorizeUSNRetirement(t *testing.T) {
	rawDir := filepath.Join(t.TempDir(), "generation-test")
	if err := os.Mkdir(rawDir, 0o700); err != nil {
		t.Fatal(err)
	}

	data := `{"record_kind":"USNReadBoundary","payload":{"source_batch_sha256":"` +
		strings.Repeat("a", 64) + `"}}` + "\n"
	writeGenerationTestBatch(t, rawDir, "usn-preflight", []byte(data))

	raw := RawGeneration{
		GenerationDir: rawDir,
		GenerationID:  "test",
	}

	for _, tc := range []struct {
		name      string
		stateDir  string
		sealedDir string
		sourceID  string
	}{
		{name: "no-custody-config"},
		{
			name:      "missing-committed-state",
			stateDir:  t.TempDir(),
			sealedDir: filepath.Join(t.TempDir(), "generation-test"),
			sourceID:  "test-source",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := removeRawGenerationWithCustody(
				context.Background(), raw,
				tc.stateDir, tc.sealedDir, tc.sourceID,
			)
			if err == nil {
				t.Fatal("USN generation retired without durable authorization")
			}
			if tc.stateDir == "" &&
				!errors.Is(err, ErrSourceCustodyHandoffRequired) {
				t.Fatalf("missing custody state did not fail closed: %v", err)
			}
			if _, err := os.Stat(rawDir); err != nil {
				t.Fatalf("unretired USN source missing: %v", err)
			}
		})
	}
}

func TestCustodyPreflightPreservesNonUSNRetirement(t *testing.T) {
	rawDir := filepath.Join(t.TempDir(), "generation-other")
	if err := os.Mkdir(rawDir, 0o700); err != nil {
		t.Fatal(err)
	}

	writeGenerationTestBatch(
		t, rawDir, "unrelated",
		[]byte("{\"record_kind\":\"WindowsSecurityEvent\"}\n"),
	)

	err := removeRawGenerationWithCustody(
		context.Background(),
		RawGeneration{
			GenerationDir: rawDir,
			GenerationID:  "other",
		},
		"", "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rawDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-USN generation retirement failed: %v", err)
	}
}
