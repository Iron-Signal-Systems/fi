// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every production raw-removal path calls the same function. A frozen source
// range must survive until its exact source-to-sealed custody is established.
func TestRawGenerationRetirementRequiresUSNHandoff(t *testing.T) {
	for _, kind := range []string{"USNReadBoundary", "USNObjectObservation"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "generation-raw")
			rawDir := filepath.Join(root, "generation-test")
			if err := os.MkdirAll(rawDir, 0o700); err != nil {
				t.Fatal(err)
			}
			data := `{"record_kind":"` + kind + `","payload":{"source_batch_sha256":"` + strings.Repeat("a", 64) + `"}}` + "\n"
			writeGenerationTestBatch(t, rawDir, "guarded-usn", []byte(data))
			err := removeRawGenerationDirectory(RawGeneration{GenerationDir: rawDir, GenerationID: "test"})
			if !errors.Is(err, ErrSourceCustodyHandoffRequired) {
				t.Fatalf("retirement was not blocked: %v", err)
			}
			if _, err := os.Stat(rawDir); err != nil {
				t.Fatalf("original source generation was removed: %v", err)
			}
		})
	}
}

func TestRawGenerationRetirementKeepsNonUSNPath(t *testing.T) {
	rawDir := filepath.Join(t.TempDir(), "generation-other")
	if err := os.Mkdir(rawDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeGenerationTestBatch(t, rawDir, "other", []byte("{\"record_kind\":\"WindowsSecurityEvent\"}\n"))
	if err := removeRawGenerationDirectory(RawGeneration{GenerationDir: rawDir, GenerationID: "other"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rawDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unrelated generation not retired: %v", err)
	}
}

func TestRawGenerationRetirementRejectsInvalidCustodyData(t *testing.T) {
	for _, data := range []string{
		`{"record_kind":"USNReadBoundary","payload":{}}` + "\n",
		`{"record_kind":` + "\n",
	} {
		rawDir := filepath.Join(t.TempDir(), "generation-corrupt")
		if err := os.Mkdir(rawDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeGenerationTestBatch(t, rawDir, "corrupt", []byte(data))
		if err := removeRawGenerationDirectory(RawGeneration{GenerationDir: rawDir, GenerationID: "corrupt"}); err == nil {
			t.Fatal("raw generation with invalid custody data was deleted")
		}
		if _, err := os.Stat(rawDir); err != nil {
			t.Fatalf("corrupt generation bytes were removed: %v", err)
		}
	}
}
