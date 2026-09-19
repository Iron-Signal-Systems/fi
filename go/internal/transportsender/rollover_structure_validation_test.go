// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRolloverRejectsStructurallyIncompletePublishedSpool(
	t *testing.T,
) {
	parent :=
		t.TempDir()

	spoolDir :=
		filepath.Join(
			parent,
			"spool",
		)

	if err :=
		os.Mkdir(
			spoolDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	orphan :=
		filepath.Join(
			spoolDir,
			"batch-orphan.jsonl",
		)

	if err :=
		os.WriteFile(
			orphan,
			[]byte("{}\n"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	raw, found, err :=
		RolloverPublishedSpool(
			spoolDir,
		)

	if err == nil {
		t.Fatal(
			"RolloverPublishedSpool accepted structurally incomplete spool",
		)
	}

	if found {
		t.Fatal(
			"RolloverPublishedSpool reported generation for invalid spool",
		)
	}

	if raw.GenerationDir != "" ||
		raw.GenerationID != "" {
		t.Fatalf(
			"raw generation = %+v, want zero value",
			raw,
		)
	}

	if !strings.Contains(
		err.Error(),
		"no matching manifest",
	) {
		t.Fatalf(
			"error = %v, want missing-manifest structural error",
			err,
		)
	}

	if _, statErr :=
		os.Stat(
			orphan,
		); statErr != nil {
		t.Fatalf(
			"orphan data changed after rejected rollover: %v",
			statErr,
		)
	}
}
