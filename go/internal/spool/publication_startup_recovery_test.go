// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStartupRecoverySalvagesVerifiedManifestOpen(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, _, manifestPath :=
		writePreparedRecoveryTestPair(
			t,
			spoolDir,
			"manifest-open-salvage",
		)

	openManifestPath :=
		manifestPath +
			".open"

	if err :=
		durableRename(
			manifestPath,
			openManifestPath,
		); err != nil {
		t.Fatal(err)
	}

	recovered, err :=
		RecoverAbandonedPublications(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if recovered != 1 {
		t.Fatalf(
			"recovered publications = %d, want 1",
			recovered,
		)
	}

	publishedManifest :=
		filepath.Join(
			spoolDir,
			"batch-manifest-open-salvage.manifest.json",
		)

	verification, err :=
		VerifyManifest(
			publishedManifest,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !verification.Verified {
		t.Fatal(
			"salvaged manifest-open publication did not verify",
		)
	}

	entries, err :=
		os.ReadDir(
			workDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 0 {
		t.Fatalf(
			"work directory contains %d artifacts after salvage, want 0",
			len(entries),
		)
	}
}

func TestStartupRecoveryQuarantinesPartialWorkOpen(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, err :=
		CollectorWorkDir(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		os.MkdirAll(
			workDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	source :=
		filepath.Join(
			workDir,
			"batch-partial.open",
		)

	if err :=
		os.WriteFile(
			source,
			[]byte("partial"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		RecoverAbandonedPublications(
			spoolDir,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		os.Stat(
			source,
		); !os.IsNotExist(err) {
		t.Fatalf(
			"partial work file remained after quarantine: %v",
			err,
		)
	}

	assertQuarantineContains(
		t,
		spoolDir,
		"work-batch-partial.open",
	)
}

func TestStartupRecoveryQuarantinesOrphanWorkData(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, err :=
		CollectorWorkDir(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		os.MkdirAll(
			workDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	source :=
		filepath.Join(
			workDir,
			"batch-orphan.jsonl",
		)

	if err :=
		os.WriteFile(
			source,
			[]byte("{}\n"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		RecoverAbandonedPublications(
			spoolDir,
		); err != nil {
		t.Fatal(err)
	}

	assertQuarantineContains(
		t,
		spoolDir,
		"work-batch-orphan.jsonl",
	)
}

func TestStartupRecoveryQuarantinesLegacyActiveOpen(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	source :=
		filepath.Join(
			spoolDir,
			"batch-legacy.open",
		)

	if err :=
		os.WriteFile(
			source,
			[]byte("legacy partial"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		RecoverAbandonedPublications(
			spoolDir,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		os.Stat(
			source,
		); !os.IsNotExist(err) {
		t.Fatalf(
			"legacy active-spool open file remained: %v",
			err,
		)
	}

	assertQuarantineContains(
		t,
		spoolDir,
		"spool-batch-legacy.open",
	)
}

func TestStartupRecoveryQuarantinesInvalidManifestOpenPair(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, err :=
		CollectorWorkDir(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		os.MkdirAll(
			workDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	dataPath :=
		filepath.Join(
			workDir,
			"batch-invalid-open.jsonl",
		)

	manifestOpenPath :=
		filepath.Join(
			workDir,
			"batch-invalid-open.manifest.json.open",
		)

	if err :=
		os.WriteFile(
			dataPath,
			[]byte("{}\n"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			manifestOpenPath,
			[]byte("{"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		RecoverAbandonedPublications(
			spoolDir,
		); err != nil {
		t.Fatal(err)
	}

	assertQuarantineContains(
		t,
		spoolDir,
		"work-batch-invalid-open.jsonl",
	)

	assertQuarantineContains(
		t,
		spoolDir,
		"work-batch-invalid-open.manifest.json.open",
	)
}

func TestStartupRecoveryRejectsUnknownWorkArtifact(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, err :=
		CollectorWorkDir(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		os.MkdirAll(
			workDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			filepath.Join(
				workDir,
				"unexpected.bin",
			),
			[]byte("unexpected"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		RecoverAbandonedPublications(
			spoolDir,
		); err == nil {
		t.Fatal(
			"startup recovery accepted unknown work artifact",
		)
	}
}

func assertQuarantineContains(
	t *testing.T,
	spoolDir string,
	want string,
) {
	t.Helper()

	root, err :=
		collectorQuarantineRoot(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	recoveries, err :=
		os.ReadDir(
			root,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(recoveries) != 1 ||
		!recoveries[0].IsDir() {
		t.Fatalf(
			"quarantine recovery directories = %d, want 1",
			len(recoveries),
		)
	}

	entries, err :=
		os.ReadDir(
			filepath.Join(
				root,
				recoveries[0].Name(),
			),
		)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {

		if entry.Name() ==
			want {
			return
		}
	}

	t.Fatalf(
		"quarantine does not contain %q",
		want,
	)
}
