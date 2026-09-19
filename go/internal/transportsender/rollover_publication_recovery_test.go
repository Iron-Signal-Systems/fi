// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestRolloverRepairsInterruptedPublicationBeforeFreeze(
	t *testing.T,
) {
	root :=
		t.TempDir()

	spoolDir :=
		filepath.Join(
			root,
			"spool",
		)

	if err :=
		os.Mkdir(
			spoolDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	workDir, err :=
		spool.CollectorWorkDir(
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

	const batchID = "rollover-interrupted-publication"

	dataName :=
		"batch-" +
			batchID +
			".jsonl"

	manifestName :=
		"batch-" +
			batchID +
			".manifest.json"

	data :=
		[]byte(
			"{\"value\":\"one\"}\n",
		)

	digest :=
		sha256.Sum256(
			data,
		)

	publicationDataPath :=
		filepath.Join(
			spoolDir,
			dataName,
		)

	if err :=
		os.WriteFile(
			publicationDataPath,
			data,
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	manifest :=
		spool.Manifest{
			Version:         spool.ManifestVersion,
			BatchID:         batchID,
			TargetBatchSize: spool.DefaultBatchSize,
			RecordCount:     1,
			DataBytes:       int64(len(data)),
			DataSHA256:      hex.EncodeToString(digest[:]),
			DataFile:        dataName,
			Collector: spool.CollectorIdentity{
				ExecutablePath: `C:\Program Files\FI\fi.exe`,
				ExecutableSHA256: strings.Repeat(
					"a",
					64,
				),
			},
			CreatedAt:   "2026-09-18T10:00:00.000000000Z",
			CompletedAt: "2026-09-18T10:00:01.000000000Z",
		}

	encodedManifest, err :=
		json.MarshalIndent(
			manifest,
			"",
			"  ",
		)
	if err != nil {
		t.Fatal(err)
	}

	encodedManifest =
		append(
			encodedManifest,
			'\n',
		)

	workManifestPath :=
		filepath.Join(
			workDir,
			manifestName,
		)

	if err :=
		os.WriteFile(
			workManifestPath,
			encodedManifest,
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	raw, found, err :=
		RolloverPublishedSpool(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !found {
		t.Fatal(
			"rollover reported no generation after interrupted publication repair",
		)
	}

	frozenDataPath :=
		filepath.Join(
			raw.GenerationDir,
			dataName,
		)

	frozenManifestPath :=
		filepath.Join(
			raw.GenerationDir,
			manifestName,
		)

	if _, err :=
		os.Stat(
			frozenDataPath,
		); err != nil {
		t.Fatalf(
			"repaired data missing from frozen generation: %v",
			err,
		)
	}

	if _, err :=
		os.Stat(
			frozenManifestPath,
		); err != nil {
		t.Fatalf(
			"repaired manifest missing from frozen generation: %v",
			err,
		)
	}

	verification, err :=
		spool.VerifyManifest(
			frozenManifestPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !verification.Verified {
		t.Fatal(
			"repaired frozen batch did not independently verify",
		)
	}

	if _, err :=
		os.Stat(
			workManifestPath,
		); !os.IsNotExist(err) {
		t.Fatalf(
			"work manifest remained after repair and rollover: %v",
			err,
		)
	}

	activeEntries, err :=
		os.ReadDir(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(activeEntries) != 0 {
		t.Fatalf(
			"replacement active spool contains %d entries; want 0",
			len(activeEntries),
		)
	}
}
