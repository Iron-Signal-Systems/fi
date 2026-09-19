// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInterruptedPublicationRecoveryCompletesManifest(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, workDataPath, workManifestPath :=
		writePreparedRecoveryTestPair(
			t,
			spoolDir,
			"interrupted-publication",
		)

	t.Cleanup(
		func() {
			_ =
				os.RemoveAll(
					workDir,
				)
		},
	)

	publicationDir, err :=
		resolveDirectoryPath(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	publicationDataPath :=
		filepath.Join(
			publicationDir,
			filepath.Base(
				workDataPath,
			),
		)

	publicationManifestPath :=
		filepath.Join(
			publicationDir,
			filepath.Base(
				workManifestPath,
			),
		)

	if err :=
		durableRename(
			workDataPath,
			publicationDataPath,
		); err != nil {
		t.Fatal(err)
	}

	guard, err :=
		AcquirePublishBoundary()
	if err != nil {
		t.Fatal(err)
	}

	recovered, recoveryErr :=
		RecoverInterruptedPublicationsLocked(
			spoolDir,
		)

	closeErr :=
		guard.Close()

	if recoveryErr != nil {
		t.Fatal(
			recoveryErr,
		)
	}

	if closeErr != nil {
		t.Fatal(
			closeErr,
		)
	}

	if recovered != 1 {
		t.Fatalf(
			"recovered publications = %d, want 1",
			recovered,
		)
	}

	if _, err :=
		os.Stat(
			publicationManifestPath,
		); err != nil {
		t.Fatalf(
			"published manifest missing after recovery: %v",
			err,
		)
	}

	if _, err :=
		os.Stat(
			workManifestPath,
		); !os.IsNotExist(err) {
		t.Fatalf(
			"work manifest remained after recovery: %v",
			err,
		)
	}

	verification, err :=
		VerifyManifest(
			publicationManifestPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !verification.Verified {
		t.Fatal(
			"recovered interrupted publication did not verify",
		)
	}
}

func TestRolloverRecoveryIgnoresUnstartedPreparedPair(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, workDataPath, workManifestPath :=
		writePreparedRecoveryTestPair(
			t,
			spoolDir,
			"live-prepared-publication",
		)

	t.Cleanup(
		func() {
			_ =
				os.RemoveAll(
					workDir,
				)
		},
	)

	guard, err :=
		AcquirePublishBoundary()
	if err != nil {
		t.Fatal(err)
	}

	recovered, recoveryErr :=
		RecoverInterruptedPublicationsLocked(
			spoolDir,
		)

	closeErr :=
		guard.Close()

	if recoveryErr != nil {
		t.Fatal(
			recoveryErr,
		)
	}

	if closeErr != nil {
		t.Fatal(
			closeErr,
		)
	}

	if recovered != 0 {
		t.Fatalf(
			"recovered publications = %d, want 0",
			recovered,
		)
	}

	if _, err :=
		os.Stat(
			workDataPath,
		); err != nil {
		t.Fatalf(
			"live prepared data was disturbed: %v",
			err,
		)
	}

	if _, err :=
		os.Stat(
			workManifestPath,
		); err != nil {
		t.Fatalf(
			"live prepared manifest was disturbed: %v",
			err,
		)
	}

	publicationEntries, err :=
		os.ReadDir(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(publicationEntries) != 0 {
		t.Fatalf(
			"rollover recovery published %d artifacts from an unstarted pair; want 0",
			len(publicationEntries),
		)
	}
}

func TestStartupRecoveryPublishesAbandonedPreparedPair(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, workDataPath, workManifestPath :=
		writePreparedRecoveryTestPair(
			t,
			spoolDir,
			"abandoned-prepared-publication",
		)

	t.Cleanup(
		func() {
			_ =
				os.RemoveAll(
					workDir,
				)
		},
	)

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

	if _, err :=
		os.Stat(
			workDataPath,
		); !os.IsNotExist(err) {
		t.Fatalf(
			"abandoned work data remained after recovery: %v",
			err,
		)
	}

	if _, err :=
		os.Stat(
			workManifestPath,
		); !os.IsNotExist(err) {
		t.Fatalf(
			"abandoned work manifest remained after recovery: %v",
			err,
		)
	}

	publicationManifestPath :=
		filepath.Join(
			spoolDir,
			"batch-abandoned-prepared-publication.manifest.json",
		)

	verification, err :=
		VerifyManifest(
			publicationManifestPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !verification.Verified {
		t.Fatal(
			"startup-recovered publication did not verify",
		)
	}
}

func TestStartupRecoveryCompletesInterruptedPublication(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, workDataPath, workManifestPath :=
		writePreparedRecoveryTestPair(
			t,
			spoolDir,
			"startup-interrupted-publication",
		)

	t.Cleanup(
		func() {
			_ =
				os.RemoveAll(
					workDir,
				)
		},
	)

	publicationDataPath :=
		filepath.Join(
			spoolDir,
			filepath.Base(
				workDataPath,
			),
		)

	if err :=
		durableRename(
			workDataPath,
			publicationDataPath,
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

	publicationManifestPath :=
		filepath.Join(
			spoolDir,
			filepath.Base(
				workManifestPath,
			),
		)

	verification, err :=
		VerifyManifest(
			publicationManifestPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !verification.Verified {
		t.Fatal(
			"startup interrupted publication did not verify",
		)
	}
}

func TestInterruptedRecoveryRejectsMissingPreparedData(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, workDataPath, _ :=
		writePreparedRecoveryTestPair(
			t,
			spoolDir,
			"missing-prepared-data",
		)

	t.Cleanup(
		func() {
			_ =
				os.RemoveAll(
					workDir,
				)
		},
	)

	if err :=
		os.Remove(
			workDataPath,
		); err != nil {
		t.Fatal(err)
	}

	guard, err :=
		AcquirePublishBoundary()
	if err != nil {
		t.Fatal(err)
	}

	_, recoveryErr :=
		RecoverInterruptedPublicationsLocked(
			spoolDir,
		)

	closeErr :=
		guard.Close()

	if recoveryErr == nil {
		t.Fatal(
			"interrupted recovery accepted a manifest with no data",
		)
	}

	if closeErr != nil {
		t.Fatal(
			closeErr,
		)
	}
}

func writePreparedRecoveryTestPair(
	t *testing.T,
	spoolDir string,
	batchID string,
) (
	workDir string,
	dataPath string,
	manifestPath string,
) {
	t.Helper()

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

	dataName :=
		"batch-" +
			batchID +
			".jsonl"

	dataPath =
		filepath.Join(
			workDir,
			dataName,
		)

	data :=
		[]byte(
			"{\"value\":\"one\"}\n",
		)

	if err :=
		os.WriteFile(
			dataPath,
			data,
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	digest, dataBytes, records, err :=
		inspectDataFile(
			dataPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	manifest :=
		Manifest{
			Version:         ManifestVersion,
			BatchID:         batchID,
			TargetBatchSize: DefaultBatchSize,
			RecordCount:     records,
			DataBytes:       dataBytes,
			DataSHA256:      digest,
			DataFile:        dataName,
			Collector: CollectorIdentity{
				ExecutablePath: `C:\Program Files\FI\fi.exe`,
				ExecutableSHA256: strings.Repeat(
					"e",
					64,
				),
			},
			CreatedAt:   "2026-09-18T10:00:00.000000000Z",
			CompletedAt: "2026-09-18T10:00:01.000000000Z",
		}

	manifestPath =
		filepath.Join(
			workDir,
			"batch-"+
				batchID+
				".manifest.json",
		)

	if err :=
		writeManifest(
			manifestPath,
			manifest,
		); err != nil {
		t.Fatal(err)
	}

	return workDir, dataPath, manifestPath
}
