// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationsealer"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func TestValidateCanonicalAcceptsExactBatchPairs(
	t *testing.T,
) {
	frozen :=
		t.TempDir()

	firstData :=
		[]byte(
			"{\"record\":1}\n{\"record\":2}\n",
		)

	secondData :=
		[]byte(
			"{\"record\":3}\n",
		)

	writeRecorderBatch(
		t,
		frozen,
		"20260918T160000.000000000Z-0011223344556677",
		firstData,
		"",
	)

	writeRecorderBatch(
		t,
		frozen,
		"20260918T160001.000000000Z-8899aabbccddeeff",
		secondData,
		"",
	)

	result :=
		validateRecorderFixture(
			t,
			frozen,
			Config{
				MaxManifestBytes: 1 << 20,
			},
		)

	if result.BatchCount != 2 {
		t.Fatalf(
			"BatchCount = %d, want 2",
			result.BatchCount,
		)
	}

	if result.RecordCount != 3 {
		t.Fatalf(
			"RecordCount = %d, want 3",
			result.RecordCount,
		)
	}

	wantDataBytes :=
		uint64(
			len(firstData) +
				len(secondData),
		)

	if result.DataBytes !=
		wantDataBytes {
		t.Fatalf(
			"DataBytes = %d, want %d",
			result.DataBytes,
			wantDataBytes,
		)
	}

	if result.ArtifactCount != 4 {
		t.Fatalf(
			"ArtifactCount = %d, want 4",
			result.ArtifactCount,
		)
	}
}

func TestValidateCanonicalRejectsManifestHashMismatch(
	t *testing.T,
) {
	frozen :=
		t.TempDir()

	writeRecorderBatch(
		t,
		frozen,
		"20260918T160000.000000000Z-0011223344556677",
		[]byte(
			"{\"record\":1}\n",
		),
		strings.Repeat(
			"0",
			64,
		),
	)

	if err :=
		validateRecorderFixtureError(
			t,
			frozen,
			Config{
				MaxManifestBytes: 1 << 20,
			},
		); err == nil {
		t.Fatal(
			"generation with manifest/data hash mismatch was accepted",
		)
	}
}

func TestValidateCanonicalRejectsManifestWithoutData(
	t *testing.T,
) {
	frozen :=
		t.TempDir()

	batchID :=
		"20260918T160000.000000000Z-0011223344556677"

	manifest :=
		recorderManifest(
			batchID,
			[]byte(
				"{\"record\":1}\n",
			),
			"",
		)

	writeRecorderManifest(
		t,
		frozen,
		manifest,
	)

	if err :=
		validateRecorderFixtureError(
			t,
			frozen,
			Config{
				MaxManifestBytes: 1 << 20,
			},
		); err == nil {
		t.Fatal(
			"generation with orphan manifest was accepted",
		)
	}
}

func TestValidateCanonicalRejectsUnexpectedArtifact(
	t *testing.T,
) {
	frozen :=
		t.TempDir()

	writeRecorderBatch(
		t,
		frozen,
		"20260918T160000.000000000Z-0011223344556677",
		[]byte(
			"{\"record\":1}\n",
		),
		"",
	)

	for _, name := range []string{
		"unexpected-a.txt",
		"unexpected-b.txt",
	} {
		if err :=
			os.WriteFile(
				filepath.Join(
					frozen,
					name,
				),
				[]byte("unexpected\n"),
				0o600,
			); err != nil {
			t.Fatal(err)
		}
	}

	if err :=
		validateRecorderFixtureError(
			t,
			frozen,
			Config{
				MaxManifestBytes: 1 << 20,
			},
		); err == nil {
		t.Fatal(
			"generation with unexpected artifact was accepted",
		)
	}
}

func TestValidateCanonicalRejectsManifestAboveConfiguredLimit(
	t *testing.T,
) {
	frozen :=
		t.TempDir()

	writeRecorderBatch(
		t,
		frozen,
		"20260918T160000.000000000Z-0011223344556677",
		[]byte(
			"{\"record\":1}\n",
		),
		"",
	)

	if err :=
		validateRecorderFixtureError(
			t,
			frozen,
			Config{
				MaxManifestBytes: 32,
			},
		); err == nil {
		t.Fatal(
			"generation manifest above configured recorder limit was accepted",
		)
	}
}

func recorderManifest(
	batchID string,
	data []byte,
	overrideSHA256 string,
) spool.Manifest {
	digest :=
		sha256.Sum256(
			data,
		)

	dataSHA256 :=
		hex.EncodeToString(
			digest[:],
		)

	if overrideSHA256 != "" {
		dataSHA256 =
			overrideSHA256
	}

	return spool.Manifest{
		Version: spool.ManifestVersion,

		BatchID: batchID,

		TargetBatchSize: spool.DefaultBatchSize,

		RecordCount: bytes.Count(
			data,
			[]byte{'\n'},
		),

		DataBytes: int64(
			len(data),
		),

		DataSHA256: dataSHA256,

		DataFile: "batch-" +
			batchID +
			".jsonl",

		Collector: spool.CollectorIdentity{
			ExecutablePath: "C:\\Program Files\\FI\\fi.exe",

			ExecutableSHA256: strings.Repeat(
				"1",
				64,
			),
		},

		CreatedAt: "2026-09-18T16:00:00.000000000Z",

		CompletedAt: "2026-09-18T16:00:01.000000000Z",
	}
}

func validateRecorderFixture(
	t *testing.T,
	frozen string,
	config Config,
) Result {
	t.Helper()

	result, err :=
		validateRecorderFixtureResult(
			t,
			frozen,
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func validateRecorderFixtureError(
	t *testing.T,
	frozen string,
	config Config,
) error {
	t.Helper()

	_, err :=
		validateRecorderFixtureResult(
			t,
			frozen,
			config,
		)

	return err
}

func validateRecorderFixtureResult(
	t *testing.T,
	frozen string,
	config Config,
) (
	Result,
	error,
) {
	t.Helper()

	sealed :=
		filepath.Join(
			t.TempDir(),
			"sealed",
		)

	seal, err :=
		generationsealer.Seal(
			context.Background(),
			generationsealer.Config{
				FrozenDir: frozen,

				GenerationID: "20260918T161500.000000000Z-0123456789abcdef",

				SealedDir: sealed,
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	descriptor, err :=
		transportgeneration.DescriptorFromSeal(
			"iss-fs-01.iss.local",
			seal,
		)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err :=
		os.Open(
			seal.SealedPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	defer encoded.Close()

	decoder, err :=
		transportencoding.NewZstdDecoder(
			encoded,
		)
	if err != nil {
		t.Fatal(err)
	}

	defer decoder.Close()

	return ValidateCanonical(
		decoder,
		descriptor,
		config,
	)
}

func writeRecorderBatch(
	t *testing.T,
	dir string,
	batchID string,
	data []byte,
	overrideSHA256 string,
) {
	t.Helper()

	manifest :=
		recorderManifest(
			batchID,
			data,
			overrideSHA256,
		)

	if err :=
		os.WriteFile(
			filepath.Join(
				dir,
				manifest.DataFile,
			),
			data,
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	writeRecorderManifest(
		t,
		dir,
		manifest,
	)
}

func writeRecorderManifest(
	t *testing.T,
	dir string,
	manifest spool.Manifest,
) {
	t.Helper()

	raw, err :=
		json.MarshalIndent(
			manifest,
			"",
			"  ",
		)
	if err != nil {
		t.Fatal(err)
	}

	raw =
		append(
			raw,
			'\n',
		)

	if err :=
		os.WriteFile(
			filepath.Join(
				dir,
				"batch-"+
					manifest.BatchID+
					".manifest.json",
			),
			raw,
			0o600,
		); err != nil {
		t.Fatal(err)
	}
}
