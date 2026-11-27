// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateSealedGenerationPublishesTwoFileDirectory(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	expectedDirectory :=
		filepath.Join(
			config.SealedRoot,
			"generation-"+
				config.GenerationID,
		)

	if published.DirectoryPath !=
		expectedDirectory {
		t.Fatalf(
			"published directory = %q, want %q",
			published.DirectoryPath,
			expectedDirectory,
		)
	}

	entries, err :=
		os.ReadDir(
			published.DirectoryPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 2 {
		t.Fatalf(
			"published entry count = %d, want 2",
			len(entries),
		)
	}

	names :=
		map[string]bool{}

	for _, entry := range entries {
		names[entry.Name()] =
			true
	}

	if !names[SealedGenerationPayloadName] {
		t.Fatal(
			"published generation is missing payload.figz",
		)
	}

	if !names[SignedGenerationMetadataName] {
		t.Fatal(
			"published generation is missing signed-generation.json",
		)
	}

	loaded, err :=
		LoadSealedGeneration(
			published.DirectoryPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Signed.Descriptor !=
		published.Signed.Descriptor {
		t.Fatal(
			"reloaded generation descriptor changed",
		)
	}

	if err :=
		VerifyPublishedGenerationPayload(
			loaded,
		); err != nil {
		t.Fatal(err)
	}

	openEntries, err :=
		os.ReadDir(
			config.SealedRoot,
		)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range openEntries {
		if strings.HasPrefix(
			entry.Name(),
			".generation-",
		) {
			t.Fatalf(
				"provisional generation remains after publication: %q",
				entry.Name(),
			)
		}
	}
}

func TestCreateSealedGenerationRejectsEncodedLimitBeforePublication(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	config.MaxEncodedBytes = 1

	_, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if !errors.Is(
		err,
		ErrEncodedLimitExceeded,
	) {
		t.Fatalf(
			"create error = %v, want ErrEncodedLimitExceeded",
			err,
		)
	}

	finalPath :=
		filepath.Join(
			config.SealedRoot,
			"generation-"+
				config.GenerationID,
		)

	if _, err :=
		os.Lstat(
			finalPath,
		); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"generation published despite encoded limit: %v",
			err,
		)
	}

	entries, err :=
		os.ReadDir(
			config.SealedRoot,
		)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if strings.HasPrefix(
			entry.Name(),
			".generation-",
		) {
			t.Fatalf(
				"provisional generation remains after encoded-limit rejection: %q",
				entry.Name(),
			)
		}
	}
}

func TestCreateSealedGenerationRestartReusesPublishedObject(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	first, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	firstMetadata, err :=
		os.ReadFile(
			first.MetadataPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	stale :=
		filepath.Join(
			config.SealedRoot,
			".generation-"+
				config.GenerationID+
				"-stale.open",
		)

	if err :=
		os.Mkdir(
			stale,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			filepath.Join(
				stale,
				"partial",
			),
			[]byte(
				"abandoned",
			),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	second, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	secondMetadata, err :=
		os.ReadFile(
			second.MetadataPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		firstMetadata,
		secondMetadata,
	) {
		t.Fatal(
			"restart rebuilt signed generation instead of reusing durable object",
		)
	}

	if _,
		err :=
		os.Lstat(
			stale,
		); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"stale provisional generation remains after restart reconciliation: %v",
			err,
		)
	}

	if second.Signed.Descriptor !=
		first.Signed.Descriptor {
		t.Fatal(
			"restart changed durable generation descriptor",
		)
	}
}

func TestVerifyPublishedGenerationPayloadRejectsMutation(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	file, err :=
		os.OpenFile(
			published.PayloadPath,
			os.O_RDWR,
			0,
		)
	if err != nil {
		t.Fatal(err)
	}

	var first [1]byte

	if _,
		err :=
		file.ReadAt(
			first[:],
			0,
		); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	first[0] ^= 0xff

	if _,
		err :=
		file.WriteAt(
			first[:],
			0,
		); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err :=
		file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err :=
		file.Close(); err != nil {
		t.Fatal(err)
	}

	if err :=
		VerifyPublishedGenerationPayload(
			published,
		); err == nil {
		t.Fatal(
			"mutated sealed-generation payload verified",
		)
	}
}

func TestLoadSealedGenerationRejectsUnexpectedArtifact(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			filepath.Join(
				published.DirectoryPath,
				"unexpected",
			),
			[]byte(
				"must-fail",
			),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if _,
		err :=
		LoadSealedGeneration(
			published.DirectoryPath,
		); err == nil {
		t.Fatal(
			"sealed-generation directory with unexpected artifact was accepted",
		)
	}
}

func testCreateGenerationConfig(
	t *testing.T,
) CreateConfig {
	t.Helper()

	frozen :=
		filepath.Join(
			t.TempDir(),
			"frozen",
		)

	sealed :=
		filepath.Join(
			t.TempDir(),
			"sealed",
		)

	if err :=
		os.MkdirAll(
			frozen,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.MkdirAll(
			sealed,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	files :=
		map[string][]byte{
			"batch-a.manifest.json": []byte(
				"{\"batch\":\"a\"}\n",
			),

			"batch-a.jsonl": []byte(
				"{\"record\":1}\n",
			),

			"batch-b.manifest.json": []byte(
				"{\"batch\":\"b\"}\n",
			),

			"batch-b.jsonl": []byte(
				"{\"record\":2}\n{\"record\":3}\n",
			),
		}

	for name, value := range files {
		if err :=
			os.WriteFile(
				filepath.Join(
					frozen,
					name,
				),
				value,
				0o600,
			); err != nil {
			t.Fatal(err)
		}
	}

	key, certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	return CreateConfig{
		BatchSigner: key,

		BatchSigningCertificate: certificate,

		FrozenDir: frozen,

		GenerationID: "20260918T134500.000000000Z-0011223344556677",

		SealedRoot: sealed,

		SourceID: "iss-fs-01.iss.local",
	}
}
