// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationsealer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestSealDeterministicGeneration(t *testing.T) {
	firstFrozen := filepath.Join(
		t.TempDir(),
		"frozen",
	)

	secondFrozen := filepath.Join(
		t.TempDir(),
		"frozen",
	)

	firstSealed := filepath.Join(
		t.TempDir(),
		"sealed",
	)

	secondSealed := filepath.Join(
		t.TempDir(),
		"sealed",
	)

	for _, path := range []string{
		firstFrozen,
		secondFrozen,
		firstSealed,
		secondSealed,
	} {
		if err := os.MkdirAll(
			path,
			0o700,
		); err != nil {
			t.Fatal(err)
		}
	}

	files := map[string][]byte{
		"batch-b.manifest.json": []byte(
			"{\"batch\":\"b\"}\n",
		),
		"batch-b.jsonl": []byte(
			"{\"record\":2}\n{\"record\":3}\n",
		),
		"batch-a.manifest.json": []byte(
			"{\"batch\":\"a\"}\n",
		),
		"batch-a.jsonl": []byte(
			"{\"record\":1}\n",
		),
	}

	firstOrder := []string{
		"batch-b.manifest.json",
		"batch-b.jsonl",
		"batch-a.manifest.json",
		"batch-a.jsonl",
	}

	secondOrder := []string{
		"batch-a.jsonl",
		"batch-a.manifest.json",
		"batch-b.jsonl",
		"batch-b.manifest.json",
	}

	writeFixtureFiles(
		t,
		firstFrozen,
		firstOrder,
		files,
	)

	writeFixtureFiles(
		t,
		secondFrozen,
		secondOrder,
		files,
	)

	first, err := Seal(
		context.Background(),
		Config{
			FrozenDir:    firstFrozen,
			GenerationID: "test-generation",
			SealedDir:    firstSealed,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Seal(
		context.Background(),
		Config{
			FrozenDir:    secondFrozen,
			GenerationID: "test-generation",
			SealedDir:    secondSealed,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if first.FileCount != 4 {
		t.Fatalf(
			"file count = %d, want 4",
			first.FileCount,
		)
	}

	if first.SourceBytes != second.SourceBytes {
		t.Fatalf(
			"source bytes differ: %d != %d",
			first.SourceBytes,
			second.SourceBytes,
		)
	}

	if first.CanonicalSHA256 != second.CanonicalSHA256 {
		t.Fatalf(
			"canonical hashes differ: %s != %s",
			first.CanonicalSHA256,
			second.CanonicalSHA256,
		)
	}

	if first.EncodedSHA256 != second.EncodedSHA256 {
		t.Fatalf(
			"encoded hashes differ: %s != %s",
			first.EncodedSHA256,
			second.EncodedSHA256,
		)
	}

	verifySealedGeneration(
		t,
		first,
	)
}

func verifySealedGeneration(
	t *testing.T,
	result Result,
) {
	t.Helper()

	file, err :=
		os.Open(result.SealedPath)

	if err != nil {
		t.Fatal(err)
	}

	encodedHasher :=
		sha256.New()

	encodedBytes, err :=
		io.Copy(
			encodedHasher,
			file,
		)

	if closeErr := file.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	if err != nil {
		t.Fatal(err)
	}

	if uint64(encodedBytes) != result.EncodedBytes {
		t.Fatalf(
			"encoded bytes = %d, want %d",
			encodedBytes,
			result.EncodedBytes,
		)
	}

	if hex.EncodeToString(
		encodedHasher.Sum(nil),
	) != result.EncodedSHA256 {
		t.Fatal(
			"sealed file SHA-256 does not match result",
		)
	}

	file, err =
		os.Open(result.SealedPath)

	if err != nil {
		t.Fatal(err)
	}

	decoder, err :=
		zstd.NewReader(file)

	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	canonicalHasher :=
		sha256.New()

	canonicalBytes, err :=
		io.Copy(
			canonicalHasher,
			decoder,
		)

	decoder.Close()

	if closeErr := file.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	if err != nil {
		t.Fatal(err)
	}

	if uint64(canonicalBytes) != result.CanonicalBytes {
		t.Fatalf(
			"canonical bytes = %d, want %d",
			canonicalBytes,
			result.CanonicalBytes,
		)
	}

	if hex.EncodeToString(
		canonicalHasher.Sum(nil),
	) != result.CanonicalSHA256 {
		t.Fatal(
			"decoded canonical SHA-256 does not match result",
		)
	}
}

func writeFixtureFiles(
	t *testing.T,
	dir string,
	order []string,
	files map[string][]byte,
) {
	t.Helper()

	for _, name := range order {
		if err := os.WriteFile(
			filepath.Join(
				dir,
				name,
			),
			files[name],
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
}
