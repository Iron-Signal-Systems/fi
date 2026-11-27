// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"context"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationsealer"
)

func TestDescriptorFromSealBindsExactSealerFacts(
	t *testing.T,
) {
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

	for _, path := range []string{
		frozen,
		sealed,
	} {
		if err :=
			os.MkdirAll(
				path,
				0o700,
			); err != nil {
			t.Fatal(err)
		}
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

	result, err :=
		generationsealer.Seal(
			context.Background(),
			generationsealer.Config{
				FrozenDir: frozen,

				GenerationID: "20260918T133000.000000000Z-0011223344556677",

				SealedDir: sealed,
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	descriptor, err :=
		DescriptorFromSeal(
			"iss-fs-01.iss.local",
			result,
		)
	if err != nil {
		t.Fatal(err)
	}

	if descriptor.GenerationID !=
		result.GenerationID {
		t.Fatalf(
			"descriptor generation ID = %q, want %q",
			descriptor.GenerationID,
			result.GenerationID,
		)
	}

	if descriptor.ArtifactCount !=
		result.FileCount {
		t.Fatalf(
			"descriptor artifact count = %d, want %d",
			descriptor.ArtifactCount,
			result.FileCount,
		)
	}

	if descriptor.SourceBytes !=
		result.SourceBytes {
		t.Fatalf(
			"descriptor source bytes = %d, want %d",
			descriptor.SourceBytes,
			result.SourceBytes,
		)
	}

	if descriptor.CanonicalBytes !=
		result.CanonicalBytes {
		t.Fatalf(
			"descriptor canonical bytes = %d, want %d",
			descriptor.CanonicalBytes,
			result.CanonicalBytes,
		)
	}

	if descriptor.CanonicalSHA256 !=
		result.CanonicalSHA256 {
		t.Fatalf(
			"descriptor canonical SHA-256 = %q, want %q",
			descriptor.CanonicalSHA256,
			result.CanonicalSHA256,
		)
	}

	if descriptor.EncodedDataBytes !=
		result.EncodedBytes {
		t.Fatalf(
			"descriptor encoded bytes = %d, want %d",
			descriptor.EncodedDataBytes,
			result.EncodedBytes,
		)
	}

	if descriptor.EncodedDataSHA256 !=
		result.EncodedSHA256 {
		t.Fatalf(
			"descriptor encoded SHA-256 = %q, want %q",
			descriptor.EncodedDataSHA256,
			result.EncodedSHA256,
		)
	}

	if descriptor.CanonicalVersion !=
		generationsealer.CanonicalVersion {
		t.Fatalf(
			"descriptor canonical version = %q, want %q",
			descriptor.CanonicalVersion,
			generationsealer.CanonicalVersion,
		)
	}

	key, certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	signed, err :=
		NewSignedGeneration(
			descriptor,
			certificate,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err :=
		signed.BatchSigningCertificate()
	if err != nil {
		t.Fatal(err)
	}

	publicKey, ok :=
		parsed.PublicKey.(*rsa.PublicKey)

	if !ok ||
		publicKey == nil {
		t.Fatal(
			"signed generation certificate is not RSA",
		)
	}

	if err :=
		VerifySignedGenerationSignature(
			signed,
			publicKey,
		); err != nil {
		t.Fatal(err)
	}
}

func TestDescriptorFromSealRejectsIncompleteResult(
	t *testing.T,
) {
	_,
		err :=
		DescriptorFromSeal(
			"iss-fs-01.iss.local",
			generationsealer.Result{},
		)

	if err == nil {
		t.Fatal(
			"incomplete generation sealer result accepted",
		)
	}
}
