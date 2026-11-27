// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateSealedGenerationRecoversPrePublicationCrashStates(
	t *testing.T,
) {
	tests :=
		[]struct {
			name string

			seed func(
				t *testing.T,
				staleDir string,
				config CreateConfig,
				donor PublishedGeneration,
			)
		}{
			{
				name: "outer provisional directory created",
			},
			{
				name: "sealer provisional payload exists",

				seed: func(
					t *testing.T,
					staleDir string,
					config CreateConfig,
					donor PublishedGeneration,
				) {
					t.Helper()

					path :=
						filepath.Join(
							staleDir,
							".generation-"+
								config.GenerationID+
								"-partial.open",
						)

					if err :=
						os.WriteFile(
							path,
							[]byte(
								"partial-sealer-output",
							),
							0o600,
						); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "sealer completed payload before payload rename",

				seed: func(
					t *testing.T,
					staleDir string,
					config CreateConfig,
					donor PublishedGeneration,
				) {
					t.Helper()

					copyGenerationCrashFixture(
						t,
						donor.PayloadPath,
						filepath.Join(
							staleDir,
							"generation-"+
								config.GenerationID+
								".figz",
						),
					)
				},
			},
			{
				name: "payload renamed before metadata",

				seed: func(
					t *testing.T,
					staleDir string,
					config CreateConfig,
					donor PublishedGeneration,
				) {
					t.Helper()

					copyGenerationCrashFixture(
						t,
						donor.PayloadPath,
						filepath.Join(
							staleDir,
							SealedGenerationPayloadName,
						),
					)
				},
			},
			{
				name: "metadata written before directory publication",

				seed: func(
					t *testing.T,
					staleDir string,
					config CreateConfig,
					donor PublishedGeneration,
				) {
					t.Helper()

					copyGenerationCrashFixture(
						t,
						donor.PayloadPath,
						filepath.Join(
							staleDir,
							SealedGenerationPayloadName,
						),
					)

					copyGenerationCrashFixture(
						t,
						donor.MetadataPath,
						filepath.Join(
							staleDir,
							SignedGenerationMetadataName,
						),
					)
				},
			},
		}

	for _, test := range tests {
		t.Run(
			test.name,
			func(
				t *testing.T,
			) {
				config :=
					testCreateGenerationConfig(
						t,
					)

				donorRoot :=
					filepath.Join(
						t.TempDir(),
						"donor-sealed",
					)

				if err :=
					os.MkdirAll(
						donorRoot,
						0o700,
					); err != nil {
					t.Fatal(err)
				}

				donorConfig :=
					config

				donorConfig.SealedRoot =
					donorRoot

				donor, err :=
					CreateSealedGeneration(
						context.Background(),
						donorConfig,
					)
				if err != nil {
					t.Fatal(err)
				}

				staleDir :=
					filepath.Join(
						config.SealedRoot,
						".generation-"+
							config.GenerationID+
							"-crash.open",
					)

				if err :=
					os.Mkdir(
						staleDir,
						0o700,
					); err != nil {
					t.Fatal(err)
				}

				if test.seed != nil {
					test.seed(
						t,
						staleDir,
						config,
						donor,
					)
				}

				published, err :=
					CreateSealedGeneration(
						context.Background(),
						config,
					)
				if err != nil {
					t.Fatal(err)
				}

				if _,
					err :=
					os.Lstat(
						staleDir,
					); !errors.Is(
					err,
					fs.ErrNotExist,
				) {
					t.Fatalf(
						"abandoned provisional directory remains after recovery: %v",
						err,
					)
				}

				if err :=
					VerifyPublishedGenerationPayload(
						published,
					); err != nil {
					t.Fatal(err)
				}

				entries, err :=
					os.ReadDir(
						config.SealedRoot,
					)
				if err != nil {
					t.Fatal(err)
				}

				prefix :=
					".generation-" +
						config.GenerationID +
						"-"

				for _, entry := range entries {
					if strings.HasPrefix(
						entry.Name(),
						prefix,
					) &&
						strings.HasSuffix(
							entry.Name(),
							".open",
						) {
						t.Fatalf(
							"same-generation provisional directory remains after restart recovery: %q",
							entry.Name(),
						)
					}
				}
			},
		)
	}
}

func TestCreateSealedGenerationFailsClosedOnCorruptPublishedPayload(
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

	var value [1]byte

	if _,
		err :=
		file.ReadAt(
			value[:],
			0,
		); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	value[0] ^= 0xff

	if _,
		err :=
		file.WriteAt(
			value[:],
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

	if _,
		err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		); err == nil {
		t.Fatal(
			"restart accepted corrupt already-published generation",
		)
	}

	if _,
		err :=
		os.Stat(
			published.DirectoryPath,
		); err != nil {
		t.Fatalf(
			"corrupt published generation was silently removed: %v",
			err,
		)
	}

	file, err =
		os.Open(
			published.PayloadPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	var after [1]byte

	if _,
		err :=
		file.Read(
			after[:],
		); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err :=
		file.Close(); err != nil {
		t.Fatal(err)
	}

	if after != value {
		t.Fatal(
			"corrupt durable generation was silently rebuilt or replaced",
		)
	}
}

func TestCreateSealedGenerationLeavesOtherGenerationProvisionalStateAlone(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	other :=
		filepath.Join(
			config.SealedRoot,
			".generation-other-generation-crash.open",
		)

	if err :=
		os.Mkdir(
			other,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			filepath.Join(
				other,
				"partial",
			),
			[]byte(
				"other-generation",
			),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		VerifyPublishedGenerationPayload(
			published,
		); err != nil {
		t.Fatal(err)
	}

	info, err :=
		os.Lstat(
			other,
		)
	if err != nil {
		t.Fatalf(
			"other-generation provisional state was removed: %v",
			err,
		)
	}

	if !info.IsDir() {
		t.Fatal(
			"other-generation provisional state changed type",
		)
	}
}

func copyGenerationCrashFixture(
	t *testing.T,
	source string,
	destination string,
) {
	t.Helper()

	value, err :=
		os.ReadFile(
			source,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			destination,
			value,
			0o600,
		); err != nil {
		t.Fatal(err)
	}
}
