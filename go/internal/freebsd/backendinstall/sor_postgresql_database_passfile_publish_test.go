// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSORPostgreSQLDatabasePassfileContentExact(
	t *testing.T,
) {
	policy :=
		sorPostgreSQLDatabasePolicy{
			PassfilePath:   "/var/db/fi/config/ingest/postgres.pgpass",
			PassfilePrefix: "10.77.20.22:5432:fi:fi_ingest:",
		}

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	content, err :=
		buildSORPostgreSQLDatabasePassfileContent(
			policy,
			secret,
		)
	if err != nil {
		t.Fatalf(
			"build passfile: %v",
			err,
		)
	}

	expected :=
		policy.PassfilePrefix +
			secret +
			"\n"

	if string(content) != expected {
		t.Fatalf(
			"passfile content = %q, want %q",
			string(content),
			expected,
		)
	}
}

func TestBuildSORPostgreSQLDatabasePassfileContentRejectsInvalidAuthority(
	t *testing.T,
) {
	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	tests :=
		[]struct {
			name   string
			policy sorPostgreSQLDatabasePolicy
			secret string
		}{
			{
				name: "empty path",
				policy: sorPostgreSQLDatabasePolicy{
					PassfilePrefix: "host:5432:fi:fi_ingest:",
				},
				secret: secret,
			},
			{
				name: "empty prefix",
				policy: sorPostgreSQLDatabasePolicy{
					PassfilePath: "/tmp/postgres.pgpass",
				},
				secret: secret,
			},
			{
				name: "invalid secret",
				policy: sorPostgreSQLDatabasePolicy{
					PassfilePath:   "/tmp/postgres.pgpass",
					PassfilePrefix: "host:5432:fi:fi_ingest:",
				},
				secret: "not-a-valid-secret",
			},
		}

	for _, testCase := range tests {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				if _, err :=
					buildSORPostgreSQLDatabasePassfileContent(
						testCase.policy,
						testCase.secret,
					); err == nil {
					t.Fatal(
						"invalid passfile authority accepted",
					)
				}
			},
		)
	}
}

func TestPublishSORPostgreSQLDatabasePassfileWithExactComposition(
	t *testing.T,
) {
	directory :=
		t.TempDir()

	policy :=
		sorPostgreSQLDatabasePolicy{
			PassfilePath: filepath.Join(
				directory,
				"postgres.pgpass",
			),
			PassfilePrefix: "10.77.20.22:5432:fi:fi_ingest:",
		}

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	expectedContent :=
		[]byte(
			policy.PassfilePrefix +
				secret +
				"\n",
		)

	temp :=
		filepath.Join(
			directory,
			".synthetic-stage",
		)

	calls :=
		make(
			[]string,
			0,
			4,
		)

	err :=
		publishSORPostgreSQLDatabasePassfileWith(
			policy,
			secret,
			func(
				target string,
				content []byte,
				uid uint64,
				gid uint64,
			) (string, error) {
				calls =
					append(
						calls,
						"stage",
					)

				if target !=
					policy.PassfilePath {
					t.Fatalf(
						"stage target = %q",
						target,
					)
				}

				if string(content) !=
					string(expectedContent) {
					t.Fatalf(
						"stage content changed",
					)
				}

				if uid !=
					sorPostgreSQLDatabasePassfileUID ||
					gid !=
						sorPostgreSQLDatabasePassfileGID {
					t.Fatalf(
						"stage ownership = %d:%d",
						uid,
						gid,
					)
				}

				return temp, nil
			},
			func(
				observedTemp string,
				target string,
				content []byte,
				uid uint64,
				gid uint64,
			) error {
				calls =
					append(
						calls,
						"publish",
					)

				if observedTemp != temp {
					t.Fatalf(
						"publish temp = %q",
						observedTemp,
					)
				}

				if target !=
					policy.PassfilePath {
					t.Fatalf(
						"publish target = %q",
						target,
					)
				}

				if string(content) !=
					string(expectedContent) {
					t.Fatalf(
						"publish content changed",
					)
				}

				if uid !=
					sorPostgreSQLDatabasePassfileUID ||
					gid !=
						sorPostgreSQLDatabasePassfileGID {
					t.Fatalf(
						"publish ownership = %d:%d",
						uid,
						gid,
					)
				}

				return nil
			},
			func(
				path string,
			) error {
				calls =
					append(
						calls,
						"sync",
					)

				if path != directory {
					t.Fatalf(
						"sync directory = %q, want %q",
						path,
						directory,
					)
				}

				return nil
			},
			func(
				observedPolicy sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				calls =
					append(
						calls,
						"inspect",
					)

				if observedPolicy.PassfilePath !=
					policy.PassfilePath {
					t.Fatalf(
						"inspection policy path changed",
					)
				}

				return sorPostgreSQLDatabasePassfileFacts{
						Exists:        true,
						GID:           sorPostgreSQLDatabasePassfileGID,
						LinkCount:     1,
						Mode:          sorPostgreSQLDatabasePassfileMode,
						Observed:      true,
						PrefixMatches: true,
						Regular:       true,
						SecretValid:   true,
						UID:           sorPostgreSQLDatabasePassfileUID,
					},
					secret,
					nil
			},
		)
	if err != nil {
		t.Fatalf(
			"publish passfile: %v",
			err,
		)
	}

	if strings.Join(
		calls,
		",",
	) != "stage,publish,sync,inspect" {
		t.Fatalf(
			"call order = %q",
			strings.Join(
				calls,
				",",
			),
		)
	}
}

func TestPublishSORPostgreSQLDatabasePassfileWithStopsOnPublicationFailure(
	t *testing.T,
) {
	directory :=
		t.TempDir()

	policy :=
		sorPostgreSQLDatabasePolicy{
			PassfilePath: filepath.Join(
				directory,
				"postgres.pgpass",
			),
			PassfilePrefix: "10.77.20.22:5432:fi:fi_ingest:",
		}

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	sentinel :=
		errors.New(
			"synthetic publication failure",
		)

	syncCalls := 0
	inspectCalls := 0

	err :=
		publishSORPostgreSQLDatabasePassfileWith(
			policy,
			secret,
			func(
				string,
				[]byte,
				uint64,
				uint64,
			) (string, error) {
				return filepath.Join(
						directory,
						".synthetic-stage",
					),
					nil
			},
			func(
				string,
				string,
				[]byte,
				uint64,
				uint64,
			) error {
				return sentinel
			},
			func(
				string,
			) error {
				syncCalls++

				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				inspectCalls++

				return sorPostgreSQLDatabasePassfileFacts{},
					"",
					nil
			},
		)

	if err == nil {
		t.Fatal(
			"publication failure was accepted",
		)
	}

	if !errors.Is(
		err,
		sentinel,
	) {
		t.Fatalf(
			"error = %v, want wrapped sentinel",
			err,
		)
	}

	if syncCalls != 0 {
		t.Fatalf(
			"directory sync called after publication failure: %d",
			syncCalls,
		)
	}

	if inspectCalls != 0 {
		t.Fatalf(
			"inspection called after publication failure: %d",
			inspectCalls,
		)
	}
}

func TestPublishSORPostgreSQLDatabasePassfileWithRejectsFinalDrift(
	t *testing.T,
) {
	directory :=
		t.TempDir()

	policy :=
		sorPostgreSQLDatabasePolicy{
			PassfilePath: filepath.Join(
				directory,
				"postgres.pgpass",
			),
			PassfilePrefix: "10.77.20.22:5432:fi:fi_ingest:",
		}

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	err :=
		publishSORPostgreSQLDatabasePassfileWith(
			policy,
			secret,
			func(
				string,
				[]byte,
				uint64,
				uint64,
			) (string, error) {
				return filepath.Join(
						directory,
						".synthetic-stage",
					),
					nil
			},
			func(
				string,
				string,
				[]byte,
				uint64,
				uint64,
			) error {
				return nil
			},
			func(
				string,
			) error {
				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				return sorPostgreSQLDatabasePassfileFacts{
						Exists:        true,
						GID:           sorPostgreSQLDatabasePassfileGID,
						LinkCount:     1,
						Mode:          0o644,
						Observed:      true,
						PrefixMatches: true,
						Regular:       true,
						SecretValid:   true,
						UID:           sorPostgreSQLDatabasePassfileUID,
					},
					secret,
					nil
			},
		)

	if err == nil {
		t.Fatal(
			"drifted published passfile was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"OWNED_DRIFT",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestStageSORPostgreSQLDatabasePassfileWithExactArtifact(
	t *testing.T,
) {
	policy :=
		sorPostgreSQLDatabasePolicy{
			PassfilePath:   "/var/db/fi/config/ingest/postgres.pgpass",
			PassfilePrefix: "10.77.20.22:5432:fi:fi_ingest:",
		}

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	temp :=
		"/var/db/fi/config/ingest/.synthetic-stage"

	staged, err :=
		stageSORPostgreSQLDatabasePassfileWith(
			policy,
			secret,
			func(
				target string,
				content []byte,
				uid uint64,
				gid uint64,
			) (
				string,
				error,
			) {
				if target !=
					policy.PassfilePath {
					t.Fatalf(
						"target = %q",
						target,
					)
				}

				expected :=
					policy.PassfilePrefix +
						secret +
						"\n"

				if string(content) !=
					expected {
					t.Fatalf(
						"content = %q, want %q",
						string(content),
						expected,
					)
				}

				if uid !=
					sorPostgreSQLDatabasePassfileUID ||
					gid !=
						sorPostgreSQLDatabasePassfileGID {
					t.Fatalf(
						"ownership = %d:%d",
						uid,
						gid,
					)
				}

				return temp, nil
			},
		)
	if err != nil {
		t.Fatalf(
			"stage passfile: %v",
			err,
		)
	}

	if staged.Temp !=
		temp {
		t.Fatalf(
			"staged temp = %q, want %q",
			staged.Temp,
			temp,
		)
	}

	if err :=
		validateSORPostgreSQLDatabaseStagedPassfile(
			policy,
			secret,
			staged,
		); err != nil {
		t.Fatalf(
			"validate staged passfile: %v",
			err,
		)
	}
}

func TestPublishStagedSORPostgreSQLDatabasePassfileWithRejectsChangedArtifact(
	t *testing.T,
) {
	policy :=
		sorPostgreSQLDatabasePolicy{
			PassfilePath:   "/var/db/fi/config/ingest/postgres.pgpass",
			PassfilePrefix: "10.77.20.22:5432:fi:fi_ingest:",
		}

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	publishCalls :=
		0

	err :=
		publishStagedSORPostgreSQLDatabasePassfileWith(
			policy,
			secret,
			sorPostgreSQLDatabaseStagedPassfile{
				Content: []byte(
					"changed after staging\n",
				),
				Temp: "/tmp/.synthetic-stage",
			},
			func(
				string,
				string,
				[]byte,
				uint64,
				uint64,
			) error {
				publishCalls++

				return nil
			},
			func(
				string,
			) error {
				t.Fatal(
					"directory sync ran for changed staged artifact",
				)

				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				t.Fatal(
					"inspection ran for changed staged artifact",
				)

				return sorPostgreSQLDatabasePassfileFacts{},
					"",
					nil
			},
		)

	if err == nil {
		t.Fatal(
			"changed staged passfile was accepted",
		)
	}

	if publishCalls != 0 {
		t.Fatalf(
			"publication calls = %d, want 0",
			publishCalls,
		)
	}
}
