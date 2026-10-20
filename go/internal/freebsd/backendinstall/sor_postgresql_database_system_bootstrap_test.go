// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSystemSORPostgreSQLDatabaseBootstrapperExactLifecycle(
	t *testing.T,
) {
	plan :=
		testSORPostgreSQLDatabaseSystemBootstrapPlan(
			t,
		)

	calls :=
		make(
			[]string,
			0,
			20,
		)

	running :=
		false

	bootstrapper :=
		systemSORPostgreSQLDatabaseBootstrapper{
			stagePassfile: func(
				policy sorPostgreSQLDatabasePolicy,
				secret string,
			) (
				sorPostgreSQLDatabaseStagedPassfile,
				error,
			) {
				return testSORPostgreSQLDatabaseSystemBootstrapStagedPassfile(
					t,
					policy,
					secret,
				), nil
			},

			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				call :=
					path

				if len(args) != 0 {
					call +=
						" " +
							strings.Join(
								args,
								" ",
							)
				}

				calls =
					append(
						calls,
						call,
					)

				switch path {
				case "/usr/sbin/jls":
					if len(args) != 2 ||
						args[0] != "-j" {
						t.Fatalf(
							"unexpected jls args: %#v",
							args,
						)
					}

					jailName :=
						args[1]

					if jailName ==
						"fi-sor-db" &&
						running {
						return []byte(
								"JID IP Address Hostname Path\n",
							),
							nil
					}

					return testSORPostgreSQLDatabaseSystemBootstrapJLSAbsent(
						jailName,
					)

				case "/usr/local/etc/rc.d/fi_pf":
					if !reflect.DeepEqual(
						args,
						[]string{
							"onestatus",
						},
					) {
						t.Fatalf(
							"unexpected PF args: %#v",
							args,
						)
					}

					return nil, nil

				case "/etc/rc.d/jail":
					if reflect.DeepEqual(
						args,
						[]string{
							"onestart",
							"fi-sor-db",
						},
					) {
						if running {
							t.Fatal(
								"fi-sor-db started twice",
							)
						}

						running =
							true

						return nil, nil
					}

					if reflect.DeepEqual(
						args,
						[]string{
							"onestop",
							"fi-sor-db",
						},
					) {
						if !running {
							t.Fatal(
								"fi-sor-db stopped while not running",
							)
						}

						running =
							false

						return nil, nil
					}

					t.Fatalf(
						"unexpected jail args: %#v",
						args,
					)

				case "/usr/sbin/jexec":
					expected :=
						[]string{
							"fi-sor-db",
							"/usr/sbin/service",
							"postgresql",
							"onestatus",
						}

					if !reflect.DeepEqual(
						args,
						expected,
					) {
						t.Fatalf(
							"unexpected jexec args: %#v",
							args,
						)
					}

					if !running {
						t.Fatal(
							"PostgreSQL runtime checked while jail stopped",
						)
					}

					return nil, nil

				default:
					t.Fatalf(
						"unexpected command: %s %#v",
						path,
						args,
					)
				}

				return nil, nil
			},

			executeSQL: func(
				database string,
				sql []byte,
			) error {
				if !running {
					t.Fatal(
						"plain SQL executed while jail stopped",
					)
				}

				calls =
					append(
						calls,
						"SQL "+
							database+
							" "+
							testSORPostgreSQLDatabaseSystemBootstrapSQLPhase(
								t,
								sql,
							),
					)

				return nil
			},

			executeSQLAsRole: func(
				database string,
				role string,
				sql []byte,
			) error {
				if !running {
					t.Fatal(
						"role SQL executed while jail stopped",
					)
				}

				calls =
					append(
						calls,
						"MIGRATION "+
							database+
							" "+
							role+
							" "+
							testSORPostgreSQLDatabaseSystemBootstrapMigrationName(
								t,
								plan,
								sql,
							),
					)

				return nil
			},

			publishPassfile: func(
				policy sorPostgreSQLDatabasePolicy,
				secret string,
			) error {
				if !running {
					t.Fatal(
						"passfile published while jail stopped",
					)
				}

				if policy.PassfilePath !=
					plan.Policy.PassfilePath {
					t.Fatal(
						"passfile policy changed",
					)
				}

				if secret !=
					plan.Secret {
					t.Fatal(
						"passfile secret changed",
					)
				}

				calls =
					append(
						calls,
						"PUBLISH PASSFILE",
					)

				return nil
			},

			verifySubstrate: func(
				Config,
			) error {
				calls =
					append(
						calls,
						"VERIFY SUBSTRATE",
					)

				return nil
			},
		}

	if err :=
		bootstrapper.Apply(
			Config{},
			plan,
		); err != nil {
		t.Fatalf(
			"apply system bootstrap: %v",
			err,
		)
	}

	if running {
		t.Fatal(
			"fi-sor-db remained running after bootstrap",
		)
	}

	expected :=
		[]string{
			"/usr/sbin/jls -j fi-sor-db",
			"/usr/sbin/jls -j fi-ingest",
			"/usr/sbin/jls -j fi-receiver",
			"VERIFY SUBSTRATE",
			"/usr/local/etc/rc.d/fi_pf onestatus",
			"/etc/rc.d/jail onestart fi-sor-db",
			"/usr/sbin/jls -j fi-sor-db",
			"/usr/sbin/jexec fi-sor-db /usr/sbin/service postgresql onestatus",
			"SQL postgres roles",
			"SQL postgres database",
			"SQL postgres database-hardening",
			"SQL fi local-hardening",
			"MIGRATION fi fi_owner 0001_relational.sql",
			"MIGRATION fi fi_owner 0002_source_families.sql",
			"MIGRATION fi fi_owner 0003_usn_relational_identity.sql",
			"MIGRATION fi fi_owner 0004_security_field_name_index.sql",
			"SQL fi schema-authority",
			"PUBLISH PASSFILE",
			"/etc/rc.d/jail onestop fi-sor-db",
			"/usr/sbin/jls -j fi-sor-db",
		}

	if !reflect.DeepEqual(
		calls,
		expected,
	) {
		t.Fatalf(
			"system bootstrap calls:\ngot:  %#v\nwant: %#v",
			calls,
			expected,
		)
	}
}

func TestSystemSORPostgreSQLDatabaseBootstrapperRejectsInvalidPlanBeforeLifecycle(
	t *testing.T,
) {
	commandCalls := 0
	sqlCalls := 0
	publishCalls := 0
	substrateCalls := 0

	bootstrapper :=
		systemSORPostgreSQLDatabaseBootstrapper{
			stagePassfile: func(
				policy sorPostgreSQLDatabasePolicy,
				secret string,
			) (
				sorPostgreSQLDatabaseStagedPassfile,
				error,
			) {
				return testSORPostgreSQLDatabaseSystemBootstrapStagedPassfile(
					t,
					policy,
					secret,
				), nil
			},

			execute: func(
				string,
				...string,
			) ([]byte, error) {
				commandCalls++

				return nil, nil
			},

			executeSQL: func(
				string,
				[]byte,
			) error {
				sqlCalls++

				return nil
			},

			executeSQLAsRole: func(
				string,
				string,
				[]byte,
			) error {
				sqlCalls++

				return nil
			},

			publishPassfile: func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				publishCalls++

				return nil
			},

			verifySubstrate: func(
				Config,
			) error {
				substrateCalls++

				return nil
			},
		}

	err :=
		bootstrapper.Apply(
			Config{},
			sorPostgreSQLDatabaseBootstrapPlan{},
		)

	if err == nil {
		t.Fatal(
			"system bootstrap accepted empty plan",
		)
	}

	if commandCalls != 0 ||
		sqlCalls != 0 ||
		publishCalls != 0 ||
		substrateCalls != 0 {
		t.Fatalf(
			"invalid plan crossed lifecycle boundary: commands=%d sql=%d publish=%d substrate=%d",
			commandCalls,
			sqlCalls,
			publishCalls,
			substrateCalls,
		)
	}
}

func TestSystemSORPostgreSQLDatabaseBootstrapperCleansUpAfterApplyFailure(
	t *testing.T,
) {
	plan :=
		testSORPostgreSQLDatabaseSystemBootstrapPlan(
			t,
		)

	sentinel :=
		errors.New(
			"synthetic SQL failure",
		)

	running :=
		false

	stopped :=
		false

	sqlCalls :=
		0

	bootstrapper :=
		systemSORPostgreSQLDatabaseBootstrapper{
			stagePassfile: func(
				policy sorPostgreSQLDatabasePolicy,
				secret string,
			) (
				sorPostgreSQLDatabaseStagedPassfile,
				error,
			) {
				return testSORPostgreSQLDatabaseSystemBootstrapStagedPassfile(
					t,
					policy,
					secret,
				), nil
			},

			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				switch path {
				case "/usr/sbin/jls":
					jailName :=
						args[1]

					if jailName ==
						"fi-sor-db" &&
						running {
						return nil, nil
					}

					return testSORPostgreSQLDatabaseSystemBootstrapJLSAbsent(
						jailName,
					)

				case "/usr/local/etc/rc.d/fi_pf":
					return nil, nil

				case "/etc/rc.d/jail":
					if args[0] ==
						"onestart" {
						running =
							true

						return nil, nil
					}

					if args[0] ==
						"onestop" {
						running =
							false

						stopped =
							true

						return nil, nil
					}

				case "/usr/sbin/jexec":
					if !running {
						t.Fatal(
							"runtime verified while jail stopped",
						)
					}

					return nil, nil
				}

				return nil, nil
			},

			executeSQL: func(
				string,
				[]byte,
			) error {
				sqlCalls++

				return sentinel
			},

			executeSQLAsRole: func(
				string,
				string,
				[]byte,
			) error {
				t.Fatal(
					"migration executed after first SQL failure",
				)

				return nil
			},

			publishPassfile: func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				t.Fatal(
					"passfile published after SQL failure",
				)

				return nil
			},

			verifySubstrate: func(
				Config,
			) error {
				return nil
			},
		}

	err :=
		bootstrapper.Apply(
			Config{},
			plan,
		)

	if err == nil {
		t.Fatal(
			"system bootstrap accepted SQL failure",
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

	if sqlCalls != 1 {
		t.Fatalf(
			"SQL calls = %d, want 1",
			sqlCalls,
		)
	}

	if running {
		t.Fatal(
			"fi-sor-db remained running after SQL failure",
		)
	}

	if !stopped {
		t.Fatal(
			"emergency jail cleanup did not run",
		)
	}
}

func TestSystemSORPostgreSQLDatabaseBootstrapperStopsBeforeSubstrateFailure(
	t *testing.T,
) {
	plan :=
		testSORPostgreSQLDatabaseSystemBootstrapPlan(
			t,
		)

	sentinel :=
		errors.New(
			"synthetic substrate failure",
		)

	started :=
		false

	bootstrapper :=
		systemSORPostgreSQLDatabaseBootstrapper{
			stagePassfile: func(
				policy sorPostgreSQLDatabasePolicy,
				secret string,
			) (
				sorPostgreSQLDatabaseStagedPassfile,
				error,
			) {
				return testSORPostgreSQLDatabaseSystemBootstrapStagedPassfile(
					t,
					policy,
					secret,
				), nil
			},

			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				if path ==
					"/usr/sbin/jls" {
					return testSORPostgreSQLDatabaseSystemBootstrapJLSAbsent(
						args[1],
					)
				}

				if path ==
					"/etc/rc.d/jail" {
					started =
						true
				}

				return nil, nil
			},

			executeSQL: func(
				string,
				[]byte,
			) error {
				t.Fatal(
					"SQL executed after substrate failure",
				)

				return nil
			},

			executeSQLAsRole: func(
				string,
				string,
				[]byte,
			) error {
				t.Fatal(
					"migration executed after substrate failure",
				)

				return nil
			},

			publishPassfile: func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				t.Fatal(
					"passfile published after substrate failure",
				)

				return nil
			},

			verifySubstrate: func(
				Config,
			) error {
				return sentinel
			},
		}

	err :=
		bootstrapper.Apply(
			Config{},
			plan,
		)

	if err == nil {
		t.Fatal(
			"system bootstrap accepted substrate failure",
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

	if started {
		t.Fatal(
			"fi-sor-db started after substrate failure",
		)
	}
}

func testSORPostgreSQLDatabaseSystemBootstrapJLSAbsent(
	jailName string,
) (
	[]byte,
	error,
) {
	return []byte(
			fmt.Sprintf(
				"jls: jail %q not found\n"+
					"JID IP Address Hostname Path\n",
				jailName,
			),
		),
		errors.New(
			"synthetic jls absent",
		)
}

func testSORPostgreSQLDatabaseSystemBootstrapMigrationName(
	t *testing.T,
	plan sorPostgreSQLDatabaseBootstrapPlan,
	sql []byte,
) string {
	t.Helper()

	for _, asset := range plan.Assets {
		if string(sql) ==
			asset.SQL {
			return asset.Name
		}
	}

	t.Fatalf(
		"unrecognized migration SQL",
	)

	return ""
}

func testSORPostgreSQLDatabaseSystemBootstrapPlan(
	t *testing.T,
) sorPostgreSQLDatabaseBootstrapPlan {
	t.Helper()

	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			strings.NewReader(
				strings.Repeat(
					"z",
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
		)
	if err != nil {
		t.Fatalf(
			"generate test SCRAM verifier: %v",
			err,
		)
	}

	plan, err :=
		prepareSORPostgreSQLDatabaseBootstrapWith(
			policy,
			assets,
			func() (
				string,
				error,
			) {
				return secret, nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				return verifier, nil
			},
		)
	if err != nil {
		t.Fatalf(
			"prepare test bootstrap plan: %v",
			err,
		)
	}

	return plan
}

func testSORPostgreSQLDatabaseSystemBootstrapSQLPhase(
	t *testing.T,
	sql []byte,
) string {
	t.Helper()

	text :=
		string(sql)

	switch {
	case strings.Contains(
		text,
		"CREATE ROLE",
	):
		return "roles"

	case strings.Contains(
		text,
		"CREATE DATABASE",
	):
		return "database"

	case strings.Contains(
		text,
		"REVOKE ALL ON DATABASE",
	):
		return "database-hardening"

	case strings.Contains(
		text,
		"REVOKE CREATE ON SCHEMA public",
	):
		return "local-hardening"

	case strings.Contains(
		text,
		"COMMENT ON SCHEMA",
	):
		return "schema-authority"

	default:
		t.Fatalf(
			"unrecognized bootstrap SQL",
		)
	}

	return ""
}

func TestSystemSORPostgreSQLDatabaseBootstrapperStagingFailurePrecedesJailStart(
	t *testing.T,
) {
	plan :=
		testSORPostgreSQLDatabaseSystemBootstrapPlan(
			t,
		)

	sentinel :=
		errors.New(
			"synthetic passfile staging failure",
		)

	started :=
		false

	sqlCalls :=
		0

	bootstrapper :=
		systemSORPostgreSQLDatabaseBootstrapper{
			stagePassfile: func(
				sorPostgreSQLDatabasePolicy,
				string,
			) (
				sorPostgreSQLDatabaseStagedPassfile,
				error,
			) {
				if started {
					t.Fatal(
						"passfile staging occurred after jail start",
					)
				}

				return sorPostgreSQLDatabaseStagedPassfile{},
					sentinel
			},

			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				switch path {
				case "/usr/sbin/jls":
					return testSORPostgreSQLDatabaseSystemBootstrapJLSAbsent(
						args[1],
					)

				case "/usr/local/etc/rc.d/fi_pf":
					return nil, nil

				case "/etc/rc.d/jail":
					if len(args) != 0 &&
						args[0] == "onestart" {
						started =
							true
					}

					return nil, nil
				}

				return nil, nil
			},

			executeSQL: func(
				string,
				[]byte,
			) error {
				sqlCalls++

				return nil
			},

			executeSQLAsRole: func(
				string,
				string,
				[]byte,
			) error {
				sqlCalls++

				return nil
			},

			publishPassfile: func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				t.Fatal(
					"passfile publication ran after staging failure",
				)

				return nil
			},

			verifySubstrate: func(
				Config,
			) error {
				return nil
			},
		}

	err :=
		bootstrapper.Apply(
			Config{},
			plan,
		)

	if err == nil {
		t.Fatal(
			"system bootstrap accepted passfile staging failure",
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

	if started {
		t.Fatal(
			"fi-sor-db started after passfile staging failure",
		)
	}

	if sqlCalls != 0 {
		t.Fatalf(
			"SQL calls after passfile staging failure = %d, want 0",
			sqlCalls,
		)
	}
}

func testSORPostgreSQLDatabaseSystemBootstrapStagedPassfile(
	t *testing.T,
	policy sorPostgreSQLDatabasePolicy,
	secret string,
) sorPostgreSQLDatabaseStagedPassfile {
	t.Helper()

	content, err :=
		buildSORPostgreSQLDatabasePassfileContent(
			policy,
			secret,
		)
	if err != nil {
		t.Fatalf(
			"build synthetic staged passfile: %v",
			err,
		)
	}

	return sorPostgreSQLDatabaseStagedPassfile{
		Content: content,
		Temp: t.TempDir() +
			"/.synthetic-postgres-pgpass-stage",
	}
}
