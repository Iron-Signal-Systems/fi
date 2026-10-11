package backendinstall

import (
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabaseReadyHBAContract(
	t *testing.T,
) {
	config := loadTestConfig(t)

	policy, err :=
		buildSORPostgreSQLClusterPolicy(
			config,
		)
	if err != nil {
		t.Fatalf(
			"buildSORPostgreSQLClusterPolicy() error = %v",
			err,
		)
	}

	actual :=
		string(
			policy.HBADatabaseReadyContent,
		)

	required := []string{
		"# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-hba-v1",
		"# FI-ROLE: postgresql-client-authentication",
		"# Database-ready state:",
		"local   all       all                 peer",
		"host    fi        fi_ingest  10.77.20.21/32  scram-sha-256",
	}

	for _, line := range required {
		if !strings.Contains(
			actual,
			line,
		) {
			t.Fatalf(
				"database-ready HBA missing %q:\n%s",
				line,
				actual,
			)
		}
	}

	if strings.Contains(
		actual,
		"no remote database clients",
	) {
		t.Fatalf(
			"database-ready HBA retained initial-state prohibition:\n%s",
			actual,
		)
	}
}

func TestSORPostgreSQLClusterPolicyAcceptsExactHBAStages(
	t *testing.T,
) {
	root, uid, gid :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	policy :=
		testSORPostgreSQLClusterPolicy(
			t,
			root,
		)

	writeTestSORPostgreSQLManagedClusterPolicy(
		t,
		policy,
	)

	stages := []struct {
		Name    string
		Content []byte
	}{
		{
			Name:    "initial",
			Content: policy.HBAContent,
		},
		{
			Name:    "database-ready",
			Content: policy.HBADatabaseReadyContent,
		},
	}

	for _, stage := range stages {
		stage := stage

		t.Run(
			stage.Name,
			func(t *testing.T) {
				writeTestSORPostgreSQLPolicyFile(
					t,
					policy.HBAPath,
					stage.Content,
				)

				state :=
					classifySORPostgreSQLClusterPolicy(
						policy,
						uid,
						gid,
					)

				if state !=
					sorPostgreSQLClusterPolicyOwnedMatch {
					t.Fatalf(
						"policy state = %s, want %s",
						state,
						sorPostgreSQLClusterPolicyOwnedMatch,
					)
				}
			},
		)
	}
}

func TestSORPostgreSQLClusterPolicyRejectsUnknownFIHBAStage(
	t *testing.T,
) {
	root, uid, gid :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	policy :=
		testSORPostgreSQLClusterPolicy(
			t,
			root,
		)

	writeTestSORPostgreSQLManagedClusterPolicy(
		t,
		policy,
	)

	badHBA := []byte(
		strings.Replace(
			string(
				policy.HBADatabaseReadyContent,
			),
			"10.77.20.21/32",
			"10.77.20.99/32",
			1,
		),
	)

	writeTestSORPostgreSQLPolicyFile(
		t,
		policy.HBAPath,
		badHBA,
	)

	state :=
		classifySORPostgreSQLClusterPolicy(
			policy,
			uid,
			gid,
		)

	if state !=
		sorPostgreSQLClusterPolicyOwnedDrift {
		t.Fatalf(
			"policy state = %s, want %s",
			state,
			sorPostgreSQLClusterPolicyOwnedDrift,
		)
	}
}
