// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSORPostgreSQLDatabaseSecret = "0123456789abcdef0123456789abcdef" +
	"0123456789abcdef0123456789abcdef"

const testSORPostgreSQLDatabaseVerifier = "SCRAM-SHA-256$4096:" +
	"RkktdGVzdC1zYWx0LTIwMjY=" +
	"$eDXc5tneh+SNSBqBCDaLd1WpiuTJ4eHd8vZPg1bnAro=" +
	":KsgxdkVmAo252Vl4k333ZYBbB/2HWcQPRKZwBtPNjEg="

func TestParseSORPostgreSQLDatabasePassfileExact(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	content :=
		[]byte(
			policy.PassfilePrefix +
				testSORPostgreSQLDatabaseSecret +
				"\n",
		)

	secret,
		prefixMatches,
		secretValid :=
		parseSORPostgreSQLDatabasePassfile(
			policy,
			content,
		)

	if !prefixMatches {
		t.Fatal(
			"exact passfile prefix did not match",
		)
	}

	if !secretValid {
		t.Fatal(
			"exact passfile secret was rejected",
		)
	}

	if secret !=
		testSORPostgreSQLDatabaseSecret {
		t.Fatal(
			"exact passfile secret changed during parsing",
		)
	}
}

func TestParseSORPostgreSQLDatabasePassfileRejectsWrongEndpoint(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	content :=
		[]byte(
			"10.77.20.99:5432:fi:fi_ingest:" +
				testSORPostgreSQLDatabaseSecret +
				"\n",
		)

	_,
		prefixMatches,
		secretValid :=
		parseSORPostgreSQLDatabasePassfile(
			policy,
			content,
		)

	if prefixMatches ||
		secretValid {
		t.Fatal(
			"wrong PostgreSQL endpoint was accepted",
		)
	}
}

func TestParseSORPostgreSQLDatabasePassfileRejectsUppercaseSecret(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	content :=
		[]byte(
			policy.PassfilePrefix +
				strings.ToUpper(
					testSORPostgreSQLDatabaseSecret,
				) +
				"\n",
		)

	_,
		prefixMatches,
		secretValid :=
		parseSORPostgreSQLDatabasePassfile(
			policy,
			content,
		)

	if !prefixMatches {
		t.Fatal(
			"expected endpoint prefix to match",
		)
	}

	if secretValid {
		t.Fatal(
			"uppercase credential secret was accepted",
		)
	}
}

func TestParseSORPostgreSQLDatabasePassfileRejectsAdditionalLine(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	content :=
		[]byte(
			policy.PassfilePrefix +
				testSORPostgreSQLDatabaseSecret +
				"\n" +
				"unexpected\n",
		)

	_,
		prefixMatches,
		secretValid :=
		parseSORPostgreSQLDatabasePassfile(
			policy,
			content,
		)

	if !prefixMatches {
		t.Fatal(
			"expected endpoint prefix to match",
		)
	}

	if secretValid {
		t.Fatal(
			"multi-line passfile was accepted",
		)
	}
}

func TestVerifySORPostgreSQLDatabaseSCRAMSHA256KnownVector(
	t *testing.T,
) {
	matches, err :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			testSORPostgreSQLDatabaseSecret,
			testSORPostgreSQLDatabaseVerifier,
		)
	if err != nil {
		t.Fatalf(
			"verify SCRAM known vector: %v",
			err,
		)
	}

	if !matches {
		t.Fatal(
			"known SCRAM-SHA-256 vector did not match",
		)
	}
}

func TestVerifySORPostgreSQLDatabaseSCRAMSHA256WrongSecret(
	t *testing.T,
) {
	wrong :=
		"1123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	matches, err :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			wrong,
			testSORPostgreSQLDatabaseVerifier,
		)
	if err != nil {
		t.Fatalf(
			"verify SCRAM wrong secret: %v",
			err,
		)
	}

	if matches {
		t.Fatal(
			"wrong PostgreSQL secret matched SCRAM verifier",
		)
	}
}

func TestVerifySORPostgreSQLDatabaseSCRAMSHA256RejectsMalformed(
	t *testing.T,
) {
	_, err :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			testSORPostgreSQLDatabaseSecret,
			"not-a-scram-verifier",
		)

	if err == nil {
		t.Fatal(
			"malformed SCRAM verifier was accepted",
		)
	}
}

func TestVerifySORPostgreSQLDatabaseSCRAMSHA256BoundsIterations(
	t *testing.T,
) {
	verifier :=
		strings.Replace(
			testSORPostgreSQLDatabaseVerifier,
			"4096:",
			"1000001:",
			1,
		)

	_, err :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			testSORPostgreSQLDatabaseSecret,
			verifier,
		)

	if err == nil {
		t.Fatal(
			"excessive SCRAM iteration count was accepted",
		)
	}
}

func TestInspectSORPostgreSQLDatabasePassfileAbsent(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	policy.PassfilePath =
		filepath.Join(
			t.TempDir(),
			"postgres.pgpass",
		)

	facts,
		secret,
		err :=
		inspectSORPostgreSQLDatabasePassfile(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"inspect absent passfile: %v",
			err,
		)
	}

	if !facts.Observed {
		t.Fatal(
			"absent passfile was not observed",
		)
	}

	if facts.Exists {
		t.Fatal(
			"absent passfile reported present",
		)
	}

	if secret != "" {
		t.Fatal(
			"absent passfile returned a secret",
		)
	}
}

func TestInspectSORPostgreSQLDatabasePassfileContent(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	policy.PassfilePath =
		filepath.Join(
			t.TempDir(),
			"postgres.pgpass",
		)

	content :=
		[]byte(
			policy.PassfilePrefix +
				testSORPostgreSQLDatabaseSecret +
				"\n",
		)

	if err :=
		os.WriteFile(
			policy.PassfilePath,
			content,
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.Chmod(
			policy.PassfilePath,
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	facts,
		secret,
		err :=
		inspectSORPostgreSQLDatabasePassfile(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"inspect passfile: %v",
			err,
		)
	}

	if !facts.Observed ||
		!facts.Exists ||
		!facts.Regular ||
		facts.LinkCount != 1 ||
		facts.Mode != 0o600 ||
		!facts.PrefixMatches ||
		!facts.SecretValid {
		t.Fatalf(
			"unexpected passfile facts: %+v",
			facts,
		)
	}

	if secret !=
		testSORPostgreSQLDatabaseSecret {
		t.Fatal(
			"inspected passfile secret changed",
		)
	}
}

func TestInspectSORPostgreSQLDatabasePassfileRejectsSymlink(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	root :=
		t.TempDir()

	target :=
		filepath.Join(
			root,
			"target",
		)

	policy.PassfilePath =
		filepath.Join(
			root,
			"postgres.pgpass",
		)

	content :=
		[]byte(
			policy.PassfilePrefix +
				testSORPostgreSQLDatabaseSecret +
				"\n",
		)

	if err :=
		os.WriteFile(
			target,
			content,
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.Symlink(
			target,
			policy.PassfilePath,
		); err != nil {
		t.Fatal(err)
	}

	facts,
		secret,
		err :=
		inspectSORPostgreSQLDatabasePassfile(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"inspect symlink passfile: %v",
			err,
		)
	}

	if !facts.Observed ||
		!facts.Exists {
		t.Fatalf(
			"symlink existence was not observed: %+v",
			facts,
		)
	}

	if facts.Regular {
		t.Fatal(
			"passfile symlink classified as regular",
		)
	}

	if secret != "" {
		t.Fatal(
			"passfile symlink was read",
		)
	}
}
