// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSORPostgreSQLPolicyContentExact(t *testing.T) {
	expected := "" +
		"# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-v1\n" +
		"# FI-ROLE: postgresql-rc-policy\n" +
		"\n" +
		"postgresql_enable=\"YES\"\n" +
		"postgresql_user=\"postgres\"\n" +
		"postgresql_data=\"/var/db/fi/sor/postgres\"\n" +
		"postgresql_initdb_flags=\"--encoding=UTF8 --locale=C --data-checksums\"\n"

	if sorPostgreSQLPolicyContent != expected {
		t.Fatalf(
			"PostgreSQL policy content differs from accepted contract:\n%q",
			sorPostgreSQLPolicyContent,
		)
	}
}

func TestClassifySORPostgreSQLPolicyAbsent(t *testing.T) {
	spec := testSORPostgreSQLPolicySpec(
		filepath.Join(
			t.TempDir(),
			"postgresql",
		),
	)

	state := classifySORPostgreSQLPolicy(spec)

	if state != sorPostgreSQLPolicyAbsent {
		t.Fatalf(
			"state = %s, want ABSENT",
			state,
		)
	}
}

func TestClassifySORPostgreSQLPolicyForeignUnmarked(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"postgresql",
	)

	if err := os.WriteFile(
		target,
		[]byte(
			"postgresql_enable=\"YES\"\n",
		),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLPolicySpec(target)

	state := classifySORPostgreSQLPolicy(spec)

	if state != sorPostgreSQLPolicyForeignCollision {
		t.Fatalf(
			"state = %s, want FOREIGN_COLLISION",
			state,
		)
	}
}

func TestClassifySORPostgreSQLPolicyOwnedDrift(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"postgresql",
	)

	content := sorPostgreSQLPolicyContent +
		"# unexpected drift\n"

	if err := os.WriteFile(
		target,
		[]byte(content),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLPolicySpec(target)

	state := classifySORPostgreSQLPolicy(spec)

	if state != sorPostgreSQLPolicyOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestClassifySORPostgreSQLPolicyOwnedMatch(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"postgresql",
	)

	if err := os.WriteFile(
		target,
		[]byte(sorPostgreSQLPolicyContent),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		target,
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLPolicySpec(target)

	state := classifySORPostgreSQLPolicy(spec)

	if state != sorPostgreSQLPolicyOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestClassifySORPostgreSQLPolicyRejectsHardLinkDrift(t *testing.T) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"postgresql",
	)

	other := filepath.Join(
		directory,
		"postgresql.other",
	)

	if err := os.WriteFile(
		target,
		[]byte(sorPostgreSQLPolicyContent),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		target,
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Link(
		target,
		other,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLPolicySpec(target)

	state := classifySORPostgreSQLPolicy(spec)

	if state != sorPostgreSQLPolicyOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestContainsExactLine(t *testing.T) {
	content := []byte(
		"one\n" +
			sorPostgreSQLPolicyMarker +
			"\nthree\n",
	)

	if !containsExactLine(
		content,
		sorPostgreSQLPolicyMarker,
	) {
		t.Fatal(
			"containsExactLine did not find exact marker",
		)
	}

	if containsExactLine(
		content,
		sorPostgreSQLPolicyMarker+"x",
	) {
		t.Fatal(
			"containsExactLine accepted non-exact marker",
		)
	}
}

func TestSORPostgreSQLPolicySpecForConfig(t *testing.T) {
	config := loadTestConfig(t)

	spec := sorPostgreSQLPolicySpecForConfig(config)

	expected := "/usr/local/jails/containers/fi-sor-db/etc/rc.conf.d/postgresql"

	if spec.Target != expected {
		t.Fatalf(
			"target = %q, want %q",
			spec.Target,
			expected,
		)
	}

	if spec.UID != 0 ||
		spec.GID != 0 ||
		spec.Mode != 0o644 {
		t.Fatalf(
			"metadata = %d:%d %o",
			spec.UID,
			spec.GID,
			spec.Mode,
		)
	}
}

func testSORPostgreSQLPolicySpec(
	target string,
) sorPostgreSQLPolicySpec {
	info, err := os.Stat(
		filepath.Dir(target),
	)
	if err != nil {
		panic(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		panic(
			"test directory stat is not syscall.Stat_t",
		)
	}

	return sorPostgreSQLPolicySpec{
		Content: []byte(
			sorPostgreSQLPolicyContent,
		),
		GID:    uint64(stat.Gid),
		Mode:   0o644,
		Target: target,
		UID:    uint64(stat.Uid),
	}
}
