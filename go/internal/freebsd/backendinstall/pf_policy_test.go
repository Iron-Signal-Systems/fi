// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestRenderPFPolicy(t *testing.T) {
	config := loadTestConfig(t)

	content, err := renderPFPolicy(
		pfPolicyAsset,
		config,
	)
	if err != nil {
		t.Fatalf(
			"renderPFPolicy() error = %v",
			err,
		)
	}

	rendered := string(content)

	if hostFileTokenPattern.MatchString(
		rendered,
	) {
		t.Fatal(
			"rendered PF policy contains unresolved template token",
		)
	}

	ingestIP, err := pfAddressOnly(
		"FI_INGEST_WORK_ADDRESS",
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	sorIP, err := pfAddressOnly(
		"FI_SOR_DB_WORK_ADDRESS",
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(
		rendered,
		"from "+ingestIP+" to "+sorIP+" port 5432",
	) {
		t.Fatal(
			"rendered PF policy lacks exact ingest-to-SOR PostgreSQL rule",
		)
	}

	if strings.Contains(
		rendered,
		config.Value("FI_INGEST_WORK_ADDRESS"),
	) {
		t.Fatal(
			"rendered PF PostgreSQL rule retained ingest CIDR prefix",
		)
	}

	if strings.Contains(
		rendered,
		config.Value("FI_SOR_DB_WORK_ADDRESS"),
	) {
		t.Fatal(
			"rendered PF PostgreSQL rule retained SOR CIDR prefix",
		)
	}
}

func TestRenderPFPolicyRejectsUnknownToken(t *testing.T) {
	config := loadTestConfig(t)

	_, err := renderPFPolicy(
		pfPolicyAsset+"\n@FI_NOT_A_REAL_KEY@\n",
		config,
	)

	if err == nil {
		t.Fatal(
			"renderPFPolicy accepted unknown template token",
		)
	}
}

func TestClassifyPFPolicyAbsent(t *testing.T) {
	spec := testPFPolicySpec(
		filepath.Join(
			t.TempDir(),
			"pf.conf",
		),
	)

	if state := classifyPFPolicy(
		spec,
	); state != pfPolicyAbsent {
		t.Fatalf(
			"state = %s, want ABSENT",
			state,
		)
	}
}

func TestClassifyPFPolicyForeignCollision(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"pf.conf",
	)

	if err := os.WriteFile(
		target,
		[]byte("pass all\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	spec := testPFPolicySpec(
		target,
	)

	if state := classifyPFPolicy(
		spec,
	); state != pfPolicyForeignCollision {
		t.Fatalf(
			"state = %s, want FOREIGN_COLLISION",
			state,
		)
	}
}

func TestClassifyPFPolicyOwnedDrift(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"pf.conf",
	)

	content := []byte(
		pfPolicyMarker +
			"\n" +
			"# FI-ROLE: " +
			pfPolicyRole +
			"\n" +
			"pass all\n",
	)

	if err := os.WriteFile(
		target,
		content,
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	spec := testPFPolicySpec(
		target,
	)

	if state := classifyPFPolicy(
		spec,
	); state != pfPolicyOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestClassifyPFPolicyOwnedMatch(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"pf.conf",
	)

	spec := testPFPolicySpec(
		target,
	)

	if err := os.WriteFile(
		target,
		spec.Content,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyPFPolicy(
		spec,
	); state != pfPolicyOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestAcceptedPFPolicyParsesOnFreeBSD(t *testing.T) {
	if runtime.GOOS != "freebsd" {
		t.Skip(
			"PF syntax validation requires FreeBSD",
		)
	}

	config := loadTestConfig(t)

	content, err := renderPFPolicy(
		pfPolicyAsset,
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := validatePFPolicyContent(
		content,
	); err != nil {
		if strings.Contains(
			err.Error(),
			"Failed to open netlink",
		) {
			t.Skipf(
				"PF syntax validation unavailable in this FreeBSD environment: %v",
				err,
			)
		}

		t.Fatalf(
			"accepted PF policy syntax rejected: %v",
			err,
		)
	}
}

func testPFPolicySpec(
	target string,
) pfPolicySpec {
	parent := filepath.Dir(
		target,
	)

	info, err := os.Stat(
		parent,
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

	content := []byte(
		pfPolicyMarker +
			"\n" +
			"# FI-ROLE: " +
			pfPolicyRole +
			"\n",
	)

	return pfPolicySpec{
		Content: content,
		GID:     uint64(stat.Gid),
		Mode:    0o644,
		Target:  target,
		UID:     uint64(stat.Uid),
	}
}
