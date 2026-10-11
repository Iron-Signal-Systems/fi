// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBuildLifecyclePlan(
	t *testing.T,
) {
	config := loadTestConfig(
		t,
	)

	plan, err := buildLifecyclePlan(
		config,
	)
	if err != nil {
		t.Fatalf(
			"buildLifecyclePlan() error = %v",
			err,
		)
	}

	if len(plan.Parents) != 3 {
		t.Fatalf(
			"parents = %d, want 3",
			len(plan.Parents),
		)
	}

	expectedParents := []struct {
		role string
		path string
	}{
		{
			role: "local-etc-directory",
			path: "/usr/local/etc",
		},
		{
			role: "local-rc-directory",
			path: "/usr/local/etc/rc.d",
		},
		{
			role: "rc-conf-directory",
			path: "/etc/rc.conf.d",
		},
	}

	for index, expected := range expectedParents {
		actual := plan.Parents[index]

		if actual.Role != expected.role ||
			actual.Path != expected.path {
			t.Fatalf(
				"parent[%d] = %s -> %s, want %s -> %s",
				index,
				actual.Role,
				actual.Path,
				expected.role,
				expected.path,
			)
		}
	}

	if len(plan.Files) != 6 {
		t.Fatalf(
			"files = %d, want 6",
			len(plan.Files),
		)
	}

	files := make(
		map[string]lifecycleFileSpec,
	)

	for _, spec := range plan.Files {
		files[spec.Role] = spec
	}

	pfBoot, ok := files["pf-boot-policy"]
	if !ok {
		t.Fatal(
			"pf-boot-policy absent",
		)
	}

	pfBootText := string(
		pfBoot.Content,
	)

	if !strings.Contains(
		pfBootText,
		"pf_enable=\"YES\"",
	) {
		t.Fatal(
			"PF boot policy does not enable base PF",
		)
	}

	if !strings.Contains(
		pfBootText,
		"pf_rules=\"/etc/pf.conf\"",
	) {
		t.Fatal(
			"PF boot policy does not bind /etc/pf.conf",
		)
	}

	pfSpec, err := buildPFPolicySpec(
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(
		pfSpec.Content,
	)

	fiPF, ok := files["fi-pf-enable-policy"]
	if !ok {
		t.Fatal(
			"fi-pf-enable-policy absent",
		)
	}

	expectedHash := fmt.Sprintf(
		"%x",
		digest,
	)

	if !strings.Contains(
		string(fiPF.Content),
		"fi_pf_expected_sha256=\""+
			expectedHash+
			"\"",
	) {
		t.Fatal(
			"FI PF lifecycle config does not bind exact PF hash",
		)
	}

	sorIP, err := pfAddressOnly(
		"FI_SOR_DB_WORK_ADDRESS",
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(
		string(fiPF.Content),
		"fi_pf_sor_db_work_ip=\""+
			sorIP+
			"\"",
	) {
		t.Fatal(
			"FI PF lifecycle config does not bind exact SOR address",
		)
	}
}

func TestClassifyLifecycleFile(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"lifecycle-file",
	)

	spec := testLifecycleFileSpec(
		t,
		target,
	)

	if state := classifyLifecycleFile(
		spec,
	); state != lifecycleFileAbsent {
		t.Fatalf(
			"absent state = %s",
			state,
		)
	}

	if err := os.WriteFile(
		target,
		[]byte("foreign\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyLifecycleFile(
		spec,
	); state != lifecycleFileForeignCollision {
		t.Fatalf(
			"foreign state = %s",
			state,
		)
	}

	if err := os.WriteFile(
		target,
		[]byte(
			lifecycleMarker+
				"\n"+
				"# FI-ROLE: test\n"+
				"drift=true\n",
		),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyLifecycleFile(
		spec,
	); state != lifecycleFileOwnedDrift {
		t.Fatalf(
			"drift state = %s",
			state,
		)
	}

	if err := os.WriteFile(
		target,
		spec.Content,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		target,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyLifecycleFile(
		spec,
	); state != lifecycleFileOwnedMatch {
		t.Fatalf(
			"match state = %s",
			state,
		)
	}
}

func TestClassifyLifecycleFileRejectsHardLinkDrift(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"lifecycle-file",
	)

	spec := testLifecycleFileSpec(
		t,
		target,
	)

	if err := os.WriteFile(
		target,
		spec.Content,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		target,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	other := filepath.Join(
		directory,
		"lifecycle-file.other",
	)

	if err := os.Link(
		target,
		other,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyLifecycleFile(
		spec,
	); state != lifecycleFileOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestValidateLifecycleGlobalJailPolicy(
	t *testing.T,
) {
	tests := []struct {
		enable  string
		list    string
		wantErr bool
	}{
		{
			enable: "NO",
			list:   "",
		},
		{
			enable: "FALSE",
			list:   "",
		},
		{
			enable: "YES",
			list:   "site-jail another-jail",
		},
		{
			enable:  "YES",
			list:    "",
			wantErr: true,
		},
		{
			enable:  "YES",
			list:    "_ALL",
			wantErr: true,
		},
		{
			enable:  "YES",
			list:    "site-jail fi-ingest",
			wantErr: true,
		},
		{
			enable:  "MAYBE",
			list:    "site-jail",
			wantErr: true,
		},
	}

	for _, test := range tests {
		err := validateLifecycleGlobalJailPolicy(
			test.enable,
			test.list,
		)

		if test.wantErr && err == nil {
			t.Fatalf(
				"enable=%q list=%q: expected error",
				test.enable,
				test.list,
			)
		}

		if !test.wantErr && err != nil {
			t.Fatalf(
				"enable=%q list=%q: unexpected error: %v",
				test.enable,
				test.list,
				err,
			)
		}
	}
}

func testLifecycleFileSpec(
	t *testing.T,
	target string,
) lifecycleFileSpec {
	t.Helper()

	info, err := os.Stat(
		filepath.Dir(
			target,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal(
			"directory stat is not syscall.Stat_t",
		)
	}

	return lifecycleFileSpec{
		Content: []byte(
			lifecycleMarker +
				"\n" +
				"# FI-ROLE: test\n",
		),
		GID: uint64(
			stat.Gid,
		),
		Mode:   0o644,
		Role:   "test",
		Target: target,
		UID: uint64(
			stat.Uid,
		),
	}
}
