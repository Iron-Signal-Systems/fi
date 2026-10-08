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

func TestHostFileSpecsRenderEightResources(t *testing.T) {
	config := loadTestConfig(t)

	specs, err := hostFileSpecs(config)
	if err != nil {
		t.Fatalf(
			"hostFileSpecs() error = %v",
			err,
		)
	}

	if len(specs) != 8 {
		t.Fatalf(
			"spec count = %d, want 8",
			len(specs),
		)
	}

	for _, spec := range specs {
		if hostFileTokenPattern.Match(
			spec.Content,
		) {
			t.Fatalf(
				"%s contains unresolved token",
				spec.Role,
			)
		}

		if !containsExactLine(
			spec.Content,
			hostFileMarker,
		) {
			t.Fatalf(
				"%s lacks FI marker",
				spec.Role,
			)
		}

		if !containsExactLine(
			spec.Content,
			"# FI-ROLE: "+spec.Role,
		) {
			t.Fatalf(
				"%s lacks exact FI role",
				spec.Role,
			)
		}
	}
}

func TestHostFileSpecsMetadata(t *testing.T) {
	config := loadTestConfig(t)

	specs, err := hostFileSpecs(config)
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string]struct {
		mode   os.FileMode
		target string
	}{
		"jail-config-receiver": {
			0o644,
			"/etc/jail.conf.d/fi-receiver.conf",
		},
		"jail-config-ingest": {
			0o644,
			"/etc/jail.conf.d/fi-ingest.conf",
		},
		"jail-config-sor-db": {
			0o644,
			"/etc/jail.conf.d/fi-sor-db.conf",
		},
		"fstab-receiver": {
			0o600,
			"/etc/fstab.fi-receiver",
		},
		"fstab-ingest": {
			0o600,
			"/etc/fstab.fi-ingest",
		},
		"fstab-sor-db": {
			0o600,
			"/etc/fstab.fi-sor-db",
		},
		"devfs-rules": {
			0o644,
			"/etc/devfs.rules.fi",
		},
		"vnet-helper": {
			0o555,
			"/usr/local/libexec/fi-vnet-pair",
		},
	}

	for _, spec := range specs {
		want, ok := expected[spec.Role]
		if !ok {
			t.Fatalf(
				"unexpected role %q",
				spec.Role,
			)
		}

		if spec.Target != want.target {
			t.Fatalf(
				"%s target = %q, want %q",
				spec.Role,
				spec.Target,
				want.target,
			)
		}

		if spec.Mode != want.mode ||
			spec.UID != 0 ||
			spec.GID != 0 {
			t.Fatalf(
				"%s metadata = %d:%d %o",
				spec.Role,
				spec.UID,
				spec.GID,
				spec.Mode,
			)
		}
	}
}

func TestVNETHelperAssetIsNotRendered(t *testing.T) {
	config := loadTestConfig(t)

	specs, err := hostFileSpecs(config)
	if err != nil {
		t.Fatal(err)
	}

	for _, spec := range specs {
		if spec.Role != "vnet-helper" {
			continue
		}

		if string(spec.Content) !=
			hostFileAssetVNETHelper {
			t.Fatal(
				"VNET helper changed during rendering",
			)
		}

		return
	}

	t.Fatal(
		"VNET helper specification not found",
	)
}

func TestClassifyHostFileAbsent(t *testing.T) {
	spec := testHostFileSpec(
		filepath.Join(
			t.TempDir(),
			"missing",
		),
	)

	if state := classifyHostFile(
		spec,
	); state != hostFileAbsent {
		t.Fatalf(
			"state = %s, want ABSENT",
			state,
		)
	}
}

func TestClassifyHostFileForeignCollision(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"host-file",
	)

	if err := os.WriteFile(
		target,
		[]byte("foreign\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	spec := testHostFileSpec(target)

	if state := classifyHostFile(
		spec,
	); state != hostFileForeignCollision {
		t.Fatalf(
			"state = %s, want FOREIGN_COLLISION",
			state,
		)
	}
}

func TestClassifyHostFileOwnedDrift(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"host-file",
	)

	content := "" +
		hostFileMarker +
		"\n" +
		"# FI-ROLE: test\n" +
		"drift\n"

	if err := os.WriteFile(
		target,
		[]byte(content),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	spec := testHostFileSpec(target)

	if state := classifyHostFile(
		spec,
	); state != hostFileOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSystemHostFileMutatorPublishesAbsent(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"host-file",
	)

	spec := testHostFileSpec(target)

	mutator := systemHostFileMutator{}

	if err := mutator.PublishAbsent(
		spec,
	); err != nil {
		t.Fatalf(
			"PublishAbsent() error = %v",
			err,
		)
	}

	if state := classifyHostFile(
		spec,
	); state != hostFileOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestClassifyHostFileRejectsHardLinkDrift(t *testing.T) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"host-file",
	)

	spec := testHostFileSpec(target)

	mutator := systemHostFileMutator{}

	if err := mutator.PublishAbsent(
		spec,
	); err != nil {
		t.Fatal(err)
	}

	other := filepath.Join(
		directory,
		"host-file.other",
	)

	if err := os.Link(
		target,
		other,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyHostFile(
		spec,
	); state != hostFileOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func testHostFileSpec(
	target string,
) hostFileSpec {
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

	content := []byte(
		hostFileMarker +
			"\n" +
			"# FI-ROLE: test\n",
	)

	return hostFileSpec{
		Content: content,
		GID:     uint64(stat.Gid),
		Mode:    0o644,
		Role:    "test",
		Target:  target,
		UID:     uint64(stat.Uid),
	}
}

func TestRenderHostFileAssetRejectsUnknownToken(t *testing.T) {
	config := loadTestConfig(t)

	_, err := renderHostFileAsset(
		"# FI-MANAGED: test\n@FI_NOT_A_REAL_KEY@\n",
		config,
	)

	if err == nil {
		t.Fatal(
			"renderHostFileAsset accepted unknown configuration token",
		)
	}
}

func TestExactManagedFileMode(t *testing.T) {
	expected := os.FileMode(0o644)

	if !exactManagedFileMode(
		expected,
		expected,
	) {
		t.Fatal(
			"exact mode rejected",
		)
	}

	cases := []struct {
		name string
		mode os.FileMode
	}{
		{
			name: "setuid",
			mode: expected | os.ModeSetuid,
		},
		{
			name: "setgid",
			mode: expected | os.ModeSetgid,
		},
		{
			name: "sticky",
			mode: expected | os.ModeSticky,
		},
		{
			name: "permission drift",
			mode: 0o600,
		},
	}

	for _, test := range cases {
		t.Run(
			test.name,
			func(t *testing.T) {
				if exactManagedFileMode(
					test.mode,
					expected,
				) {
					t.Fatalf(
						"mode %v unexpectedly accepted",
						test.mode,
					)
				}
			},
		)
	}
}
