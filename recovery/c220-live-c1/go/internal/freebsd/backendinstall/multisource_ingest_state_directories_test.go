// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func m1TestIngestDirectoryIdentity(
	t *testing.T,
	root string,
) (uint64, uint64) {
	t.Helper()

	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("unsupported filesystem stat")
	}

	return uint64(stat.Uid), uint64(stat.Gid)
}

func TestM1IngestStateChildProvisioningIsIdempotent(
	t *testing.T,
) {
	root := t.TempDir()

	before, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf(
		"temporary root initial mode=%#o",
		before.Mode().Perm(),
	)

	// The actual installer first establishes the dataset root
	// ownership and 0700 mode. The disposable test fixture must
	// independently establish the same prerequisite.
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}

	uid, gid := m1TestIngestDirectoryIdentity(t, root)

	rootFD, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|
			unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)

	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		t.Fatal(err)
	}

	t.Logf(
		"prepared root mode=%#o uid=%d gid=%d expected_uid=%d expected_gid=%d",
		rootStat.Mode,
		rootStat.Uid,
		rootStat.Gid,
		uid,
		gid,
	)

	if !m1ExactIngestDirectory(&rootStat, uid, gid) {
		t.Fatal("disposable fixture does not satisfy root contract")
	}

	if err := m1ProvisionIngestStateChildren(
		root, uid, gid, false,
	); err != nil {
		t.Fatal(err)
	}

	for _, name := range m1IngestStateChildren {
		if _, err := os.Lstat(
			filepath.Join(root, name),
		); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf(
				"precheck unexpectedly created %s: %v",
				name, err,
			)
		}
	}

	if err := m1ProvisionIngestStateChildren(
		root, uid, gid, true,
	); err != nil {
		t.Fatal(err)
	}

	for _, name := range m1IngestStateChildren {
		path := filepath.Join(root, name)

		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}

		if !info.IsDir() ||
			info.Mode().Perm() != 0700 {
			t.Fatalf(
				"incorrect permissions on %s: %v",
				name, info.Mode(),
			)
		}
	}

	marker := filepath.Join(
		root,
		"quarantine",
		"source-marker.json",
	)

	if err := os.WriteFile(
		marker,
		[]byte("preserve-quarantine"),
		0400,
	); err != nil {
		t.Fatal(err)
	}

	audit := filepath.Join(
		root,
		"history",
		"release-record.json",
	)

	if err := os.WriteFile(
		audit,
		[]byte("preserve-history"),
		0400,
	); err != nil {
		t.Fatal(err)
	}

	if err := m1ProvisionIngestStateChildren(
		root, uid, gid, true,
	); err != nil {
		t.Fatal(err)
	}

	for path, expected := range map[string]string{
		marker: "preserve-quarantine",
		audit:  "preserve-history",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != expected {
			t.Fatalf(
				"reapply modified existing state: %s",
				path,
			)
		}
	}

	t.Log("PASS: Precheck creates nothing")
	t.Log("PASS: Both persistent state directories provisioned")
	t.Log("PASS: Reapply preserves quarantine and audit records")
}

func TestM1IngestStateChildPrecheckRejectsForeignState(
	t *testing.T,
) {
	root := t.TempDir()
	uid, gid := m1TestIngestDirectoryIdentity(t, root)

	foreign := filepath.Join(root, "history")

	if err := os.Symlink(
		t.TempDir(),
		foreign,
	); err != nil {
		t.Fatal(err)
	}

	if err := m1ProvisionIngestStateChildren(
		root, uid, gid, false,
	); err == nil {
		t.Fatal("precheck accepted foreign symlink")
	}

	if err := m1ProvisionIngestStateChildren(
		root, uid, gid, true,
	); err == nil {
		t.Fatal("provisioning accepted foreign symlink")
	}

	if _, err := os.Lstat(
		filepath.Join(root, "quarantine"),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(
			"installer created quarantine before rejecting history",
		)
	}

	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(foreign, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(foreign, 0755); err != nil {
		t.Fatal(err)
	}

	if err := m1ProvisionIngestStateChildren(
		root, uid, gid, true,
	); err == nil {
		t.Fatal("installer accepted writable or exposed history")
	}

	t.Log("PASS: Symlink and permission drift fail closed")
	t.Log("PASS: Complete child preclassification precedes mutation")
}

func TestM1IngestStateChildProvisioningRequiresRealRoot(
	t *testing.T,
) {
	base := t.TempDir()
	uid, gid := m1TestIngestDirectoryIdentity(t, base)

	missing := filepath.Join(base, "missing")

	if err := m1ProvisionIngestStateChildren(
		missing, uid, gid, true,
	); err == nil {
		t.Fatal("installer created an absent dataset root")
	}

	alias := filepath.Join(base, "alias")

	if err := os.Symlink(base, alias); err != nil {
		t.Fatal(err)
	}

	if err := m1ProvisionIngestStateChildren(
		alias, uid, gid, true,
	); err == nil {
		t.Fatal("installer followed dataset root symlink")
	}

	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}

	if err := m1ProvisionIngestStateChildren(
		base, uid, gid, true,
	); err == nil {
		t.Fatal("installer accepted nonprivate dataset root")
	}

	t.Log("PASS: Absent, symlinked and unsafe roots rejected")
}
