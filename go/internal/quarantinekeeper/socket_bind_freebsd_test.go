// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestKeeperBindCreatesVerifiedEndpoint(
	t *testing.T,
) {
	policy := keeperSocketTestPolicy(t)

	listener, err := BindWorkerSocket(policy)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	path := filepath.Join(
		policy.Directory,
		KeeperSocketName,
	)

	if err := VerifySocketAuthority(
		policy, true,
	); err != nil {
		t.Fatal(err)
	}

	client, err := net.DialUnix(
		"unix",
		nil,
		&net.UnixAddr{
			Name: path,
			Net:  "unix",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := BindWorkerSocket(policy); err == nil {
		t.Fatal("second keeper bind replaced live endpoint")
	}

	t.Log("PASS: Socket bound with verified ownership")
	t.Log("PASS: Live endpoint cannot be replaced")
}

func TestKeeperBindNeverReplacesForeignObjects(
	t *testing.T,
) {
	for _, kind := range []string{
		"regular",
		"symlink",
	} {
		t.Run(kind, func(t *testing.T) {
			policy := keeperSocketTestPolicy(t)

			path := filepath.Join(
				policy.Directory,
				KeeperSocketName,
			)

			switch kind {
			case "regular":
				if err := os.WriteFile(
					path,
					[]byte("preserve"),
					0600,
				); err != nil {
					t.Fatal(err)
				}

			case "symlink":
				if err := os.Symlink(
					"foreign-target",
					path,
				); err != nil {
					t.Fatal(err)
				}
			}

			if _, err := BindWorkerSocket(policy); err == nil {
				t.Fatal("foreign pathname replaced")
			}

			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}

			if kind == "regular" && !info.Mode().IsRegular() {
				t.Fatal("existing file type changed")
			}

			if kind == "symlink" &&
				info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("existing symlink replaced")
			}
		})
	}

	t.Log("PASS: Foreign objects remain untouched")
}

func TestKeeperBindRejectsUnsafeDirectory(
	t *testing.T,
) {
	policy := keeperSocketTestPolicy(t)

	if err := os.Chmod(
		policy.Directory,
		0770,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := BindWorkerSocket(policy); err == nil {
		t.Fatal("worker-writable directory accepted")
	}

	path := filepath.Join(
		policy.Directory,
		KeeperSocketName,
	)

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf(
			"socket created despite unsafe directory: %v",
			err,
		)
	}

	t.Log("PASS: Invalid authority rejected before binding")
}

func TestKeeperBindDoesNotUnlinkOnClose(
	t *testing.T,
) {
	policy := keeperSocketTestPolicy(t)

	listener, err := BindWorkerSocket(policy)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(
		policy.Directory,
		KeeperSocketName,
	)

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(
			"listener close unexpectedly unlinked endpoint:",
			err,
		)
	}

	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("socket pathname changed after close")
	}

	if _, err := BindWorkerSocket(policy); err == nil {
		t.Fatal("stale endpoint silently replaced")
	}

	t.Log("PASS: Close cannot silently unlink pathname")
	t.Log("PASS: Stale endpoint requires explicit retirement")
}
