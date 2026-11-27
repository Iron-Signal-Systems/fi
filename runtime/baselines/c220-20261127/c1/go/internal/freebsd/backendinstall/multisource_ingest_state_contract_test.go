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

func TestM1IngestStateStorageAuthority(t *testing.T) {
	config := loadTestConfig(t)

	foundDataset := false

	for _, spec := range fiHierarchySpecs(config) {
		if spec.Role != "ingest-state" {
			continue
		}

		if foundDataset {
			t.Fatal("duplicate ingest-state dataset")
		}
		foundDataset = true

		if spec.Target != "zroot/fi/ingest" ||
			spec.Mountpoint != "/var/db/fi/ingest" ||
			spec.Canmount != "on" ||
			spec.Mounted != "yes" {
			t.Fatalf("invalid ingest-state dataset: %+v", spec)
		}
	}

	if !foundDataset {
		t.Fatal("persistent ingest-state dataset missing")
	}

	hosts, jails, err := directorySpecs(config)
	if err != nil {
		t.Fatal(err)
	}

	foundHost := false

	for _, spec := range hosts {
		if spec.Name != "persistent ingest-state directory" {
			continue
		}

		if foundHost {
			t.Fatal("duplicate ingest-state host directory")
		}
		foundHost = true

		if spec.Path != "/var/db/fi/ingest" ||
			spec.Mode != 0700 ||
			spec.UID != 4100 ||
			spec.GID != 4100 {
			t.Fatalf("invalid state root ownership: %+v", spec)
		}
	}

	if !foundHost {
		t.Fatal("installer does not manage ingest-state host directory")
	}

	foundJail := false

	for _, jail := range jails {
		for _, path := range jail.Paths {
			if filepath.Base(path.Path) != "ingest" ||
				filepath.Base(filepath.Dir(path.Path)) != "fi" {
				continue
			}

			if jail.Role != "ingest" {
				t.Fatalf("state mountpoint leaked to %s jail", jail.Role)
			}

			if foundJail {
				t.Fatal("duplicate ingest-state jail mountpoint")
			}

			foundJail = true

			if path.Mode != 0755 ||
				path.UID != 0 ||
				path.GID != 0 {
				t.Fatalf(
					"invalid pre-mount destination: %+v", path,
				)
			}
		}
	}

	if !foundJail {
		t.Fatal("ingest jail state mountpoint missing")
	}

	const mount = "/var/db/fi/ingest"

	if strings.Count(
		hostFileAssetIngestFstab, mount,
	) != 2 {
		t.Fatal("ingest nullfs source/destination not unique")
	}

	if !strings.Contains(
		hostFileAssetIngestFstab,
		"nullfs  rw    0    0",
	) {
		t.Fatal("ingest-state nullfs mount must be writable")
	}

	if strings.Contains(hostFileAssetReceiverFstab, mount) ||
		strings.Contains(hostFileAssetSORFstab, mount) {
		t.Fatal("ingest state is mounted into another application jail")
	}

	t.Log("PASS: Dedicated persistent dataset")
	t.Log("PASS: Worker-owned host directory")
	t.Log("PASS: Ingest-only nullfs mountpoint")
}

func TestM1IngestStateFstabAssetMatchesSource(t *testing.T) {
	path := filepath.Join(
		"..", "..", "..", "..",
		"tools", "deployment", "freebsd",
		"fstab.d", "fi-ingest.fstab.template",
	)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if hostFileAssetIngestFstab != string(raw) {
		t.Fatal("embedded fstab asset differs from canonical template")
	}

	t.Log("PASS: Generated fstab matches canonical source")
}
