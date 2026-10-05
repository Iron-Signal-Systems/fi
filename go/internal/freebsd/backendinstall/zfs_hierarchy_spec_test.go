// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "testing"

func TestFIHierarchySpecsMatchAcceptedContract(t *testing.T) {
	config := loadTestConfig(t)

	specs := fiHierarchySpecs(config)

	expected := []fiDatasetSpec{
		{
			Target:     "zroot/fi/custody",
			Role:       "custody-parent",
			Mountpoint: "none",
			Canmount:   "off",
			Mounted:    "no",
		},
		{
			Target:     "zroot/fi/custody/generation",
			Role:       "custody-generation",
			Mountpoint: "/var/db/fi/custody/generation",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     "zroot/fi/custody/transport",
			Role:       "custody-transport",
			Mountpoint: "/var/db/fi/custody/transport",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     "zroot/fi/recorded",
			Role:       "recorded",
			Mountpoint: "/var/db/fi/custody/recorded",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     "zroot/fi/ready",
			Role:       "ready",
			Mountpoint: "/var/db/fi/custody/ready",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     "zroot/fi/config",
			Role:       "config-parent",
			Mountpoint: "none",
			Canmount:   "off",
			Mounted:    "no",
		},
		{
			Target:     "zroot/fi/config/receiver",
			Role:       "config-receiver",
			Mountpoint: "/var/db/fi/config/receiver",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     "zroot/fi/config/ingest",
			Role:       "config-ingest",
			Mountpoint: "/var/db/fi/config/ingest",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     "zroot/fi/sor",
			Role:       "sor-parent",
			Mountpoint: "none",
			Canmount:   "off",
			Mounted:    "no",
		},
		{
			Target:     "zroot/fi/sor/postgres",
			Role:       "sor-postgres",
			Mountpoint: "/var/db/fi/sor/postgres",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     "zroot/fi/backups",
			Role:       "backups",
			Mountpoint: "/var/db/fi/backups",
			Canmount:   "on",
			Mounted:    "yes",
		},
	}

	if len(specs) != len(expected) {
		t.Fatalf(
			"hierarchy spec count = %d, want %d",
			len(specs),
			len(expected),
		)
	}

	for index := range expected {
		if specs[index] != expected[index] {
			t.Fatalf(
				"hierarchy spec %d = %#v, want %#v",
				index,
				specs[index],
				expected[index],
			)
		}
	}
}
