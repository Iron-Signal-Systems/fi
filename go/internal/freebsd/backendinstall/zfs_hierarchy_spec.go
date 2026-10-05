// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

// -----------------------------------------------------------------------------
// FI production ZFS hierarchy
// -----------------------------------------------------------------------------

type fiDatasetSpec struct {
	Canmount   string
	Mounted    string
	Mountpoint string
	Role       string
	Target     string
}

func fiHierarchySpecs(config Config) []fiDatasetSpec {
	root := config.Value("FI_ZPOOL") + "/fi"

	return []fiDatasetSpec{
		{
			Target:     root + "/custody",
			Role:       "custody-parent",
			Mountpoint: "none",
			Canmount:   "off",
			Mounted:    "no",
		},
		{
			Target:     root + "/custody/generation",
			Role:       "custody-generation",
			Mountpoint: "/var/db/fi/custody/generation",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     root + "/custody/transport",
			Role:       "custody-transport",
			Mountpoint: "/var/db/fi/custody/transport",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     root + "/recorded",
			Role:       "recorded",
			Mountpoint: "/var/db/fi/custody/recorded",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     root + "/ready",
			Role:       "ready",
			Mountpoint: "/var/db/fi/custody/ready",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     root + "/config",
			Role:       "config-parent",
			Mountpoint: "none",
			Canmount:   "off",
			Mounted:    "no",
		},
		{
			Target:     root + "/config/receiver",
			Role:       "config-receiver",
			Mountpoint: "/var/db/fi/config/receiver",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     root + "/config/ingest",
			Role:       "config-ingest",
			Mountpoint: "/var/db/fi/config/ingest",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     root + "/sor",
			Role:       "sor-parent",
			Mountpoint: "none",
			Canmount:   "off",
			Mounted:    "no",
		},
		{
			Target:     root + "/sor/postgres",
			Role:       "sor-postgres",
			Mountpoint: "/var/db/fi/sor/postgres",
			Canmount:   "on",
			Mounted:    "yes",
		},
		{
			Target:     root + "/backups",
			Role:       "backups",
			Mountpoint: "/var/db/fi/backups",
			Canmount:   "on",
			Mounted:    "yes",
		},
	}
}
