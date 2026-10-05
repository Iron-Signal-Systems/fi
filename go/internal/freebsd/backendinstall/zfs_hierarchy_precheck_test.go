// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
	"testing"
)

func TestPrecheckFIHierarchyAcceptsAbsentHierarchy(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	if err := precheckFIHierarchy(
		config,
		&probe,
	); err != nil {
		t.Fatalf(
			"precheckFIHierarchy() error = %v",
			err,
		)
	}
}

func TestPrecheckFIHierarchyBlocksMountpointCollision(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	probe.paths["/var/db/fi/custody/generation"] =
		fakeHostPathResponse{
			exists: true,
		}

	err := precheckFIHierarchy(
		config,
		&probe,
	)
	if err == nil {
		t.Fatal(
			"precheckFIHierarchy() unexpectedly accepted mountpoint collision",
		)
	}

	if !strings.Contains(
		err.Error(),
		"FOREIGN_COLLISION",
	) {
		t.Fatalf(
			"precheckFIHierarchy() error = %v, want FOREIGN_COLLISION",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		"/var/db/fi/custody/generation",
	) {
		t.Fatalf(
			"precheckFIHierarchy() error = %v, want collision path",
			err,
		)
	}
}

func TestPrecheckFIHierarchyBlocksLateForeignDataset(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\nzroot/fi/backups\n",
		}

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed zroot/fi/backups"] =
		fakeHostProbeResponse{
			output: "-\t-\n",
		}

	err := precheckFIHierarchy(
		config,
		&probe,
	)
	if err == nil {
		t.Fatal(
			"precheckFIHierarchy() unexpectedly accepted late foreign dataset",
		)
	}

	if !strings.Contains(
		err.Error(),
		"FOREIGN_COLLISION",
	) {
		t.Fatalf(
			"precheckFIHierarchy() error = %v, want FOREIGN_COLLISION",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		"zroot/fi/backups",
	) {
		t.Fatalf(
			"precheckFIHierarchy() error = %v, want backups target",
			err,
		)
	}
}

func TestPrecheckFIHierarchyBlocksUnknownState(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			err: fmt.Errorf("enumeration failed"),
		}

	err := precheckFIHierarchy(
		config,
		&probe,
	)
	if err == nil {
		t.Fatal(
			"precheckFIHierarchy() unexpectedly accepted UNKNOWN state",
		)
	}

	if !strings.Contains(
		err.Error(),
		"UNKNOWN",
	) {
		t.Fatalf(
			"precheckFIHierarchy() error = %v, want UNKNOWN",
			err,
		)
	}
}
