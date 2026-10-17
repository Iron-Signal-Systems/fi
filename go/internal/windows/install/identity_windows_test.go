// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestDeriveDesiredFIIdentitiesDomainPrefix(t *testing.T) {
	t.Parallel()

	value, err := DeriveDesiredFIIdentities(
		"ISS-FS-01",
		"ISS",
	)
	if err != nil {
		t.Fatal(err)
	}

	if value.CollectorSender.Account != `ISS\gFI-FS01$` {
		t.Fatalf(
			"collector/sender account=%q",
			value.CollectorSender.Account,
		)
	}
	if value.USNReader.Account != `ISS\gFI-USN-FS01$` {
		t.Fatalf(
			"USN account=%q",
			value.USNReader.Account,
		)
	}
	if value.ObjReader.Account != `ISS\gFI-OBJ-FS01$` {
		t.Fatalf(
			"object-reader account=%q",
			value.ObjReader.Account,
		)
	}
}

func TestDeriveDesiredFIIdentitiesPreservesNonDomainPrefix(t *testing.T) {
	t.Parallel()

	value, err := DeriveDesiredFIIdentities(
		"FILE-01",
		"COUNTY",
	)
	if err != nil {
		t.Fatal(err)
	}

	if value.CollectorSender.SAMAccountName != "gFI-FILE01$" {
		t.Fatalf(
			"collector/sender SAM=%q",
			value.CollectorSender.SAMAccountName,
		)
	}
}

func TestDeriveDesiredFIIdentitiesRejectsUnsafeTruncation(t *testing.T) {
	t.Parallel()

	_, err := DeriveDesiredFIIdentities(
		"COUNTY-VERY-LONG-FILE-SERVER-NAME",
		"COUNTY",
	)
	if err == nil {
		t.Fatal(
			"expected an explicit-naming error for an overlength derived gMSA",
		)
	}
}
