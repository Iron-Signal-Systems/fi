// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectDirectorySourceRejectsMissingObservedSIDSet(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{
			NetBIOSName: "SERVER1",
			DNSDomain:   "iss.local",
		},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-1-2-3-1106",
				DomainName: "ISS",
			},
		},
	}

	result := collectDirectorySource(nil, identity, nil)
	if result.Snapshot != nil {
		t.Fatal("missing observed SID set returned a directory snapshot")
	}
	if result.Error != "DirectoryObservedSIDsUnavailable" {
		t.Fatalf("error = %q, want DirectoryObservedSIDsUnavailable", result.Error)
	}
}

func TestCollectDirectorySourceRejectsEmptyDomainSIDSetWithoutLDAP(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{
			NetBIOSName: "SERVER1",
			DNSDomain:   "iss.local",
		},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-1-2-3-1106",
				DomainName: "ISS",
			},
		},
	}

	observed := newObservedSIDSet()
	observed.add("S-1-1-0")
	observed.add("S-1-5-32-544")

	result := collectDirectorySource(nil, identity, observed)
	if result.Snapshot != nil {
		t.Fatal("non-domain SID set returned a directory snapshot")
	}
	if result.Error != "DirectoryDomainSIDsUnavailable" {
		t.Fatalf("error = %q, want DirectoryDomainSIDsUnavailable", result.Error)
	}
}
