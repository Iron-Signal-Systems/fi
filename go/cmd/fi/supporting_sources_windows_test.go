// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectDirectorySourceRejectsMissingObservedSIDSet(t *testing.T) {
	identity := directoryTestIdentity()

	result := collectDirectorySource(nil, identity, nil)
	if len(result.Snapshots) != 0 {
		t.Fatalf("missing observed SID set returned %d directory snapshots", len(result.Snapshots))
	}
	if result.Error != "DirectoryObservedSIDsUnavailable" {
		t.Fatalf("error = %q, want DirectoryObservedSIDsUnavailable", result.Error)
	}
}

func TestCollectDirectorySourceRejectsEmptyDomainSIDSetWithoutLDAP(t *testing.T) {
	identity := directoryTestIdentity()
	observed := newObservedSIDSet()
	observed.add("S-1-1-0")
	observed.add("S-1-5-32-544")

	called := false
	result := collectDirectorySourceWithCollector(
		context.Background(),
		identity,
		observed,
		func(context.Context, string, []string) (records.DirectoryPrincipalSnapshot, error) {
			called = true
			return records.DirectoryPrincipalSnapshot{}, nil
		},
	)
	if called {
		t.Fatal("LDAP collector was called for a non-domain SID set")
	}
	if len(result.Snapshots) != 0 {
		t.Fatalf("non-domain SID set returned %d directory snapshots", len(result.Snapshots))
	}
	if result.Error != "DirectoryDomainSIDsUnavailable" {
		t.Fatalf("error = %q, want DirectoryDomainSIDsUnavailable", result.Error)
	}
}

func TestCollectDirectorySourceBatchesLargeRelevantSIDSet(t *testing.T) {
	identity := directoryTestIdentity()
	observed := newObservedSIDSet()
	for index := 0; index < directorySIDBatchSize+1; index++ {
		observed.add(fmt.Sprintf("S-1-5-21-1-2-3-%d", 1000+index))
	}

	var batchSizes []int
	result := collectDirectorySourceWithCollector(
		context.Background(),
		identity,
		observed,
		func(_ context.Context, domain string, sids []string) (records.DirectoryPrincipalSnapshot, error) {
			if domain != "iss.local" {
				t.Fatalf("domain = %q, want iss.local", domain)
			}
			batchSizes = append(batchSizes, len(sids))
			return records.DirectoryPrincipalSnapshot{
				RequestedSIDs: append([]string(nil), sids...),
			}, nil
		},
	)
	if result.Error != "" {
		t.Fatalf("directory source error = %q", result.Error)
	}
	if len(result.Snapshots) != 2 {
		t.Fatalf("snapshots = %d, want 2", len(result.Snapshots))
	}
	if len(batchSizes) != 2 || batchSizes[0] != directorySIDBatchSize || batchSizes[1] != 1 {
		t.Fatalf("batch sizes = %#v, want [%d 1]", batchSizes, directorySIDBatchSize)
	}
}

func TestCollectDirectorySourcePreservesCompletedBatchBeforeFailure(t *testing.T) {
	identity := directoryTestIdentity()
	observed := newObservedSIDSet()
	for index := 0; index < directorySIDBatchSize+1; index++ {
		observed.add(fmt.Sprintf("S-1-5-21-1-2-3-%d", 2000+index))
	}

	calls := 0
	result := collectDirectorySourceWithCollector(
		context.Background(),
		identity,
		observed,
		func(_ context.Context, _ string, sids []string) (records.DirectoryPrincipalSnapshot, error) {
			calls++
			if calls == 2 {
				return records.DirectoryPrincipalSnapshot{}, errors.New("second LDAP batch failed")
			}
			return records.DirectoryPrincipalSnapshot{
				RequestedSIDs: append([]string(nil), sids...),
			}, nil
		},
	)
	if len(result.Snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1 completed snapshot", len(result.Snapshots))
	}
	if result.Error != "second LDAP batch failed" {
		t.Fatalf("error = %q", result.Error)
	}
}

func TestLoadSupportingSIDStateMissingRequiresDurableBaseline(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())

	statePath, count, err := loadSupportingSIDState(
		directoryTestIdentity(),
		newObservedSIDSet(),
	)
	if err == nil {
		t.Fatal("missing supporting SID state returned no error")
	}
	if statePath == "" {
		t.Fatal("missing supporting SID state did not report its expected path")
	}
	if count != 0 {
		t.Fatalf("missing supporting SID state count = %d, want 0", count)
	}
	if !strings.Contains(err.Error(), "complete a durable baseline") {
		t.Fatalf("error = %q, want durable-baseline prerequisite", err)
	}
}

func directoryTestIdentity() records.ProcessIdentityObservation {
	return records.ProcessIdentityObservation{
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
}
