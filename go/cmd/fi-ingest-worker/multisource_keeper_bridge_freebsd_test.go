// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/quarantinekeeper"
)

type m1FakeKeeper struct {
	statuses     map[string]quarantinekeeper.Status
	failureAt    string
	publishError error
	published    []string
}

func (fake *m1FakeKeeper) Read(_ context.Context, source string) (quarantinekeeper.Status, error) {
	if fake.failureAt == source {
		return "", errors.New("simulated keeper failure")
	}
	return fake.statuses[source], nil
}

func (fake *m1FakeKeeper) Publish(_ context.Context, source, reason, generation, detail string) error {
	fake.published = append(fake.published, source+":"+reason+":"+generation+":"+detail)
	return fake.publishError
}

func m1KeeperBridgeStates(t *testing.T) []sourceSessionState {
	t.Helper()
	states, err := newSourceSessionStates(workerConfig{
		SourceNamespaces: true,
		QuarantineRoot:   "/test/keeper-owned/not-worker-writable",
		SourceIDs:        []string{"iss-fs-2019.iss.local", "iss-fs-22.iss.local"},
		RepairInterval:   time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return states
}

func TestM1KeeperBridgeRestoresIsolatedSource(t *testing.T) {
	states := m1KeeperBridgeStates(t)
	keeper := &m1FakeKeeper{statuses: map[string]quarantinekeeper.Status{
		"iss-fs-2019.iss.local": quarantinekeeper.StatusQuarantined,
		"iss-fs-22.iss.local":   quarantinekeeper.StatusClear,
	}}
	if err := m1RestoreSourceKeeperStates(context.Background(), states, keeper); err != nil {
		t.Fatal(err)
	}
	if !states[0].Quarantined || states[1].Quarantined ||
		states[0].KeeperClient == nil || states[1].KeeperClient == nil ||
		states[0].QuarantineStore != nil || states[1].QuarantineStore != nil {
		t.Fatal("keeper startup did not isolate only the quarantined source")
	}
	if err := m1CheckKeeperState(context.Background(), &states[1]); err != nil {
		t.Fatal(err)
	}
}

func TestM1KeeperBridgeStartupFailsWithoutPartialActivation(t *testing.T) {
	states := m1KeeperBridgeStates(t)
	keeper := &m1FakeKeeper{statuses: map[string]quarantinekeeper.Status{
		"iss-fs-2019.iss.local": quarantinekeeper.StatusQuarantined,
		"iss-fs-22.iss.local":   quarantinekeeper.StatusClear,
	}, failureAt: "iss-fs-22.iss.local"}
	if err := m1RestoreSourceKeeperStates(context.Background(), states, keeper); err == nil {
		t.Fatal("unavailable keeper did not prevent worker startup")
	}
	for _, state := range states {
		if state.KeeperClient != nil || state.Quarantined {
			t.Fatal("keeper failure partially activated source state")
		}
	}
}

func TestM1KeeperBridgeRejectsMissingAndAmbiguousAuthority(t *testing.T) {
	states := m1KeeperBridgeStates(t)
	if err := m1RestoreSourceKeeperStates(context.Background(), states, nil); err == nil {
		t.Fatal("missing keeper accepted")
	}
	states[0].QuarantineStore = &m1QuarantineStore{Root: states[0].Config.QuarantineRoot}
	keeper := &m1FakeKeeper{statuses: map[string]quarantinekeeper.Status{
		"iss-fs-2019.iss.local": quarantinekeeper.StatusClear,
		"iss-fs-22.iss.local":   quarantinekeeper.StatusClear,
	}}
	if err := m1RestoreSourceKeeperStates(context.Background(), states, keeper); err == nil {
		t.Fatal("legacy worker-owned store accepted by keeper startup")
	}
}

func TestM1KeeperBridgeNoSilentRelease(t *testing.T) {
	states := m1KeeperBridgeStates(t)
	keeper := &m1FakeKeeper{statuses: map[string]quarantinekeeper.Status{
		"iss-fs-2019.iss.local": quarantinekeeper.StatusQuarantined,
		"iss-fs-22.iss.local":   quarantinekeeper.StatusClear,
	}}
	if err := m1RestoreSourceKeeperStates(context.Background(), states, keeper); err != nil {
		t.Fatal(err)
	}
	keeper.statuses["iss-fs-2019.iss.local"] = quarantinekeeper.StatusClear
	if err := m1CheckKeeperState(context.Background(), &states[0]); err == nil || !states[0].Quarantined {
		t.Fatal("quarantined source silently resumed")
	}
}

func TestM1KeeperBridgeFailsClosedWhenKeeperDisappears(t *testing.T) {
	states := m1KeeperBridgeStates(t)
	keeper := &m1FakeKeeper{statuses: map[string]quarantinekeeper.Status{
		"iss-fs-2019.iss.local": quarantinekeeper.StatusClear,
		"iss-fs-22.iss.local":   quarantinekeeper.StatusClear,
	}}
	if err := m1RestoreSourceKeeperStates(context.Background(), states, keeper); err != nil {
		t.Fatal(err)
	}
	keeper.failureAt = "iss-fs-2019.iss.local"
	if err := m1CheckKeeperState(context.Background(), &states[0]); err == nil {
		t.Fatal("missing keeper was treated as clear")
	}
}

func TestM1KeeperBridgePublishesWithoutWorkerStorage(t *testing.T) {
	states := m1KeeperBridgeStates(t)
	keeper := &m1FakeKeeper{statuses: map[string]quarantinekeeper.Status{
		"iss-fs-2019.iss.local": quarantinekeeper.StatusClear,
		"iss-fs-22.iss.local":   quarantinekeeper.StatusClear,
	}}
	if err := m1RestoreSourceKeeperStates(context.Background(), states, keeper); err != nil {
		t.Fatal(err)
	}
	if err := m1PersistSourceQuarantine(&states[0],
		"RELATIONAL_CONFLICT", "generation-1", "test conflict"); err != nil {
		t.Fatal(err)
	}
	if len(keeper.published) != 1 ||
		keeper.published[0] != "iss-fs-2019.iss.local:RELATIONAL_CONFLICT:generation-1:test conflict" ||
		states[0].QuarantineStore != nil {
		t.Fatal("keeper was not used exclusively for publication")
	}
	keeper.publishError = errors.New("simulated publication failure")
	if err := m1PersistSourceQuarantine(&states[0],
		"RELATIONAL_CONFLICT", "generation-2", "test failure"); err == nil {
		t.Fatal("failed keeper publication was acknowledged")
	}
}
