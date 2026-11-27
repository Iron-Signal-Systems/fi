// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/Iron-Signal-Systems/fi/go/internal/quarantinekeeper"
	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

// m1WorkerKeeperClient is injectable so isolated worker integration tests
// can exercise the same authority boundary without creating real identities.
// The operational worker only constructs a kernel-authenticated Unix client.
type m1WorkerKeeperClient interface {
	Read(context.Context, string) (quarantinekeeper.Status, error)
	Publish(context.Context, string, string, string, string) error
}

// m1PinnedKeeperWorkerIdentity resolves operating-system accounts, never
// caller-provided numeric identities. Both the IPC and singleton-lock checks
// must agree on this exact identity boundary.
func m1PinnedKeeperWorkerIdentity() (workerlock.ProtectedLockPolicy, error) {
	keeper, err := user.Lookup("fi-quarantine-keeper")
	if err != nil {
		return workerlock.ProtectedLockPolicy{}, fmt.Errorf("independent keeper account is not installed: %w", err)
	}
	worker, err := user.Lookup("fi-ingest")
	if err != nil {
		return workerlock.ProtectedLockPolicy{}, fmt.Errorf("ingest worker account is not installed: %w", err)
	}
	keeperUID, err := strconv.ParseUint(keeper.Uid, 10, 32)
	if err != nil {
		return workerlock.ProtectedLockPolicy{}, fmt.Errorf("invalid keeper UID: %w", err)
	}
	workerUID, err := strconv.ParseUint(worker.Uid, 10, 32)
	if err != nil {
		return workerlock.ProtectedLockPolicy{}, fmt.Errorf("invalid worker UID: %w", err)
	}
	workerGID, err := strconv.ParseUint(worker.Gid, 10, 32)
	if err != nil {
		return workerlock.ProtectedLockPolicy{}, fmt.Errorf("invalid worker GID: %w", err)
	}
	policy := workerlock.ProtectedLockPolicy{
		KeeperUID: uint32(keeperUID),
		WorkerUID: uint32(workerUID),
		WorkerGID: uint32(workerGID),
	}
	if policy.KeeperUID == 0 || policy.WorkerUID == 0 || policy.WorkerGID == 0 ||
		policy.KeeperUID == policy.WorkerUID ||
		uint32(os.Geteuid()) != policy.WorkerUID ||
		uint32(os.Getegid()) != policy.WorkerGID {
		return workerlock.ProtectedLockPolicy{}, errors.New("worker and keeper require distinct pinned runtime identities")
	}
	return policy, nil
}

func m1NewWorkerKeeperClient() (m1WorkerKeeperClient, error) {
	policy, err := m1PinnedKeeperWorkerIdentity()
	if err != nil {
		return nil, err
	}
	return quarantinekeeper.WorkerClient{
		Socket: quarantinekeeper.SocketAuthority{
			Directory: quarantinekeeper.KeeperSocketDirectory,
			KeeperUID: policy.KeeperUID,
			WorkerUID: policy.WorkerUID,
			WorkerGID: policy.WorkerGID,
		},
	}, nil
}

// m1RestoreSourceKeeperStates reads every source before allowing any
// state to transition. An unavailable or malformed response blocks all
// sources before the first PostgreSQL connection.
func m1RestoreSourceKeeperStates(
	ctx context.Context,
	states []sourceSessionState,
	keeper m1WorkerKeeperClient,
) error {
	if ctx == nil || keeper == nil || len(states) == 0 {
		return errors.New("FI namespace startup requires independent keeper authority")
	}
	statuses := make([]quarantinekeeper.Status, len(states))
	seen := make(map[string]bool, len(states))
	for index := range states {
		state := &states[index]
		source := state.Config.SourceID
		if !state.Config.SourceNamespaces || state.Config.QuarantineRoot == "" ||
			state.QuarantineStore != nil || state.KeeperClient != nil ||
			state.Quarantined || seen[source] {
			return fmt.Errorf("invalid keeper initialization for source %q", source)
		}
		seen[source] = true
		status, err := keeper.Read(ctx, source)
		if err != nil {
			return fmt.Errorf("keeper startup read for source %q failed closed: %w", source, err)
		}
		if status != quarantinekeeper.StatusClear && status != quarantinekeeper.StatusQuarantined {
			return fmt.Errorf("unrecognized keeper state for source %q", source)
		}
		statuses[index] = status
	}
	for index := range states {
		state := &states[index]
		state.KeeperClient = keeper
		if statuses[index] == quarantinekeeper.StatusQuarantined {
			state.Quarantined = true
			state.Repair.Reset()
			fmt.Printf("SOURCE QUARANTINE RESTORED source=%s authority=keeper action=operator_review_required\n",
				state.Config.SourceID)
		}
	}
	return nil
}

// m1CheckKeeperState rechecks the authority before startup and every
// scheduled source pass. Failure aborts the entire worker; it never
// infers Clear from a timeout. An already isolated source cannot be
// silently released while this worker is running.
func m1CheckKeeperState(ctx context.Context, state *sourceSessionState) error {
	if state == nil {
		return errors.New("FI keeper source state is missing")
	}
	if !state.Config.SourceNamespaces {
		return nil
	}
	if ctx == nil || state.KeeperClient == nil || state.QuarantineStore != nil {
		return errors.New("FI namespaced worker has no independent keeper authority")
	}
	status, err := state.KeeperClient.Read(ctx, state.Config.SourceID)
	if err != nil {
		return fmt.Errorf("FI keeper status unavailable for source %q: %w",
			state.Config.SourceID, err)
	}
	switch status {
	case quarantinekeeper.StatusQuarantined:
		if !state.Quarantined {
			state.Quarantined = true
			state.Repair.Reset()
			fmt.Printf("SOURCE QUARANTINED source=%s authority=keeper action=operator_review_required\n",
				state.Config.SourceID)
		}
	case quarantinekeeper.StatusClear:
		if state.Quarantined {
			return fmt.Errorf("FI quarantined source %q became clear without worker restart",
				state.Config.SourceID)
		}
	default:
		return fmt.Errorf("FI keeper returned invalid source status for %q",
			state.Config.SourceID)
	}
	return nil
}
