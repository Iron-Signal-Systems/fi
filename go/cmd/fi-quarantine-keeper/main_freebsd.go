// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

// fi-quarantine-keeper is an unprivileged, separately launched keeper.
// It never grants release authority over its worker-facing socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/quarantinekeeper"
)

type enrolledSourceFlags []string

func (sources *enrolledSourceFlags) String() string {
	return fmt.Sprintf("%d enrolled sources", len(*sources))
}
func (sources *enrolledSourceFlags) Set(value string) error {
	request := quarantinekeeper.Request{
		Version:   quarantinekeeper.ProtocolVersion,
		Operation: quarantinekeeper.OperationRead,
		SourceID:  value,
	}
	if err := request.Validate(); err != nil {
		return err
	}
	for _, existing := range *sources {
		if existing == value {
			return errors.New("repeated keeper enrolled source")
		}
	}
	*sources = append(*sources, value)
	return nil
}

func run(args []string) error {
	flags := flag.NewFlagSet("fi-quarantine-keeper", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	root := flags.String("quarantine-root", "", "preprovisioned keeper-owned 0700 quarantine storage")
	socketDirectory := flags.String("socket-directory", quarantinekeeper.KeeperSocketDirectory,
		"preprovisioned keeper-owned 0710 worker socket directory")
	keeperUID := flags.Uint("keeper-uid", 0, "unprivileged keeper UID")
	keeperGID := flags.Uint("keeper-gid", 0, "keeper primary GID")
	workerUID := flags.Uint("worker-uid", 0, "enrolled ingest-worker UID")
	workerGID := flags.Uint("worker-gid", 0, "enrolled ingest-worker primary GID")
	maxConnections := flags.Int("max-active", 4, "bounded concurrent worker connections (1..8)")
	adminEnabled := flags.Bool("admin-enable", false, "enable independent root-peer administrative release")
	historyRoot := flags.String("history-root", "", "preprovisioned keeper-owned durable release audit history")
	sources := enrolledSourceFlags{}
	flags.Var(&sources, "source", "exact enrolled source ID; repeat per source")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || len(sources) == 0 || *root == "" ||
		*keeperUID == 0 || *workerUID == 0 ||
		*keeperUID == *workerUID ||
		*keeperUID > 4294967295 || *keeperGID > 4294967295 ||
		*workerUID > 4294967295 || *workerGID > 4294967295 {
		return errors.New("missing or invalid keeper identities, sources or storage")
	}
	if (*adminEnabled && (*historyRoot == "" || *keeperGID == 0 || *workerGID == 0)) ||
		(!*adminEnabled && *historyRoot != "") {
		return errors.New("admin release requires explicit enable, history root, and nonzero keeper/worker GIDs")
	}
	policy := quarantinekeeper.SocketAuthority{
		Directory: *socketDirectory,
		KeeperUID: uint32(*keeperUID),
		WorkerUID: uint32(*workerUID),
		WorkerGID: uint32(*workerGID),
	}
	store, err := quarantinekeeper.NewKeeperStore(*root,
		uint32(*keeperUID), uint32(*keeperGID), []string(sources))
	if err != nil {
		return fmt.Errorf("verify keeper-owned marker inventory: %w", err)
	}
	if *adminEnabled {
		if err := store.VerifyReleaseHistory(*historyRoot); err != nil {
			return fmt.Errorf("verify private keeper release history: %w", err)
		}
	}
	listener, err := quarantinekeeper.BindWorkerSocket(policy)
	if err != nil {
		return fmt.Errorf("bind authenticated keeper socket: %w", err)
	}
	// Endpoint retirement is intentionally not automatic. An unexpected
	// crash leaves a pathname requiring independent administrative review.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	workerServe := func() error {
		return quarantinekeeper.ServeWorkerConnections(ctx, listener,
			quarantinekeeper.WorkerIdentity{UID: uint32(*workerUID), GID: uint32(*workerGID)},
			store.Handle, func(err error) {
				fmt.Fprintln(os.Stderr, "fi-quarantine-keeper worker request:", err)
			}, *maxConnections)
	}
	if !*adminEnabled {
		err = workerServe()
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	adminPolicy := quarantinekeeper.AdminSocketAuthority{
		Directory: quarantinekeeper.AdminSocketDirectory,
		KeeperUID: uint32(*keeperUID), KeeperGID: uint32(*keeperGID),
	}
	adminListener, err := quarantinekeeper.BindAdminSocket(adminPolicy)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("bind private keeper administrative socket: %w", err)
	}
	// There is no worker-facing release handler. Only a kernel-authenticated
	// root peer can reach this separate listener; the handler then takes the
	// same keeper-owned singleton inode as namespaced ingest.
	handler := quarantinekeeper.ProtectedAdminReleaseHandler(store, *historyRoot,
		workerlock.ProtectedLockPolicy{
			KeeperUID: uint32(*keeperUID), WorkerUID: uint32(*workerUID),
			WorkerGID: uint32(*workerGID),
		}, uint32(*keeperGID))
	results := make(chan error, 2)
	go func() { results <- workerServe() }()
	go func() {
		results <- quarantinekeeper.ServeAdminReleaseConnections(ctx, adminListener,
			handler, func(err error) {
				fmt.Fprintln(os.Stderr, "fi-quarantine-keeper admin release:", err)
			})
	}()
	first := <-results
	stop()
	second := <-results
	for _, result := range []error{first, second} {
		if result != nil && !errors.Is(result, context.Canceled) {
			return result
		}
	}
	if first == nil || second == nil {
		return errors.New("keeper listener terminated unexpectedly")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fi-quarantine-keeper:", err)
		os.Exit(1)
	}
}
