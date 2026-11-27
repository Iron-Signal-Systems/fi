// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

// fi-keeper-admin is an explicitly invoked, root-only operator client.
// It does not share the worker-facing quarantine socket or release authority.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/quarantinekeeper"
)

func keeperIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("fi-quarantine-keeper")
	if err != nil {
		return 0, 0, fmt.Errorf("resolve keeper service account: %w", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, 0, errors.New("invalid keeper account UID")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return 0, 0, errors.New("invalid keeper account GID")
	}
	return uint32(uid), uint32(gid), nil
}

func run(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("administrative quarantine release requires root")
	}
	if len(args) == 0 || args[0] != "release" {
		return errors.New("usage: fi-keeper-admin release -source ID -confirm ID -reference CHANGE -justification TEXT")
	}
	flags := flag.NewFlagSet("release", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	source := flags.String("source", "", "exact enrolled source")
	confirmation := flags.String("confirm", "", "must exactly match source")
	reference := flags.String("reference", "", "operator change or incident reference")
	justification := flags.String("justification", "", "operator review justification")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected release arguments")
	}
	request := quarantinekeeper.AdminReleaseRequest{
		Version:   quarantinekeeper.AdminProtocolVersion,
		Operation: "release", SourceID: *source, ConfirmSource: *confirmation,
		Reference: *reference, Justification: *justification,
	}
	if err := request.Validate(); err != nil {
		return err
	}
	uid, gid, err := keeperIdentity()
	if err != nil {
		return err
	}
	policy := quarantinekeeper.AdminSocketAuthority{
		Directory: quarantinekeeper.AdminSocketDirectory,
		KeeperUID: uid, KeeperGID: gid,
	}
	if err := quarantinekeeper.VerifyAdminSocketAuthority(policy, true); err != nil {
		return fmt.Errorf("verify administrative endpoint authority: %w", err)
	}
	path := filepath.Join(policy.Directory, quarantinekeeper.AdminSocketName)
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect keeper administrative endpoint: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		return err
	}
	if err := quarantinekeeper.WriteAdminReleaseRequest(conn, request); err != nil {
		return err
	}
	response, err := quarantinekeeper.ReadAdminReleaseResponse(conn)
	if err != nil {
		return fmt.Errorf("read authenticated keeper release result: %w", err)
	}
	if response.Status != "released" {
		return fmt.Errorf("keeper release denied: %s", response.ErrorCode)
	}
	fmt.Printf("RELEASED source=%s audit=%s\n", *source, response.AuditPath)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fi-keeper-admin:", err)
		os.Exit(1)
	}
}
