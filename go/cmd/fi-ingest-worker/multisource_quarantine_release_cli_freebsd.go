// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

const (
	m1InstalledQuarantineRoot = "/var/db/fi/ingest/quarantine"

	m1InstalledReleaseHistoryRoot = "/var/db/fi/ingest/history"

	m1InstalledWorkerLock = "/var/run/fi/fi-ingest-worker.lock"
)

type m1QuarantineReleaseOptions struct {
	ConfirmSourceID string
	Operator        string
	Reason          string
	Reference       string
	SourceID        string
}

func m1ParseQuarantineReleaseOptions(
	args []string,
	output io.Writer,
) (m1QuarantineReleaseOptions, error) {
	var options m1QuarantineReleaseOptions

	flags := flag.NewFlagSet(
		"fi-ingest-worker quarantine-release",
		flag.ContinueOnError,
	)
	flags.SetOutput(output)

	flags.StringVar(
		&options.SourceID,
		"source-id", "",
		"exact enabled source ID to release",
	)
	flags.StringVar(
		&options.ConfirmSourceID,
		"confirm-source-id", "",
		"repeat the exact source ID to confirm release",
	)
	flags.StringVar(
		&options.Operator,
		"operator", "",
		"operator identification for audit",
	)
	flags.StringVar(
		&options.Reference,
		"change-reference", "",
		"approved change or incident reference",
	)
	flags.StringVar(
		&options.Reason,
		"reason", "",
		"description of completed source review and remediation",
	)

	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if flags.NArg() != 0 {
		return options, errors.New(
			"FI quarantine release does not accept positional arguments",
		)
	}

	if !m1ValidQuarantineSource(options.SourceID) {
		return options, errors.New(
			"FI quarantine release requires a valid exact source ID",
		)
	}
	if options.ConfirmSourceID != options.SourceID {
		return options, errors.New(
			"FI quarantine release confirmation must exactly match source ID",
		)
	}

	for _, item := range []struct {
		name  string
		value string
		limit int
	}{
		{"operator", options.Operator, 256},
		{"change reference", options.Reference, 256},
		{"reason", options.Reason, 2048},
	} {
		if strings.TrimSpace(item.value) == "" ||
			len(item.value) > item.limit ||
			strings.ContainsAny(item.value, "\r\n") {
			return options, fmt.Errorf(
				"FI quarantine release %s is invalid",
				item.name,
			)
		}
	}

	return options, nil
}

func m1ValidateEnabledReleaseSource(
	sourceID string,
	enabledSources []string,
) error {
	if !m1ValidQuarantineSource(sourceID) {
		return errors.New("invalid quarantine release source identity")
	}

	for _, enrolled := range enabledSources {
		if enrolled == sourceID {
			return nil
		}
	}

	return fmt.Errorf(
		"FI source %q is not enabled in the installed source registry",
		sourceID,
	)
}

// m1ValidateMaintenancePathAgreement pins the namespaced quarantine
// root and forbids fallback to the old worker-owned singleton path.
// The old worker-side release command remains independently disabled;
// a keeper-authorized release mechanism must be implemented separately.
// Legacy ingest remains unaffected.
func m1ValidateMaintenancePathAgreement(
	config workerConfig,
) error {
	if !config.SourceNamespaces {
		return nil
	}

	if config.QuarantineRoot != m1InstalledQuarantineRoot {
		return fmt.Errorf(
			"FI namespaced worker quarantine root %q does not match offline maintenance root %q",
			config.QuarantineRoot,
			m1InstalledQuarantineRoot,
		)
	}

	if config.LockFile != workerlock.ProtectedLockPath {
		return fmt.Errorf(
			"FI namespaced worker lock %q must use keeper-protected path %q",
			config.LockFile, workerlock.ProtectedLockPath,
		)
	}

	return nil
}

// m1RunQuarantineReleaseCommand is only reachable through the
// explicitly selected quarantine-release subcommand.
//
// It does not connect to PostgreSQL, start a worker session,
// create state directories, or modify source authorization.
func m1RunQuarantineReleaseCommand(
	args []string,
	output io.Writer,
) error {
	options, err := m1ParseQuarantineReleaseOptions(
		args, output,
	)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}

	// Parse options and permit help, but do not allow the worker
	// executable to release quarantine using its own identity.
	if err := m1RequireIndependentReleaseAuthority(); err != nil {
		return err
	}

	issuer, err := receivertrust.LoadCertificate(
		receivertrust.BatchIssuerPath,
	)
	if err != nil {
		return fmt.Errorf(
			"load installed Batch Signing issuer: %w",
			err,
		)
	}

	registry, err := receivertrust.LoadBatchSourceRegistry(
		receivertrust.SourceRegistryPath,
		issuer,
	)
	if err != nil {
		return fmt.Errorf(
			"validate installed FI source registry: %w",
			err,
		)
	}

	enabledSources := registry.EnabledSourceIDs()

	if err := m1ValidateEnabledReleaseSource(
		options.SourceID,
		enabledSources,
	); err != nil {
		return err
	}

	request := m1QuarantineReleaseRequest{
		EnrolledSources: enabledSources,
		HistoryRoot:     m1InstalledReleaseHistoryRoot,
		LockFile:        m1InstalledWorkerLock,
		Operator:        options.Operator,
		QuarantineRoot:  m1InstalledQuarantineRoot,
		Reason:          options.Reason,
		Reference:       options.Reference,
		SourceID:        options.SourceID,
	}

	auditPath, err := m1ReleaseQuarantinedSource(request)
	if err != nil {
		return err
	}

	fmt.Fprintf(
		output,
		"FI QUARANTINE RELEASED source=%s audit=%s reference=%s\n",
		options.SourceID,
		auditPath,
		options.Reference,
	)

	return nil
}
