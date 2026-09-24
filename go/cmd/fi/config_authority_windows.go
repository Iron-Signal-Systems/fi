// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

type serviceOperationalSnapshot struct {
	ConfigPath              string
	GovernedRoots           []string
	StateDir                string
	USNInterval             time.Duration
	VersionID               string
	WindowsSecurityInterval time.Duration
}

func applyConfiguredSpoolPolicy(value config.Config) error {
	if value.VersionID != config.Version11 {
		return fmt.Errorf(
			"FI operational configuration version %s does not define spool policy; version %s is required",
			value.VersionID,
			config.Version11,
		)
	}

	return spool.ConfigurePolicy(spool.Policy{
		Directory:        value.Storage.SpoolDir,
		MaxBatchRecords:  value.Spool.MaxBatchRecords,
		MaxRecordBytes:   value.Spool.MaxRecordBytes,
		TargetBatchBytes: value.Spool.TargetBatchBytes,
	})
}

func resolveServiceConfiguration(
	collectionOverride string,
	supportingRefreshOverride string,
) (
	serviceOperationalSnapshot,
	time.Duration,
	time.Duration,
	error,
) {
	value, configPath, err := config.LoadDefault()
	if err != nil {
		return serviceOperationalSnapshot{}, 0, 0, err
	}
	if value.VersionID != config.Version11 {
		return serviceOperationalSnapshot{}, 0, 0, fmt.Errorf(
			"FI service requires configuration version %s",
			config.Version11,
		)
	}
	if err := applyConfiguredSpoolPolicy(value); err != nil {
		return serviceOperationalSnapshot{}, 0, 0, err
	}

	collection, supporting, err := resolveCollectorIntervals(
		value,
		collectionOverride,
		supportingRefreshOverride,
		os.Stderr,
	)
	if err != nil {
		return serviceOperationalSnapshot{}, 0, 0, err
	}

	snapshot := serviceOperationalSnapshot{
		ConfigPath:              configPath,
		GovernedRoots:           append([]string(nil), value.GovernedRoots...),
		StateDir:                value.Storage.StateDir,
		USNInterval:             value.Collector.USNEvery,
		VersionID:               value.VersionID,
		WindowsSecurityInterval: value.Collector.WindowsSecurityEvery,
	}

	return snapshot, collection, supporting, nil
}

func resolveCollectorIntervals(
	value config.Config,
	collectionOverride string,
	supportingRefreshOverride string,
	warningWriter io.Writer,
) (time.Duration, time.Duration, error) {
	collection := value.Collector.CollectionEvery
	supporting := value.Collector.SupportingRefreshEvery

	var overrides []string

	if strings.TrimSpace(collectionOverride) != "" {
		overrides = append(
			overrides,
			"service-collection-every",
		)
	}
	if strings.TrimSpace(supportingRefreshOverride) != "" {
		overrides = append(
			overrides,
			"service-supporting-refresh-every",
		)
	}

	if len(overrides) != 0 &&
		(!value.Troubleshoot.Enabled ||
			!value.Troubleshoot.AllowCollectorCLIOverride) {
		return 0, 0, errors.New(
			"manual FI collector interval overrides are disabled by configuration; set troubleshoot.enabled=true and troubleshoot.allow_collector_cli_override=true for controlled troubleshooting",
		)
	}

	var err error

	if strings.TrimSpace(collectionOverride) != "" {
		collection, err = parseServiceInterval(
			"service-collection-every",
			collectionOverride,
		)
		if err != nil {
			return 0, 0, err
		}
	}

	if strings.TrimSpace(supportingRefreshOverride) != "" {
		supporting, err = parseServiceInterval(
			"service-supporting-refresh-every",
			supportingRefreshOverride,
		)
		if err != nil {
			return 0, 0, err
		}
	}

	if len(overrides) != 0 {
		writeAuthorizedCollectorOverrideWarning(
			warningWriter,
			overrides,
		)
	}

	return collection, supporting, nil
}

func writeAuthorizedCollectorOverrideWarning(
	writer io.Writer,
	overrides []string,
) {
	if writer == nil || len(overrides) == 0 {
		return
	}

	fmt.Fprintf(
		writer,
		"WARNING: FI troubleshooting CLI override authorized by configuration; collector=[%s]\n",
		strings.Join(overrides, ", "),
	)
}
