// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
	"github.com/jackc/pgx/v5"
)

func workerRecordedSourcePlan(
	ctx context.Context,
	connection *pgx.Conn,
	config workerConfig,
) (recordingest.ReconcilePlan, error) {
	if config.SourceNamespaces {
		return recordingest.PlanRecordedGenerationsForSource(
			ctx,
			connection,
			config.RecordedRoot,
			config.SourceID,
		)
	}

	return recordingest.PlanRecordedGenerationsForIngest(
		ctx,
		connection,
		config.RecordedRoot,
		config.SourceID,
	)
}

func workerReceiptDirectory(
	config workerConfig,
) (string, error) {
	if !config.SourceNamespaces {
		return config.RecordedRoot, nil
	}

	return generationrecorder.RecordedSourceDirectory(
		config.RecordedRoot,
		config.SourceID,
	)
}

func workerDiscoverReceiptNames(
	config workerConfig,
	names []string,
) ([]recordingest.RecordedReceiptCandidate, error) {
	root, err := workerReceiptDirectory(config)
	if err != nil {
		return nil, err
	}

	filter := config.SourceID
	if config.SourceNamespaces {
		filter = ""
	}

	candidates, err := recordingest.DiscoverRecordedReceiptsByName(
		root,
		names,
		filter,
	)
	if err == nil && config.SourceNamespaces {
		for _, candidate := range candidates {
			if candidate.SourceID != config.SourceID {
				err = fmt.Errorf(
					"FI authoritative source namespace %q contains receipt belonging to %q",
					config.SourceID,
					candidate.SourceID,
				)
				break
			}
		}
	}
	if err != nil && config.SourceNamespaces {
		return nil, &recordingest.SourceReceiptDiscoveryError{
			SourceID: config.SourceID,
			Cause:    err,
		}
	}

	return candidates, err
}

// validateWorkerSourceNamespaces checks the complete directory topology
// without scanning receipts or modifying the recorded dataset.
// A deployment with missing or unsafe directories must not start.
func validateWorkerSourceNamespaces(config workerConfig) error {
	if !config.SourceNamespaces {
		return nil
	}

	if len(config.SourceIDs) == 0 {
		return fmt.Errorf(
			"FI namespaced receipt mode requires enabled sources",
		)
	}

	if !filepath.IsAbs(config.RecordedRoot) ||
		filepath.Clean(config.RecordedRoot) != config.RecordedRoot {
		return fmt.Errorf(
			"FI namespaced recorded root must be a clean absolute path",
		)
	}

	directories := []string{
		config.RecordedRoot,
		filepath.Join(config.RecordedRoot, "sources"),
	}

	for _, sourceID := range config.SourceIDs {
		directory, err := generationrecorder.RecordedSourceDirectory(
			config.RecordedRoot,
			sourceID,
		)
		if err != nil {
			return err
		}
		directories = append(directories, directory)
	}

	for _, directory := range directories {
		resolved, err := filepath.EvalSymlinks(directory)
		if err != nil {
			return fmt.Errorf(
				"FI receipt namespace preflight %q: %w",
				directory,
				err,
			)
		}
		if resolved != directory {
			return fmt.Errorf(
				"FI receipt namespace traverses symlink: %q",
				directory,
			)
		}

		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf(
				"FI receipt namespace inspection %q: %w",
				directory,
				err,
			)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			return fmt.Errorf(
				"FI receipt namespace must be a private 0700 directory: %q",
				directory,
			)
		}
	}

	return nil
}
