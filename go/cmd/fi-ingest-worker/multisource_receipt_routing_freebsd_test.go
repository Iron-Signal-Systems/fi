// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func provisionWorkerNamespace(
	t *testing.T,
) workerConfig {
	t.Helper()

	root := filepath.Join(t.TempDir(), "recorded")

	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}

	parent := filepath.Join(root, "sources")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}

	sources := []string{
		"iss-fs-2019.iss.local",
		"iss-fs-22.iss.local",
	}

	for _, source := range sources {
		if err := os.Mkdir(
			filepath.Join(parent, source),
			0700,
		); err != nil {
			t.Fatal(err)
		}
	}

	return workerConfig{
		RecordedRoot:     root,
		SourceNamespaces: true,
		SourceIDs:        sources,
		RepairInterval:   time.Hour,
	}
}

func TestM1WorkerNamespacePreflight(t *testing.T) {
	config := provisionWorkerNamespace(t)

	if err := validateWorkerSourceNamespaces(config); err != nil {
		t.Fatal(err)
	}

	config.SourceID = config.SourceIDs[0]
	root, err := workerReceiptDirectory(config)
	if err != nil {
		t.Fatal(err)
	}

	expected := filepath.Join(
		config.RecordedRoot,
		"sources",
		config.SourceID,
	)
	if root != expected {
		t.Fatalf("source receipt root=%q want=%q", root, expected)
	}

	config.SourceNamespaces = false

	flat, err := workerReceiptDirectory(config)
	if err != nil {
		t.Fatal(err)
	}
	if flat != config.RecordedRoot {
		t.Fatalf("flat receipt root changed: %q", flat)
	}
}

func TestM1WorkerNamespacePreflightRejectsMissingSource(
	t *testing.T,
) {
	config := provisionWorkerNamespace(t)

	if err := os.Remove(
		filepath.Join(
			config.RecordedRoot,
			"sources",
			config.SourceIDs[0],
		),
	); err != nil {
		t.Fatal(err)
	}

	if err := validateWorkerSourceNamespaces(config); err == nil {
		t.Fatal("missing source namespace was accepted")
	}
}

func TestM1WorkerNamespacePreflightRejectsSymlink(
	t *testing.T,
) {
	config := provisionWorkerNamespace(t)

	path := filepath.Join(
		config.RecordedRoot,
		"sources",
		config.SourceIDs[0],
	)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), path); err != nil {
		t.Fatal(err)
	}

	if err := validateWorkerSourceNamespaces(config); err == nil {
		t.Fatal("symlinked namespace was accepted")
	}
}

func TestM1WorkerReceiptDiscoveryFailureIsSourceScoped(
	t *testing.T,
) {
	config := provisionWorkerNamespace(t)
	config.SourceID = config.SourceIDs[0]

	badName := "generation-" +
		strings.Repeat("0", 64) +
		".record.json"

	badPath := filepath.Join(
		config.RecordedRoot,
		"sources",
		config.SourceID,
		badName,
	)

	if err := os.WriteFile(
		badPath,
		[]byte("{invalid-receipt"),
		0400,
	); err != nil {
		t.Fatal(err)
	}

	_, err := workerDiscoverReceiptNames(
		config,
		[]string{badName},
	)

	var discovery *recordingest.SourceReceiptDiscoveryError
	if !errors.As(err, &discovery) {
		t.Fatalf("receipt failure lacks source identity: %v", err)
	}
	if discovery.SourceID != config.SourceID {
		t.Fatalf("incorrect source attribution: %q", discovery.SourceID)
	}

	config.SourceID = config.SourceIDs[1]

	receipts, err := workerDiscoverReceiptNames(config, nil)
	if err != nil {
		t.Fatalf("healthy source was affected: %v", err)
	}
	if len(receipts) != 0 {
		t.Fatal("unexpected receipts in healthy empty namespace")
	}
}
