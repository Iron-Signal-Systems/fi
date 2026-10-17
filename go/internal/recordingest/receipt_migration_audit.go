// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

type RecordedReceiptMigrationAudit struct {
	Legacy     int
	Namespaced int
	BySource   map[string]int
}

// AuditRecordedReceiptMigration verifies an exact immutable hard-link
// migration. It does not write, create, delete, or rename any object.
//
// The roots may differ for development rehearsal or be identical when
// both layouts occupy the same authoritative recorded dataset.
func AuditRecordedReceiptMigration(
	legacyRoot string,
	namespacedRoot string,
	sourceIDs []string,
) (RecordedReceiptMigrationAudit, error) {
	var report RecordedReceiptMigrationAudit

	if len(sourceIDs) == 0 {
		return report, fmt.Errorf(
			"FI receipt migration requires an explicit source inventory",
		)
	}

	for _, root := range []string{legacyRoot, namespacedRoot} {
		if root == "" ||
			!filepath.IsAbs(root) ||
			filepath.Clean(root) != root {
			return report, fmt.Errorf(
				"FI migration root is not a clean absolute path: %q",
				root,
			)
		}

		if err := auditMigrationDirectory(root); err != nil {
			return report, err
		}
	}

	sharedRoot := legacyRoot == namespacedRoot

	legacyEntries, err := os.ReadDir(legacyRoot)
	if err != nil {
		return report, err
	}

	legacyFiles := 0

	for _, entry := range legacyEntries {
		name := entry.Name()

		if sharedRoot && name == "sources" {
			continue
		}

		if !migrationReceiptName(name) {
			return report, fmt.Errorf(
				"FI legacy receipt root contains unexpected object %q",
				name,
			)
		}

		legacyFiles++
	}

	legacy, err := DiscoverRecordedReceipts(legacyRoot, "")
	if err != nil {
		return report, err
	}

	if len(legacy) != legacyFiles {
		return report, fmt.Errorf(
			"FI legacy inventory incomplete: validated=%d physical=%d",
			len(legacy),
			legacyFiles,
		)
	}

	expected := make(
		map[string]RecordedReceiptCandidate,
		len(legacy),
	)

	for _, candidate := range legacy {
		name := filepath.Base(candidate.Path)

		if _, exists := expected[name]; exists {
			return report, fmt.Errorf(
				"FI legacy receipt name repeated: %q",
				name,
			)
		}

		expected[name] = candidate
	}

	namespaceEntries, err := os.ReadDir(namespacedRoot)
	if err != nil {
		return report, err
	}

	for _, entry := range namespaceEntries {
		name := entry.Name()

		if name == "sources" {
			continue
		}

		if !sharedRoot || !migrationReceiptName(name) {
			return report, fmt.Errorf(
				"FI namespaced root contains unexpected object %q",
				name,
			)
		}
	}

	sourceParent := filepath.Join(namespacedRoot, "sources")

	if err := auditMigrationDirectory(sourceParent); err != nil {
		return report, err
	}

	inventory := make(map[string]bool, len(sourceIDs))
	caseFolded := make(map[string]bool, len(sourceIDs))

	for _, sourceID := range sourceIDs {
		sourceRoot, err := generationrecorder.RecordedSourceDirectory(
			namespacedRoot,
			sourceID,
		)
		if err != nil {
			return report, err
		}

		folded := strings.ToLower(sourceID)

		if inventory[sourceID] || caseFolded[folded] {
			return report, fmt.Errorf(
				"FI migration source inventory contains duplicate %q",
				sourceID,
			)
		}

		inventory[sourceID] = true
		caseFolded[folded] = true

		if err := auditMigrationDirectory(sourceRoot); err != nil {
			return report, err
		}
	}

	directories, err := os.ReadDir(sourceParent)
	if err != nil {
		return report, err
	}

	if len(directories) != len(inventory) {
		return report, fmt.Errorf(
			"FI source directory inventory mismatch: found=%d expected=%d",
			len(directories),
			len(inventory),
		)
	}

	for _, entry := range directories {
		if !inventory[entry.Name()] {
			return report, fmt.Errorf(
				"FI unexpected source directory %q",
				entry.Name(),
			)
		}
	}

	report.BySource = make(map[string]int, len(sourceIDs))

	seen := make(map[string]bool, len(legacy))

	for _, sourceID := range sourceIDs {
		sourceRoot, _ := generationrecorder.RecordedSourceDirectory(
			namespacedRoot,
			sourceID,
		)

		entries, err := os.ReadDir(sourceRoot)
		if err != nil {
			return report, err
		}

		for _, entry := range entries {
			if !migrationReceiptName(entry.Name()) {
				return report, fmt.Errorf(
					"FI source %q contains unexpected object %q",
					sourceID,
					entry.Name(),
				)
			}
		}

		candidates, err := DiscoverRecordedReceiptsForSource(
			namespacedRoot,
			sourceID,
		)
		if err != nil {
			return report, err
		}

		if len(candidates) != len(entries) {
			return report, fmt.Errorf(
				"FI source %q receipt enumeration mismatch",
				sourceID,
			)
		}

		for _, candidate := range candidates {
			name := filepath.Base(candidate.Path)

			if seen[name] {
				return report, fmt.Errorf(
					"FI namespaced receipt appears more than once: %q",
					name,
				)
			}
			seen[name] = true

			original, found := expected[name]
			if !found {
				return report, fmt.Errorf(
					"FI namespaced receipt has no legacy counterpart: %q",
					name,
				)
			}

			if original.SourceID != sourceID ||
				candidate.SourceID != original.SourceID ||
				candidate.GenerationID != original.GenerationID ||
				candidate.ReceiptSHA256 != original.ReceiptSHA256 ||
				candidate.TransferSHA256 != original.TransferSHA256 {
				return report, fmt.Errorf(
					"FI migration receipt identity mismatch: %q",
					name,
				)
			}

			oldInfo, err := os.Lstat(original.Path)
			if err != nil {
				return report, err
			}

			newInfo, err := os.Lstat(candidate.Path)
			if err != nil {
				return report, err
			}

			if !os.SameFile(oldInfo, newInfo) {
				return report, fmt.Errorf(
					"FI migration receipt is not the same immutable hard-linked object: %q",
					name,
				)
			}

			report.BySource[sourceID]++
			report.Namespaced++
		}
	}

	if report.Namespaced != len(legacy) {
		return report, fmt.Errorf(
			"FI migration accounting mismatch: legacy=%d namespaced=%d",
			len(legacy),
			report.Namespaced,
		)
	}

	report.Legacy = len(legacy)
	return report, nil
}

func auditMigrationDirectory(path string) error {
	if err := validateRecordedReceiptRoot(path); err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf(
			"FI migration directory %q must have mode 0700",
			path,
		)
	}

	return nil
}

func migrationReceiptName(name string) bool {
	return filepath.Base(name) == name &&
		strings.HasPrefix(name, "generation-") &&
		strings.HasSuffix(name, ".record.json")
}
