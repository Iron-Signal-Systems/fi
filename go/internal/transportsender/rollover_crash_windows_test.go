// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestRolloverRecoversMissingPhysicalSpoolAfterFreezeWindows(
	t *testing.T,
) {
	root :=
		t.TempDir()

	physicalParent :=
		filepath.Join(
			root,
			"physical",
		)

	if err :=
		os.Mkdir(
			physicalParent,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	physicalSpool :=
		filepath.Join(
			physicalParent,
			"spool",
		)

	if err :=
		os.Mkdir(
			physicalSpool,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	configuredParent :=
		filepath.Join(
			root,
			"configured",
		)

	if err :=
		os.Mkdir(
			configuredParent,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	configuredSpool :=
		filepath.Join(
			configuredParent,
			"spool",
		)

	command :=
		exec.Command(
			"cmd.exe",
			"/d",
			"/c",
			"mklink",
			"/J",
			configuredSpool,
			physicalSpool,
		)

	output, err :=
		command.CombinedOutput()
	if err != nil {
		t.Skipf(
			"cannot create Windows junction: %v: %s",
			err,
			strings.TrimSpace(
				string(output),
			),
		)
	}

	t.Cleanup(
		func() {
			_ =
				os.Remove(
					configuredSpool,
				)
		},
	)

	physicalSpool, err =
		spool.PhysicalSpoolPath(
			configuredSpool,
		)
	if err != nil {
		t.Fatal(err)
	}

	writeGenerationTestBatch(
		t,
		physicalSpool,
		"crash-recovery-batch",
		[]byte("{\"record\":1}\n"),
	)

	const generationID = "20260918T120000.000000000Z-crashrecovery"

	rawRoot :=
		filepath.Join(
			filepath.Dir(
				physicalSpool,
			),
			generationRawRootDirectoryName,
		)

	if err :=
		os.Mkdir(
			rawRoot,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	rawDir :=
		filepath.Join(
			rawRoot,
			generationDirectoryPrefix+
				generationID,
		)

	nextDir :=
		filepath.Join(
			filepath.Dir(
				physicalSpool,
			),
			generationRolloverNextPrefix+
				generationID,
		)

	if err :=
		os.Mkdir(
			nextDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	// Simulate power loss after the active spool has been frozen but before
	// nextDir has been promoted into the physical active-spool path.
	if err :=
		publishGenerationDirectory(
			physicalSpool,
			rawDir,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		os.Stat(
			physicalSpool,
		); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"physical spool still exists in simulated crash state: %v",
			err,
		)
	}

	resolvedMissingTarget, err :=
		spool.PhysicalSpoolPath(
			configuredSpool,
		)
	if err != nil {
		t.Fatalf(
			"cannot resolve broken configured junction target: %v",
			err,
		)
	}

	if !strings.EqualFold(
		filepath.Clean(
			resolvedMissingTarget,
		),
		filepath.Clean(
			physicalSpool,
		),
	) {
		t.Fatalf(
			"broken junction resolved to %q, want %q",
			resolvedMissingTarget,
			physicalSpool,
		)
	}

	raw, found, err :=
		RolloverPublishedSpool(
			configuredSpool,
		)
	if err != nil {
		t.Fatal(err)
	}

	if found {
		t.Fatalf(
			"recovery-only rollover unexpectedly created another generation: %+v",
			raw,
		)
	}

	if raw.GenerationDir != "" ||
		raw.GenerationID != "" {
		t.Fatalf(
			"recovery-only rollover returned non-zero raw generation: %+v",
			raw,
		)
	}

	activeEntries, err :=
		os.ReadDir(
			physicalSpool,
		)
	if err != nil {
		t.Fatalf(
			"replacement physical spool was not restored: %v",
			err,
		)
	}

	if len(activeEntries) != 0 {
		t.Fatalf(
			"recovered active spool contains %d entries, want 0",
			len(activeEntries),
		)
	}

	if _, err :=
		os.Stat(
			nextDir,
		); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"rollover-next directory still exists after recovery: %v",
			err,
		)
	}

	frozenPairs, err :=
		spool.ValidatePublishedSpoolStructureLocked(
			rawDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if frozenPairs != 1 {
		t.Fatalf(
			"frozen generation pairs = %d, want 1",
			frozenPairs,
		)
	}

	resolvedAfter, err :=
		spool.PhysicalSpoolDir(
			configuredSpool,
		)
	if err != nil {
		t.Fatalf(
			"configured junction was not restored after rollover recovery: %v",
			err,
		)
	}

	if !strings.EqualFold(
		filepath.Clean(
			resolvedAfter,
		),
		filepath.Clean(
			physicalSpool,
		),
	) {
		t.Fatalf(
			"restored configured junction resolves to %q, want %q",
			resolvedAfter,
			physicalSpool,
		)
	}
}

func TestCleanupRolloverNextDirectoriesRemovesEmptyDirectoryWindows(
	t *testing.T,
) {
	parent :=
		t.TempDir()

	spoolDir :=
		filepath.Join(
			parent,
			"spool",
		)

	if err :=
		os.Mkdir(
			spoolDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	nextDir :=
		filepath.Join(
			parent,
			generationRolloverNextPrefix+
				"stale",
		)

	if err :=
		os.Mkdir(
			nextDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		cleanupRolloverNextDirectories(
			spoolDir,
		); err != nil {
		t.Fatal(err)
	}

	if _, err :=
		os.Stat(
			nextDir,
		); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"empty rollover-next directory still exists: %v",
			err,
		)
	}
}

func TestCleanupRolloverNextDirectoriesRejectsNonEmptyDirectoryWindows(
	t *testing.T,
) {
	parent :=
		t.TempDir()

	spoolDir :=
		filepath.Join(
			parent,
			"spool",
		)

	if err :=
		os.Mkdir(
			spoolDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	nextDir :=
		filepath.Join(
			parent,
			generationRolloverNextPrefix+
				"nonempty",
		)

	if err :=
		os.Mkdir(
			nextDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			filepath.Join(
				nextDir,
				"unexpected",
			),
			[]byte("x"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		cleanupRolloverNextDirectories(
			spoolDir,
		); err == nil {
		t.Fatal(
			"cleanup accepted non-empty rollover-next directory",
		)
	}

	if _, err :=
		os.Stat(
			nextDir,
		); err != nil {
		t.Fatalf(
			"non-empty rollover-next directory was changed: %v",
			err,
		)
	}
}
