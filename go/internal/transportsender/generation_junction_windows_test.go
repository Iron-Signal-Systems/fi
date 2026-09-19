// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestRolloverPublishedSpoolUsesPhysicalJunctionTargetWindows(
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

	resolvedBefore, err :=
		spool.PhysicalSpoolDir(
			configuredSpool,
		)
	if err != nil {
		t.Fatal(err)
	}

	resolvedPhysical, err :=
		spool.PhysicalSpoolDir(
			physicalSpool,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.EqualFold(
		filepath.Clean(
			resolvedBefore,
		),
		filepath.Clean(
			resolvedPhysical,
		),
	) {
		t.Fatalf(
			"resolved configured spool = %q, want physical spool %q",
			resolvedBefore,
			resolvedPhysical,
		)
	}

	// Use the canonical physical spelling from this point forward. Windows may
	// have supplied the temp directory through an 8.3 short-name alias while
	// GetFinalPathNameByHandleW returns the corresponding long path.
	physicalSpool =
		resolvedPhysical

	dataName :=
		"batch-junction-test.jsonl"

	manifestName :=
		"batch-junction-test.manifest.json"

	if err :=
		os.WriteFile(
			filepath.Join(
				physicalSpool,
				dataName,
			),
			[]byte("{}\n"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			filepath.Join(
				physicalSpool,
				manifestName,
			),
			[]byte("{}\n"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	raw, found, err :=
		RolloverPublishedSpool(
			configuredSpool,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !found {
		t.Fatal(
			"RolloverPublishedSpool did not freeze populated physical spool",
		)
	}

	expectedRawRoot :=
		filepath.Join(
			filepath.Dir(
				physicalSpool,
			),
			generationRawRootDirectoryName,
		)

	rawRootRelative, err :=
		filepath.Rel(
			expectedRawRoot,
			raw.GenerationDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if rawRootRelative == "." ||
		strings.HasPrefix(
			rawRootRelative,
			"..",
		) {
		t.Fatalf(
			"raw generation %q is not beneath physical raw root %q",
			raw.GenerationDir,
			expectedRawRoot,
		)
	}

	for _, name := range []string{
		dataName,
		manifestName,
	} {

		if _, err :=
			os.Stat(
				filepath.Join(
					raw.GenerationDir,
					name,
				),
			); err != nil {
			t.Fatalf(
				"frozen generation missing %q: %v",
				name,
				err,
			)
		}
	}

	activeEntries, err :=
		os.ReadDir(
			physicalSpool,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(activeEntries) != 0 {
		t.Fatalf(
			"replacement physical spool contains %d entries, want 0",
			len(activeEntries),
		)
	}

	resolvedAfter, err :=
		spool.PhysicalSpoolDir(
			configuredSpool,
		)
	if err != nil {
		t.Fatalf(
			"configured junction did not survive rollover: %v",
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
			"configured spool resolves to %q after rollover, want %q",
			resolvedAfter,
			physicalSpool,
		)
	}

	configuredEntries, err :=
		os.ReadDir(
			configuredSpool,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(configuredEntries) != 0 {
		t.Fatalf(
			"configured junction sees %d active entries after rollover, want 0",
			len(configuredEntries),
		)
	}
}

func TestBuildRawTransportGenerationUsesConfiguredJunctionWindows(
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

	writeGenerationTestBatch(
		t,
		physicalSpool,
		"junction-builder-batch",
		[]byte("{\"record\":1}\n"),
	)

	raw, found, err :=
		RolloverPublishedSpool(
			configuredSpool,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !found {
		t.Fatal(
			"junction rollover produced no raw generation",
		)
	}

	stageRoot :=
		filepath.Join(
			root,
			"stage",
		)

	if err :=
		os.Mkdir(
			stageRoot,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	key, certificate :=
		generationTestSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	generation, err :=
		BuildRawTransportGeneration(
			context.Background(),
			GenerationSealConfig{
				BatchSigner:             key,
				BatchSigningCertificate: certificate,
				MaxEncodedBytes:         64 << 20,
				SourceID:                "iss-fs-01.iss.local",
				SpoolDir:                configuredSpool,
				StageRoot:               stageRoot,
			},
			raw,
		)
	if err != nil {
		t.Fatal(err)
	}

	if generation.GenerationID !=
		raw.GenerationID {
		t.Fatalf(
			"transport generation ID = %q, want %q",
			generation.GenerationID,
			raw.GenerationID,
		)
	}

	if generation.Published.Signed.Descriptor.GenerationID !=
		raw.GenerationID {
		t.Fatalf(
			"signed generation ID = %q, want %q",
			generation.Published.Signed.Descriptor.GenerationID,
			raw.GenerationID,
		)
	}

	if _, err :=
		os.Stat(
			raw.GenerationDir,
		); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"raw generation remains after durable seal: %v",
			err,
		)
	}

	if _, err :=
		spool.PhysicalSpoolDir(
			configuredSpool,
		); err != nil {
		t.Fatalf(
			"configured spool junction is unusable after build: %v",
			err,
		)
	}
}
