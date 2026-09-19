// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportgeneration

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoverDurableCustodyRootDiscoversPublishedAndRemovesProvisional(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)
	config, custody := newRestartCustodyFixture(t, fixture)

	provisional := filepath.Join(
		config.RootDir,
		".fi-generation-custody-crash.open",
	)
	if err := os.WriteFile(provisional, []byte("abandoned"), 0o600); err != nil {
		t.Fatal(err)
	}

	recovery, err := RecoverDurableCustodyRoot(config)
	if err != nil {
		t.Fatal(err)
	}

	if recovery.RemovedProvisional != 1 {
		t.Fatalf(
			"removed provisional = %d, want 1",
			recovery.RemovedProvisional,
		)
	}

	if len(recovery.Objects) != 1 {
		t.Fatalf("objects = %d, want 1", len(recovery.Objects))
	}

	if recovery.Objects[0].Path != custody.CustodyPath ||
		recovery.Objects[0].Bytes != custody.CustodyBytes {
		t.Fatal("restart discovery changed durable custody identity")
	}

	if _, err := os.Lstat(provisional); !os.IsNotExist(err) {
		t.Fatal("abandoned provisional custody entry was not removed")
	}
}

func TestRecoverDurableCustodyRootRejectsUnexpectedEntry(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)
	config, _ := newRestartCustodyFixture(t, fixture)

	if err := os.WriteFile(
		filepath.Join(config.RootDir, "unexpected.txt"),
		[]byte("unexpected"),
		0o400,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := RecoverDurableCustodyRoot(config); err == nil {
		t.Fatal("unexpected custody restart entry was accepted")
	}
}

func TestRecoverDurableCustodyRootDoesNotCleanBeforeStructuralFailure(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)
	config, _ := newRestartCustodyFixture(t, fixture)

	provisional := filepath.Join(
		config.RootDir,
		".fi-generation-custody-crash.open",
	)
	if err := os.WriteFile(provisional, []byte("abandoned"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(config.RootDir, "unexpected.txt"),
		[]byte("unexpected"),
		0o400,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := RecoverDurableCustodyRoot(config); err == nil {
		t.Fatal("structurally invalid custody root was accepted")
	}

	if _, err := os.Lstat(provisional); err != nil {
		t.Fatalf("provisional was removed before structural validation completed: %v", err)
	}
}

func TestReadDiscoveredDurableCustodyArtifactsRevalidatesExactObject(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)
	config, custody := newRestartCustodyFixture(t, fixture)

	recovery, err := RecoverDurableCustodyRoot(config)
	if err != nil {
		t.Fatal(err)
	}

	var artifactCount uint64

	restarted, err := ReadDiscoveredDurableCustodyArtifacts(
		recovery.Objects[0],
		config,
		func(_ Descriptor) (CanonicalArtifactHandler, error) {
			return func(_ string, reader io.Reader) error {
				artifactCount++
				_, err := io.Copy(io.Discard, reader)
				return err
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if restarted.Disposition != CustodyDispositionExisting {
		t.Fatalf(
			"restart disposition = %q, want EXISTING",
			restarted.Disposition,
		)
	}

	if restarted.Transfer != custody.Transfer ||
		restarted.CustodyPath != custody.CustodyPath ||
		restarted.CustodySHA256 != custody.CustodySHA256 {
		t.Fatal("restart reread changed exact custody transfer identity")
	}

	if artifactCount != custody.Transfer.Descriptor.ArtifactCount {
		t.Fatalf(
			"artifact count = %d, want %d",
			artifactCount,
			custody.Transfer.Descriptor.ArtifactCount,
		)
	}
}

func TestReadDiscoveredDurableCustodyArtifactsRejectsRenamedIdentity(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)
	config, custody := newRestartCustodyFixture(t, fixture)

	wrongName := filepath.Join(
		config.RootDir,
		"generation-"+strings.Repeat("a", 64)+".figt",
	)
	if wrongName == custody.CustodyPath {
		t.Fatal("test generated the real custody object name")
	}

	if err := os.Rename(custody.CustodyPath, wrongName); err != nil {
		t.Fatal(err)
	}

	recovery, err := RecoverDurableCustodyRoot(config)
	if err != nil {
		t.Fatal(err)
	}

	if len(recovery.Objects) != 1 {
		t.Fatalf("objects = %d, want 1", len(recovery.Objects))
	}

	_, err = ReadDiscoveredDurableCustodyArtifacts(
		recovery.Objects[0],
		config,
		func(_ Descriptor) (CanonicalArtifactHandler, error) {
			return func(_ string, reader io.Reader) error {
				_, err := io.Copy(io.Discard, reader)
				return err
			}, nil
		},
	)
	if err == nil {
		t.Fatal("custody object under the wrong deterministic identity name was accepted")
	}
}

func TestReadDiscoveredDurableCustodyArtifactsRejectsMutationAfterDiscovery(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)
	config, _ := newRestartCustodyFixture(t, fixture)

	recovery, err := RecoverDurableCustodyRoot(config)
	if err != nil {
		t.Fatal(err)
	}

	candidate := recovery.Objects[0]

	if err := os.Chmod(candidate.Path, 0o600); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(candidate.Path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := file.WriteAt([]byte{0xff}, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(candidate.Path, 0o400); err != nil {
		t.Fatal(err)
	}

	_, err = ReadDiscoveredDurableCustodyArtifacts(
		candidate,
		config,
		func(_ Descriptor) (CanonicalArtifactHandler, error) {
			return func(_ string, reader io.Reader) error {
				_, err := io.Copy(io.Discard, reader)
				return err
			}, nil
		},
	)
	if err == nil {
		t.Fatal("custody mutation after restart discovery was accepted")
	}
}

func newRestartCustodyFixture(
	t *testing.T,
	fixture generationReceiveFixture,
) (
	CustodyConfig,
	CustodyResult,
) {
	t.Helper()

	root := filepath.Join(t.TempDir(), "custody")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	config := CustodyConfig{
		Receive: fixture.Config,
		RootDir: root,
	}

	custody, err := ReceiveToDurableCustody(
		bytes.NewReader(fixture.Wire),
		fixture.Offer,
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	return config, custody
}
