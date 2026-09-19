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
	"testing"
)

func TestReadDurableCustodyArtifactsRevalidatesExactObject(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)

	custodyRoot := filepath.Join(
		t.TempDir(),
		"custody",
	)

	if err := os.Mkdir(custodyRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	config := CustodyConfig{
		Receive: fixture.Config,
		RootDir: custodyRoot,
	}

	custody, err := ReceiveToDurableCustody(
		bytes.NewReader(fixture.Wire),
		fixture.Offer,
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	var artifacts [][]byte

	transfer, err := ReadDurableCustodyArtifacts(
		custody,
		config,
		func(name string, reader io.Reader) error {
			value, err := io.ReadAll(reader)
			if err != nil {
				return err
			}

			names = append(names, name)
			artifacts = append(artifacts, value)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if transfer != custody.Transfer {
		t.Fatal("durable custody reread changed validated transfer identity")
	}

	if uint64(len(names)) != transfer.Descriptor.ArtifactCount {
		t.Fatalf(
			"artifact count = %d, want %d",
			len(names),
			transfer.Descriptor.ArtifactCount,
		)
	}

	if len(artifacts) != len(names) {
		t.Fatal("artifact name/content collection diverged")
	}

	for index := range names {
		if names[index] == "" || len(artifacts[index]) == 0 {
			t.Fatalf(
				"artifact %d was not streamed completely",
				index,
			)
		}
	}
}

func TestReadDurableCustodyArtifactsRejectsMutation(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)

	custodyRoot := filepath.Join(
		t.TempDir(),
		"custody",
	)

	if err := os.Mkdir(custodyRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	config := CustodyConfig{
		Receive: fixture.Config,
		RootDir: custodyRoot,
	}

	custody, err := ReceiveToDurableCustody(
		bytes.NewReader(fixture.Wire),
		fixture.Offer,
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(custody.CustodyPath, 0o600); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(
		custody.CustodyPath,
		os.O_WRONLY,
		0,
	)
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

	if err := os.Chmod(custody.CustodyPath, 0o400); err != nil {
		t.Fatal(err)
	}

	_, err = ReadDurableCustodyArtifacts(
		custody,
		config,
		func(_ string, reader io.Reader) error {
			_, err := io.Copy(io.Discard, reader)
			return err
		},
	)
	if err == nil {
		t.Fatal("mutated durable custody object was accepted")
	}
}

func TestReadDurableCustodyArtifactsRejectsWrongRoot(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)

	custodyRoot := filepath.Join(
		t.TempDir(),
		"custody",
	)

	if err := os.Mkdir(custodyRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	config := CustodyConfig{
		Receive: fixture.Config,
		RootDir: custodyRoot,
	}

	custody, err := ReceiveToDurableCustody(
		bytes.NewReader(fixture.Wire),
		fixture.Offer,
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	otherRoot := filepath.Join(
		t.TempDir(),
		"other-custody",
	)

	if err := os.Mkdir(otherRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	config.RootDir = otherRoot

	_, err = ReadDurableCustodyArtifacts(
		custody,
		config,
		func(_ string, reader io.Reader) error {
			_, err := io.Copy(io.Discard, reader)
			return err
		},
	)
	if err == nil {
		t.Fatal("custody object outside configured root was accepted")
	}
}

func TestReadDurableCustodyArtifactsRequiresCompleteHandlerConsumption(
	t *testing.T,
) {
	fixture := testGenerationReceiveFixture(t)

	custodyRoot := filepath.Join(
		t.TempDir(),
		"custody",
	)

	if err := os.Mkdir(custodyRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	config := CustodyConfig{
		Receive: fixture.Config,
		RootDir: custodyRoot,
	}

	custody, err := ReceiveToDurableCustody(
		bytes.NewReader(fixture.Wire),
		fixture.Offer,
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReadDurableCustodyArtifacts(
		custody,
		config,
		func(_ string, _ io.Reader) error {
			return nil
		},
	)
	if err == nil {
		t.Fatal("artifact handler that returned before EOF was accepted")
	}
}
