// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportgeneration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerationDurableCustodyNewAndDuplicate(
	t *testing.T,
) {
	fixture :=
		testGenerationReceiveFixture(
			t,
		)

	custodyRoot :=
		filepath.Join(
			t.TempDir(),
			"custody",
		)

	if err :=
		os.Mkdir(
			custodyRoot,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	config :=
		CustodyConfig{
			Receive: fixture.Config,

			RootDir: custodyRoot,
		}

	first, err :=
		ReceiveToDurableCustody(
			bytes.NewReader(
				fixture.Wire,
			),
			fixture.Offer,
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	if first.Disposition !=
		CustodyDispositionNew {
		t.Fatalf(
			"first generation custody disposition = %q, want NEW",
			first.Disposition,
		)
	}

	if first.Transfer !=
		fixture.Result {
		t.Fatal(
			"generation custody changed validated transfer facts",
		)
	}

	if first.CustodyBytes !=
		fixture.Result.TransferBytes ||
		first.CustodySHA256 !=
			fixture.Result.TransferSHA256 {
		t.Fatal(
			"generation custody exact transfer identity changed",
		)
	}

	info, err :=
		os.Lstat(
			first.CustodyPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !info.Mode().IsRegular() {
		t.Fatal(
			"generation custody object is not a regular file",
		)
	}

	if info.Mode().Perm() !=
		0o400 {
		t.Fatalf(
			"generation custody mode = %04o, want 0400",
			info.Mode().Perm(),
		)
	}

	if filepath.Ext(
		first.CustodyPath,
	) != ".figt" {
		t.Fatalf(
			"generation custody extension = %q, want .figt",
			filepath.Ext(
				first.CustodyPath,
			),
		)
	}

	custodyBytes, err :=
		os.ReadFile(
			first.CustodyPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		custodyBytes,
		fixture.Wire,
	) {
		t.Fatal(
			"durable generation custody bytes differ from exact received transfer",
		)
	}

	second, err :=
		ReceiveToDurableCustody(
			bytes.NewReader(
				fixture.Wire,
			),
			fixture.Offer,
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	if second.Disposition !=
		CustodyDispositionDuplicate {
		t.Fatalf(
			"second generation custody disposition = %q, want DUPLICATE",
			second.Disposition,
		)
	}

	if second.CustodyPath !=
		first.CustodyPath {
		t.Fatal(
			"duplicate generation mapped to different custody identity",
		)
	}

	if second.Transfer !=
		first.Transfer {
		t.Fatal(
			"duplicate generation custody changed transfer facts",
		)
	}
}

func TestGenerationDurableCustodyRejectsInvalidTransferWithoutPublication(
	t *testing.T,
) {
	fixture :=
		testGenerationReceiveFixture(
			t,
		)

	custodyRoot :=
		filepath.Join(
			t.TempDir(),
			"custody",
		)

	if err :=
		os.Mkdir(
			custodyRoot,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	wire :=
		append(
			[]byte(nil),
			fixture.Wire...,
		)

	wire[len(wire)-1] ^=
		0xff

	_,
		err :=
		ReceiveToDurableCustody(
			bytes.NewReader(
				wire,
			),
			fixture.Offer,
			CustodyConfig{
				Receive: fixture.Config,

				RootDir: custodyRoot,
			},
		)

	if err == nil {
		t.Fatal(
			"invalid generation transfer reached durable custody",
		)
	}

	entries, err :=
		os.ReadDir(
			custodyRoot,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 0 {
		t.Fatalf(
			"invalid generation left %d custody artifacts, want 0",
			len(entries),
		)
	}
}

func TestGenerationDurableCustodyConflictFailsClosed(
	t *testing.T,
) {
	fixture :=
		testGenerationReceiveFixture(
			t,
		)

	custodyRoot :=
		filepath.Join(
			t.TempDir(),
			"custody",
		)

	if err :=
		os.Mkdir(
			custodyRoot,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	config :=
		CustodyConfig{
			Receive: fixture.Config,

			RootDir: custodyRoot,
		}

	first, err :=
		ReceiveToDurableCustody(
			bytes.NewReader(
				fixture.Wire,
			),
			fixture.Offer,
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		os.Chmod(
			first.CustodyPath,
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	file, err :=
		os.OpenFile(
			first.CustodyPath,
			os.O_WRONLY,
			0,
		)
	if err != nil {
		t.Fatal(err)
	}

	if _,
		err :=
		file.WriteAt(
			[]byte{
				0xff,
			},
			0,
		); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err :=
		file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err :=
		file.Close(); err != nil {
		t.Fatal(err)
	}

	if err :=
		os.Chmod(
			first.CustodyPath,
			0o400,
		); err != nil {
		t.Fatal(err)
	}

	_,
		err =
		ReceiveToDurableCustody(
			bytes.NewReader(
				fixture.Wire,
			),
			fixture.Offer,
			config,
		)

	if !errors.Is(
		err,
		ErrGenerationCustodyConflict,
	) {
		t.Fatalf(
			"generation custody conflict error = %v, want ErrGenerationCustodyConflict",
			err,
		)
	}
}

func TestGenerationCustodyIdentitySeparatesSourcesAndGenerations(
	t *testing.T,
) {
	first :=
		generationCustodyObjectName(
			"source-a",
			"generation-a",
		)

	second :=
		generationCustodyObjectName(
			"source-a",
			"generation-b",
		)

	third :=
		generationCustodyObjectName(
			"source-b",
			"generation-a",
		)

	if first ==
		second ||
		first ==
			third ||
		second ==
			third {
		t.Fatal(
			"generation custody identity collided across source/generation values",
		)
	}
}
