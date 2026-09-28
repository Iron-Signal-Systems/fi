// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"reflect"
	"testing"
)

func TestFindAddedMachineCNGKeyForLocator(
	t *testing.T,
) {
	t.Parallel()

	locator := cngKeyLocator{
		KeyName:      "te-FI-Transport-Client-test",
		KeySpec:      0,
		MachineKey:   true,
		ProviderName: fiPKICNGProviderName,
	}

	added := []machineCNGKeyState{
		{
			Algorithm:    "RSA",
			Flags:        0,
			KeyName:      "te-FI-Transport-Client-test",
			KeySpec:      1,
			MachineKey:   true,
			ProviderName: fiPKICNGProviderName,
		},
	}

	state, found, err :=
		findAddedMachineCNGKeyForLocator(
			locator,
			added,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !found {
		t.Fatal(
			"exact transaction key was not found in added-key state",
		)
	}

	if state.KeyName != locator.KeyName {
		t.Fatalf(
			"key name=%q want=%q",
			state.KeyName,
			locator.KeyName,
		)
	}
}

func TestFindAddedMachineCNGKeyForLocatorIgnoresLegacyKeySpecMetadata(
	t *testing.T,
) {
	t.Parallel()

	locator := cngKeyLocator{
		KeyName:      "te-FI-Transport-Client-test",
		KeySpec:      0,
		MachineKey:   true,
		ProviderName: fiPKICNGProviderName,
	}

	added := []machineCNGKeyState{
		{
			Algorithm:    "RSA",
			Flags:        0,
			KeyName:      locator.KeyName,
			KeySpec:      1,
			MachineKey:   true,
			ProviderName: locator.ProviderName,
		},
	}

	_, found, err :=
		findAddedMachineCNGKeyForLocator(
			locator,
			added,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !found {
		t.Fatal(
			"same provider/key-name machine key was rejected because legacy KeySpec metadata differed",
		)
	}
}

func TestFindAddedMachineCNGKeyForLocatorRejectsWrongKey(
	t *testing.T,
) {
	t.Parallel()

	locator := cngKeyLocator{
		KeyName:      "wanted-key",
		KeySpec:      0,
		MachineKey:   true,
		ProviderName: fiPKICNGProviderName,
	}

	added := []machineCNGKeyState{
		{
			Algorithm:    "RSA",
			Flags:        0,
			KeyName:      "other-key",
			KeySpec:      1,
			MachineKey:   true,
			ProviderName: fiPKICNGProviderName,
		},
	}

	_, found, err :=
		findAddedMachineCNGKeyForLocator(
			locator,
			added,
		)
	if err != nil {
		t.Fatal(err)
	}

	if found {
		t.Fatal(
			"unrelated CNG key unexpectedly established transaction ownership",
		)
	}
}

func TestMachineCNGKeyStateDifference(
	t *testing.T,
) {
	t.Parallel()

	keyA := machineCNGKeyState{
		Algorithm:    "RSA",
		Flags:        0,
		KeyName:      "key-a",
		KeySpec:      1,
		MachineKey:   true,
		ProviderName: fiPKICNGProviderName,
	}

	keyB := machineCNGKeyState{
		Algorithm:    "RSA",
		Flags:        0,
		KeyName:      "key-b",
		KeySpec:      2,
		MachineKey:   true,
		ProviderName: fiPKICNGProviderName,
	}

	keyC := machineCNGKeyState{
		Algorithm:    "RSA",
		Flags:        0,
		KeyName:      "key-c",
		KeySpec:      1,
		MachineKey:   true,
		ProviderName: fiPKICNGProviderName,
	}

	got := machineCNGKeyStateDifference(
		[]machineCNGKeyState{
			keyA,
			keyB,
		},
		[]machineCNGKeyState{
			keyA,
			keyB,
			keyC,
		},
	)

	want := []machineCNGKeyState{
		keyC,
	}

	if !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf(
			"added keys=%+v want=%+v",
			got,
			want,
		)
	}
}

func TestMachineCNGKeyStateDifferenceUsesPersistentKeyIdentity(
	t *testing.T,
) {
	t.Parallel()

	before := machineCNGKeyState{
		Algorithm:    "RSA",
		Flags:        0,
		KeyName:      "existing-key",
		KeySpec:      0,
		MachineKey:   true,
		ProviderName: fiPKICNGProviderName,
	}

	after := before
	after.KeySpec = 1
	after.Flags = 7

	got := machineCNGKeyStateDifference(
		[]machineCNGKeyState{
			before,
		},
		[]machineCNGKeyState{
			after,
		},
	)

	if len(got) != 0 {
		t.Fatalf(
			"existing provider/key-name identity was incorrectly classified as new because metadata changed: %+v",
			got,
		)
	}
}
