// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

func TestTransportIssuerCertificateStoreDirectRoot(
	t *testing.T,
) {
	t.Parallel()

	digest := strings.Repeat(
		"A",
		64,
	)

	store, err := transportIssuerCertificateStore(
		digest,
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}

	if store != certstore.StoreRoot {
		t.Fatalf(
			"direct-root issuer store=%q want=%q",
			store,
			certstore.StoreRoot,
		)
	}
}

func TestTransportIssuerCertificateStoreIntermediate(
	t *testing.T,
) {
	t.Parallel()

	store, err := transportIssuerCertificateStore(
		strings.Repeat(
			"A",
			64,
		),
		strings.Repeat(
			"B",
			64,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	if store != certstore.StoreCA {
		t.Fatalf(
			"intermediate issuer store=%q want=%q",
			store,
			certstore.StoreCA,
		)
	}
}

func TestTransportIssuerCertificateStoreRejectsInvalidIssuer(
	t *testing.T,
) {
	t.Parallel()

	_, err := transportIssuerCertificateStore(
		"not-a-sha256",
		strings.Repeat(
			"B",
			64,
		),
	)

	if err == nil {
		t.Fatal(
			"invalid issuer SHA-256 was unexpectedly accepted",
		)
	}
}

func TestTransportIssuerCertificateStoreRejectsInvalidRoot(
	t *testing.T,
) {
	t.Parallel()

	_, err := transportIssuerCertificateStore(
		strings.Repeat(
			"A",
			64,
		),
		"not-a-sha256",
	)

	if err == nil {
		t.Fatal(
			"invalid root SHA-256 was unexpectedly accepted",
		)
	}
}
