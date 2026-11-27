// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

func TestLiveTransportIssuerDirectRootDiscovery(
	t *testing.T,
) {
	if os.Getenv(
		"FI_LIVE_PKI_DIRECT_ROOT_ISSUER",
	) != "1" {
		t.Skip(
			"set FI_LIVE_PKI_DIRECT_ROOT_ISSUER=1 to run direct-root issuer discovery",
		)
	}

	const issuerSHA256 = "83e8a85841edf4a4359419a3452b5c8309f528208d4d8dd86bee8da7e0d2efc0"

	const rootSHA256 = "83e8a85841edf4a4359419a3452b5c8309f528208d4d8dd86bee8da7e0d2efc0"

	certificate, store, err := loadLocalMachineTransportIssuer(
		issuerSHA256,
		rootSHA256,
	)
	if err != nil {
		t.Fatal(err)
	}

	if store != certstore.StoreRoot {
		t.Fatalf(
			"direct-root issuer resolved from LocalMachine\\%s want LocalMachine\\%s",
			store,
			certstore.StoreRoot,
		)
	}

	observed := certificateRawSHA256(
		certificate,
	)

	if !strings.EqualFold(
		observed,
		issuerSHA256,
	) {
		t.Fatalf(
			"issuer SHA256=%s want=%s",
			observed,
			issuerSHA256,
		)
	}

	t.Logf(
		"issuer_sha256=%s root_sha256=%s store=LocalMachine\\%s subject=%q",
		issuerSHA256,
		rootSHA256,
		store,
		certificate.Subject.String(),
	)
}
