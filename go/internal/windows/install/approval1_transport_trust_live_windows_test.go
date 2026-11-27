// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"strings"
	"testing"
)

func TestLiveApproval1TransportTrustDerivation(
	t *testing.T,
) {
	if os.Getenv(
		"FI_LIVE_PKI_TRUST_DERIVATION",
	) != "1" {
		t.Skip(
			"set FI_LIVE_PKI_TRUST_DERIVATION=1 to run live transport trust derivation",
		)
	}

	certificateSHA256 := strings.TrimSpace(
		os.Getenv(
			"FI_LIVE_PKI_TRANSPORT_SHA256",
		),
	)

	if !validSHA256Hex(
		certificateSHA256,
	) {
		t.Fatal(
			"FI_LIVE_PKI_TRANSPORT_SHA256 must contain exactly 64 hexadecimal characters",
		)
	}

	material, err :=
		deriveApproval1TransportTrustMaterial(
			certificateSHA256,
		)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(
		"transport_sha256=%s issuer_sha256=%s root_sha256=%s crl_source=%q crl_destination=%q",
		material.TransportCertificateSHA256,
		material.IssuerCertificateSHA256,
		material.RootCertificateSHA256,
		material.CRLDistributionPoint,
		material.CRLDestinationPath,
	)
}
