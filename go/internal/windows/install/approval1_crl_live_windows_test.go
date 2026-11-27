// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveApproval1LDAPCRLAcquisition(
	t *testing.T,
) {
	if os.Getenv(
		"FI_LIVE_PKI_LDAP_CRL",
	) != "1" {
		t.Skip(
			"set FI_LIVE_PKI_LDAP_CRL=1 to run live signed/sealed LDAP CRL acquisition",
		)
	}

	certificateSHA256 :=
		strings.TrimSpace(
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

	report := Discover()

	if strings.TrimSpace(
		report.AD.DomainController,
	) == "" ||
		strings.EqualFold(
			report.AD.DomainController,
			notKnown,
		) {
		t.Fatal(
			"authoritative writable domain controller discovery is unavailable",
		)
	}

	trust, err :=
		deriveApproval1TransportTrustMaterial(
			certificateSHA256,
		)
	if err != nil {
		t.Fatal(err)
	}

	session, err :=
		openLDAPSession(
			report.AD.DomainController,
		)
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()

	crl, err :=
		acquireApproval1TransportCRL(
			session,
			trust,
			time.Now(),
		)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(
		"crl_sha256=%s bytes=%d this_update=%s next_update=%s source=%q destination=%q",
		crl.SHA256,
		len(crl.DER),
		crl.ThisUpdate,
		crl.NextUpdate,
		crl.Source,
		crl.DestinationPath,
	)
}
