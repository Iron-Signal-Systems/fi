// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
)

func TestLiveTransportPKIDiscoveryDirectRoot(
	t *testing.T,
) {
	if os.Getenv(
		"FI_LIVE_PKI_DISCOVERY_DIRECT_ROOT",
	) != "1" {
		t.Skip(
			"set FI_LIVE_PKI_DISCOVERY_DIRECT_ROOT=1 to run live direct-root PKI discovery",
		)
	}

	const transportCertificateSHA256 = "07ef9a4cb8940f831c723f37868097b69a093f6df9dd8e79d79063876eac4b6d"

	const batchCertificateSHA256 = "f7765ea365387f631507d4049d6fc8b9a2e055430fcd22300948d1ca668fb206"

	const expectedRootSHA256 = "83e8a85841edf4a4359419a3452b5c8309f528208d4d8dd86bee8da7e0d2efc0"

	before := Discover()

	if strings.TrimSpace(
		before.AD.DomainController,
	) == "" ||
		strings.EqualFold(
			before.AD.DomainController,
			notKnown,
		) {
		t.Fatal(
			"authoritative writable domain controller discovery is unavailable",
		)
	}

	trustMaterial, err :=
		deriveApproval1TransportTrustMaterial(
			transportCertificateSHA256,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.EqualFold(
		trustMaterial.IssuerCertificateSHA256,
		trustMaterial.RootCertificateSHA256,
	) {
		t.Fatalf(
			"live environment is not direct-root: issuer=%s root=%s",
			trustMaterial.IssuerCertificateSHA256,
			trustMaterial.RootCertificateSHA256,
		)
	}

	if !strings.EqualFold(
		trustMaterial.RootCertificateSHA256,
		expectedRootSHA256,
	) {
		t.Fatalf(
			"root SHA256=%s want=%s",
			trustMaterial.RootCertificateSHA256,
			expectedRootSHA256,
		)
	}

	session, err := openLDAPSession(
		before.AD.DomainController,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()

	crlMaterial, err := acquireApproval1TransportCRL(
		session,
		trustMaterial,
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}

	tempRoot := t.TempDir()

	crlPath := filepath.Join(
		tempRoot,
		"fi-transport-ca.crl.pem",
	)

	crlPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "X509 CRL",
			Bytes: crlMaterial.DER,
		},
	)
	if len(crlPEM) == 0 {
		t.Fatal(
			"encode temporary transport CRL PEM returned no data",
		)
	}

	if err := os.WriteFile(
		crlPath,
		crlPEM,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	persistedCRL, err := receivertrust.LoadCRL(
		crlPath,
	)
	if err != nil {
		t.Fatalf(
			"receiver-side CRL loader rejected canonical temporary CRL: %v",
			err,
		)
	}

	if !bytes.Equal(
		persistedCRL.Raw,
		crlMaterial.DER,
	) {
		t.Fatal(
			"receiver-side CRL loader did not reproduce the validated Approval 1 DER",
		)
	}

	configPath := filepath.Join(
		tempRoot,
		"fi-transport-trust.conf",
	)

	configText := fmt.Sprintf(
		"version_id: %s\n\n"+
			"trust.root_cert_sha256 = %s\n"+
			"trust.transport_cert_sha256 = %s\n"+
			"trust.transport_issuer_sha256 = %s\n"+
			"trust.batch_signing_cert_sha256 = %s\n"+
			"trust.transport_crl = %s\n",
		config.TransportTrustVersion1,
		trustMaterial.RootCertificateSHA256,
		transportCertificateSHA256,
		trustMaterial.IssuerCertificateSHA256,
		batchCertificateSHA256,
		crlPath,
	)

	if err := os.WriteFile(
		configPath,
		[]byte(configText),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	trustConfig, err := config.LoadTransportTrust(
		configPath,
	)
	if err != nil {
		t.Fatalf(
			"temporary transport-trust configuration was rejected: %v",
			err,
		)
	}

	report := Report{
		Trust: TransportTrustState{
			BatchSigningCertificateSHA256: trustConfig.BatchSigningCertificateSHA256,
			Path:                          configPath,
			Presence:                      presencePresent,
			RootCertificateSHA256:         trustConfig.RootCertificateSHA256,
			TransportCertificateSHA256:    trustConfig.TransportCertificateSHA256,
			TransportCRLPath:              trustConfig.TransportCRLPath,
			TransportIssuerSHA256:         trustConfig.TransportIssuerSHA256,
			VersionID:                     trustConfig.VersionID,
		},
	}

	discoverPKI(
		&report,
		trustConfig,
	)

	required := map[string]bool{
		"transport root certificate":        false,
		"transport issuer certificate":      false,
		"source transport signing identity": false,
		"batch signing identity":            false,
		"transport CRL":                     false,
	}

	for _, state := range report.PKI {
		if _, wanted := required[state.Name]; !wanted {
			continue
		}

		if state.State != checkPass {
			t.Fatalf(
				"%s state=%s detail=%s",
				state.Name,
				state.State,
				state.Detail,
			)
		}

		required[state.Name] = true

		t.Logf(
			"%s: PASS: %s",
			state.Name,
			state.Detail,
		)

		if state.Name ==
			"transport issuer certificate" &&
			!strings.Contains(
				state.Detail,
				`LocalMachine\ROOT`,
			) {
			t.Fatalf(
				"direct-root issuer discovery detail=%q; expected LocalMachine\\ROOT",
				state.Detail,
			)
		}
	}

	for name, found := range required {
		if !found {
			t.Fatalf(
				"required PKI discovery state %q was not produced",
				name,
			)
		}
	}

	if !transportPKIComplete(
		report,
	) {
		t.Fatalf(
			"transportPKIComplete rejected fully discovered direct-root trust state: %+v",
			report.PKI,
		)
	}

	t.Logf(
		"transport PKI complete: transport=%s batch=%s issuer=%s root=%s crl_sha256=%s",
		trustConfig.TransportCertificateSHA256,
		trustConfig.BatchSigningCertificateSHA256,
		trustConfig.TransportIssuerSHA256,
		trustConfig.RootCertificateSHA256,
		crlMaterial.SHA256,
	)
}
