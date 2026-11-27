// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestLoadSourceRegistryMultipleSources(
	t *testing.T,
) {
	transportIssuer, batchIssuer :=
		newSourceRegistryIssuers(t)

	registry := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-22.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-01.iss.local",
		transportIssuer,
		batchIssuer,
		false,
	)

	snapshot, err := LoadSourceRegistry(
		registry,
		transportIssuer,
		batchIssuer,
	)
	if err != nil {
		t.Fatalf(
			"LoadSourceRegistry() error = %v",
			err,
		)
	}

	if snapshot.Len() != 2 {
		t.Fatalf(
			"Len() = %d, want 2",
			snapshot.Len(),
		)
	}

	authorizations := snapshot.Authorizations()

	if len(authorizations) != 2 {
		t.Fatalf(
			"len(Authorizations()) = %d, want 2",
			len(authorizations),
		)
	}

	if authorizations[0].SourceID !=
		"iss-test-01.iss.local" {
		t.Fatalf(
			"authorization[0].SourceID = %q",
			authorizations[0].SourceID,
		)
	}

	if authorizations[0].Enabled {
		t.Fatal(
			"disabled source was not preserved as disabled",
		)
	}

	if authorizations[1].SourceID !=
		"iss-test-22.iss.local" {
		t.Fatalf(
			"authorization[1].SourceID = %q",
			authorizations[1].SourceID,
		)
	}

	if !authorizations[1].Enabled {
		t.Fatal(
			"enabled source was not preserved as enabled",
		)
	}
}

func TestSourceRegistryAuthorizationsReturnsCopy(
	t *testing.T,
) {
	transportIssuer, batchIssuer :=
		newSourceRegistryIssuers(t)

	registry := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-01.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	snapshot, err := LoadSourceRegistry(
		registry,
		transportIssuer,
		batchIssuer,
	)
	if err != nil {
		t.Fatalf(
			"LoadSourceRegistry() error = %v",
			err,
		)
	}

	values := snapshot.Authorizations()

	values[0].SourceID = "modified.invalid"
	values[0].Enabled = false

	authorization, found :=
		snapshot.Lookup("iss-test-01.iss.local")

	if !found {
		t.Fatal(
			"Lookup() did not find original source",
		)
	}

	if authorization.SourceID !=
		"iss-test-01.iss.local" {
		t.Fatalf(
			"Lookup().SourceID = %q",
			authorization.SourceID,
		)
	}

	if !authorization.Enabled {
		t.Fatal(
			"caller mutation changed registry snapshot",
		)
	}
}

func TestSourceRegistryLookupCaseInsensitive(
	t *testing.T,
) {
	transportIssuer, batchIssuer :=
		newSourceRegistryIssuers(t)

	registry := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-22.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	snapshot, err := LoadSourceRegistry(
		registry,
		transportIssuer,
		batchIssuer,
	)
	if err != nil {
		t.Fatalf(
			"LoadSourceRegistry() error = %v",
			err,
		)
	}

	authorization, found := snapshot.Lookup(
		strings.ToUpper(
			"iss-test-22.iss.local",
		),
	)

	if !found {
		t.Fatal(
			"case-insensitive Lookup() returned found=false",
		)
	}

	if authorization.SourceID !=
		"iss-test-22.iss.local" {
		t.Fatalf(
			"Lookup().SourceID = %q",
			authorization.SourceID,
		)
	}

	if _, found := snapshot.Lookup(
		"not-enrolled.iss.local",
	); found {
		t.Fatal(
			"Lookup() accepted unknown source",
		)
	}
}

func TestLoadSourceRegistryRejectsDuplicateTransportCertificate(
	t *testing.T,
) {
	transportIssuer, batchIssuer :=
		newSourceRegistryIssuers(t)

	registry := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-01.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	second := writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-22.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	replaceSourceRegistryFingerprint(
		t,
		second,
		sourceRegistryTextSHA256(
			"transport:iss-test-22.iss.local",
		),
		sourceRegistryTextSHA256(
			"transport:iss-test-01.iss.local",
		),
	)

	if _, err := LoadSourceRegistry(
		registry,
		transportIssuer,
		batchIssuer,
	); err == nil ||
		!strings.Contains(
			err.Error(),
			"same transport certificate",
		) {
		t.Fatalf(
			"LoadSourceRegistry() error = %v, want duplicate transport certificate rejection",
			err,
		)
	}
}

func TestLoadSourceRegistryRejectsDuplicateBatchCertificate(
	t *testing.T,
) {
	transportIssuer, batchIssuer :=
		newSourceRegistryIssuers(t)

	registry := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-01.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	second := writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-22.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	replaceSourceRegistryFingerprint(
		t,
		second,
		sourceRegistryTextSHA256(
			"batch:iss-test-22.iss.local",
		),
		sourceRegistryTextSHA256(
			"batch:iss-test-01.iss.local",
		),
	)

	if _, err := LoadSourceRegistry(
		registry,
		transportIssuer,
		batchIssuer,
	); err == nil ||
		!strings.Contains(
			err.Error(),
			"same batch-signing certificate",
		) {
		t.Fatalf(
			"LoadSourceRegistry() error = %v, want duplicate batch certificate rejection",
			err,
		)
	}
}

func TestSourceRegistryResolveTransportCertificate(
	t *testing.T,
) {
	rawOne := []byte(
		"FI test transport certificate one",
	)

	rawTwo := []byte(
		"FI test transport certificate two",
	)

	oneSHA := sha256.Sum256(rawOne)
	twoSHA := sha256.Sum256(rawTwo)

	sourceOne := transporttrust.SourceAuthorization{
		Enabled:  true,
		SourceID: "iss-test-01.iss.local",
		Transport: transporttrust.CertificateIdentity{
			CertificateSHA256: hex.EncodeToString(
				oneSHA[:],
			),
		},
	}

	sourceTwo := transporttrust.SourceAuthorization{
		Enabled:  false,
		SourceID: "iss-test-22.iss.local",
		Transport: transporttrust.CertificateIdentity{
			CertificateSHA256: hex.EncodeToString(
				twoSHA[:],
			),
		},
	}

	registry := SourceRegistry{
		authorizations: []transporttrust.SourceAuthorization{
			sourceOne,
			sourceTwo,
		},
	}

	resolved, found, err :=
		registry.ResolveTransportCertificate(
			&x509.Certificate{
				Raw: rawTwo,
			},
		)

	if err != nil {
		t.Fatalf(
			"ResolveTransportCertificate() error = %v",
			err,
		)
	}

	if !found {
		t.Fatal(
			"ResolveTransportCertificate() found = false",
		)
	}

	if resolved.SourceID != sourceTwo.SourceID {
		t.Fatalf(
			"resolved SourceID = %q, want %q",
			resolved.SourceID,
			sourceTwo.SourceID,
		)
	}

	if resolved.Enabled {
		t.Fatal(
			"disabled source was not preserved during resolution",
		)
	}

	_, found, err =
		registry.ResolveTransportCertificate(
			&x509.Certificate{
				Raw: []byte(
					"unknown FI transport certificate",
				),
			},
		)

	if err != nil {
		t.Fatalf(
			"unknown ResolveTransportCertificate() error = %v",
			err,
		)
	}

	if found {
		t.Fatal(
			"unknown transport certificate resolved to a source",
		)
	}
}

func TestSourceRegistryResolveTransportCertificateFailsClosedOnAmbiguity(
	t *testing.T,
) {
	raw := []byte(
		"ambiguous FI transport certificate",
	)

	sum := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(sum[:])

	registry := SourceRegistry{
		authorizations: []transporttrust.SourceAuthorization{
			{
				SourceID: "iss-test-01.iss.local",
				Transport: transporttrust.CertificateIdentity{
					CertificateSHA256: fingerprint,
				},
			},
			{
				SourceID: "iss-test-22.iss.local",
				Transport: transporttrust.CertificateIdentity{
					CertificateSHA256: fingerprint,
				},
			},
		},
	}

	_, found, err :=
		registry.ResolveTransportCertificate(
			&x509.Certificate{
				Raw: raw,
			},
		)

	if err == nil {
		t.Fatal(
			"ResolveTransportCertificate() error = nil, want ambiguity rejection",
		)
	}

	if found {
		t.Fatal(
			"ambiguous transport certificate returned found=true",
		)
	}
}

func replaceSourceRegistryFingerprint(
	t *testing.T,
	path string,
	oldValue string,
	newValue string,
) {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf(
			"os.ReadFile(%q) error = %v",
			path,
			err,
		)
	}

	updated := strings.Replace(
		string(content),
		oldValue,
		newValue,
		1,
	)

	if updated == string(content) {
		t.Fatalf(
			"fingerprint %q was not found in %q",
			oldValue,
			path,
		)
	}

	if err := os.WriteFile(
		path,
		[]byte(updated),
		0600,
	); err != nil {
		t.Fatalf(
			"os.WriteFile(%q) error = %v",
			path,
			err,
		)
	}
}
