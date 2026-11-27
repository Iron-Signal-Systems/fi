// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"strings"
	"testing"
)

func TestLoadBatchSourceRegistryEnabledSources(
	t *testing.T,
) {
	transportIssuer, batchIssuer :=
		newSourceRegistryIssuers(t)

	registryPath := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registryPath,
		"iss-fs-22.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	writeSourceRegistryConfig(
		t,
		registryPath,
		"iss-fs-01.iss.local",
		transportIssuer,
		batchIssuer,
		false,
	)

	writeSourceRegistryConfig(
		t,
		registryPath,
		"app-01.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	registry, err := LoadBatchSourceRegistry(
		registryPath,
		batchIssuer,
	)
	if err != nil {
		t.Fatal(err)
	}

	got := registry.EnabledSourceIDs()

	want := []string{
		"app-01.iss.local",
		"iss-fs-22.iss.local",
	}

	if len(got) != len(want) {
		t.Fatalf(
			"EnabledSourceIDs() = %#v, want %#v",
			got,
			want,
		)
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf(
				"EnabledSourceIDs()[%d] = %q, want %q",
				index,
				got[index],
				want[index],
			)
		}
	}
}

func TestLoadBatchSourceRegistryIgnoresTransportIssuerMismatch(
	t *testing.T,
) {
	_, batchIssuer :=
		newSourceRegistryIssuers(t)

	_, otherTransportIssuer :=
		newIssuingCARelationshipCertificatesWithName(
			t,
			"Other Transport Root",
		)

	registryPath := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registryPath,
		"iss-fs-22.iss.local",
		otherTransportIssuer,
		batchIssuer,
		true,
	)

	if _, err := LoadBatchSourceRegistry(
		registryPath,
		batchIssuer,
	); err != nil {
		t.Fatalf(
			"LoadBatchSourceRegistry() error = %v",
			err,
		)
	}
}

func TestLoadBatchSourceRegistryRejectsBatchIssuerMismatch(
	t *testing.T,
) {
	transportIssuer, batchIssuer :=
		newSourceRegistryIssuers(t)

	_, otherBatchIssuer :=
		newIssuingCARelationshipCertificatesWithName(
			t,
			"Other Batch Root",
		)

	registryPath := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registryPath,
		"iss-fs-22.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	_, err := LoadBatchSourceRegistry(
		registryPath,
		otherBatchIssuer,
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"batch-signing issuing CA SHA-256",
		) {
		t.Fatalf(
			"LoadBatchSourceRegistry() error = %v",
			err,
		)
	}
}

func TestLoadSourceRegistryStillChecksTransportIssuer(
	t *testing.T,
) {
	transportIssuer, batchIssuer :=
		newSourceRegistryIssuers(t)

	_, otherTransportIssuer :=
		newIssuingCARelationshipCertificatesWithName(
			t,
			"Other Receiver Transport Root",
		)

	registryPath := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registryPath,
		"iss-fs-22.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	_, err := LoadSourceRegistry(
		registryPath,
		otherTransportIssuer,
		batchIssuer,
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"transport issuing CA SHA-256",
		) {
		t.Fatalf(
			"LoadSourceRegistry() error = %v",
			err,
		)
	}
}
