// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestM1GenerationTrustResolverRejectsNil(t *testing.T) {
	config := GenerationLoadConfig{
		CustodyRoot:       t.TempDir(),
		MaxCanonicalBytes: 1 << 20,
		MaxEncodedBytes:   1 << 20,
		MaxManifestBytes:  1 << 20,
		RecordedRoot:      t.TempDir(),
		SourceID:          "iss-fs-2019.iss.local",
	}

	_, err := loadRecordedGenerationWithTrust(
		config,
		"test-generation",
		nil,
	)

	if err == nil {
		t.Fatal("nil trust resolver accepted")
	}
}

func TestM1GenerationTrustResolverSourceIdentity(t *testing.T) {
	if os.Getenv("FI_M1_NAMESPACE_READ_TEST") != "1" {
		t.Skip("verified namespaced fixture not requested")
	}

	const sourceID = "iss-fs-2019.iss.local"

	recordedRoot := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-receipts-20261012",
		"namespaced",
	)

	receipts, err := DiscoverRecordedReceiptsForSource(
		recordedRoot,
		sourceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 104 {
		t.Fatalf("receipt count=%d, want 104", len(receipts))
	}

	config := GenerationLoadConfig{
		CustodyRoot:       t.TempDir(),
		MaxCanonicalBytes: 1 << 20,
		MaxEncodedBytes:   1 << 20,
		MaxManifestBytes:  1 << 20,
		RecordedRoot:      recordedRoot,
		SourceNamespaces:  true,
		SourceID:          sourceID,
	}

	generationID := receipts[0].GenerationID
	sentinel := errors.New("isolated trust resolver invoked")
	calls := 0

	_, err = loadRecordedGenerationWithTrust(
		config,
		generationID,
		func(requested string) (generationTrustBundle, error) {
			calls++

			if requested != sourceID {
				t.Fatalf(
					"resolver requested source=%q, want %q",
					requested,
					sourceID,
				)
			}

			return generationTrustBundle{}, sentinel
		},
	)

	if calls != 1 || !errors.Is(err, sentinel) {
		t.Fatalf(
			"trust resolver calls=%d error=%v",
			calls,
			err,
		)
	}

	_, err = loadRecordedGenerationWithTrust(
		config,
		generationID,
		func(requested string) (generationTrustBundle, error) {
			return generationTrustBundle{
				Source: transporttrust.SourceAuthorization{
					SourceID: "wrong-source.local",
				},
			}, nil
		},
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"does not match requested source",
		) {
		t.Fatalf(
			"cross-source trust identity accepted: %v",
			err,
		)
	}

	_, err = loadRecordedGenerationWithTrust(
		config,
		generationID,
		func(requested string) (generationTrustBundle, error) {
			return generationTrustBundle{
				Source: transporttrust.SourceAuthorization{
					SourceID: sourceID,
				},
			}, nil
		},
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"trust material is incomplete",
		) {
		t.Fatalf(
			"incomplete trust material accepted: %v",
			err,
		)
	}

	t.Log("PASS: Namespaced receipt resolves exact source identity")
	t.Log("PASS: Cross-source trust identity rejected")
	t.Log("PASS: Incomplete trust material rejected")
}
