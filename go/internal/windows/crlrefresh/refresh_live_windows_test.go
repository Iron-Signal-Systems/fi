// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package crlrefresh

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportcrl"
)

func TestLiveRefreshCandidateEvaluationReadOnly(
	t *testing.T,
) {
	if strings.TrimSpace(
		os.Getenv(
			"FI_LIVE_CRL_REFRESH",
		),
	) != "1" {
		t.Skip(
			"set FI_LIVE_CRL_REFRESH=1 to run live read-only CRL refresh candidate evaluation",
		)
	}

	domainDNS :=
		strings.TrimSpace(
			os.Getenv(
				"FI_LIVE_CRL_REFRESH_DOMAIN",
			),
		)

	dependencies :=
		defaultRefreshDependencies()

	prepared, err :=
		prepareRefresh(
			Options{
				At:              time.Now().UTC(),
				DomainDNS:       domainDNS,
				TrustConfigPath: DefaultTrustConfigPath,
			},
			dependencies,
		)
	if err != nil {
		t.Fatal(err)
	}

	current, err :=
		receivertrust.LoadCRL(
			prepared.trust.TransportCRLPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	decision, err :=
		transportcrl.AssessReplacement(
			current,
			prepared.candidate,
		)
	if err != nil {
		t.Fatal(err)
	}

	digest :=
		sha256.Sum256(
			prepared.candidate.Raw,
		)

	t.Logf(
		"source=%q candidate_sha256=%s current_number=%q candidate_number=%q this_update=%s next_update=%s would_activate=%t reason=%q",
		prepared.source,
		hex.EncodeToString(
			digest[:],
		),
		crlNumber(
			current,
		),
		crlNumber(
			prepared.candidate,
		),
		prepared.candidate.ThisUpdate.UTC().Format(
			time.RFC3339,
		),
		prepared.candidate.NextUpdate.UTC().Format(
			time.RFC3339,
		),
		decision.Activate,
		decision.Reason,
	)
}
