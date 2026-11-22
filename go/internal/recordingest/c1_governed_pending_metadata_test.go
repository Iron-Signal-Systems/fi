//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

func TestC1GovernedPendingMetadataRejectsUntrustedStartBeforeSQL(t *testing.T) {
	for _, f := range []c1handoff.Frame{
		{},
		{Kind: c1handoff.Drain, SourceID: "src", GenerationID: "gen", ReceiptSHA256: strings.Repeat("a", 64)},
		{Kind: c1handoff.Start, SourceID: "src", GenerationID: "gen", ReceiptSHA256: "invalid", Sequence: 1},
	} {
		if err := StageC1SignedPendingMetadata(context.Background(), "", f, c1NativeBCustodyConfig{}); err == nil {
			t.Fatalf("pending metadata SQL bootstrap admitted untrusted frame: %+v", f)
		}
	}
	if err := StageC1SignedPendingMetadata(nil, "", c1handoff.Frame{}, c1NativeBCustodyConfig{}); err == nil {
		t.Fatal("C1 pending admitted nil context")
	}
}

func TestC1GovernedPendingSignedLedgerRejectsArbitrarySchema(t *testing.T) {
	original := &PreparedGeneration{
		ReceiptSHA256: strings.Repeat("a", 64),
		Batches: []PreparedBatch{{BatchID: "batch-0001"}},
	}
	for _, name := range []string{"fi", "public", "pg_catalog", "fi_c1_pending;DROP SCHEMA fi"} {
		if _, err := c1StageOriginalLedgerTx(context.Background(),
			&c1PendingCopyCaptureTx{}, original, name); err == nil {
			t.Fatalf("C1 pending signed metadata used arbitrary SQL namespace %q", name)
		}
	}
}
