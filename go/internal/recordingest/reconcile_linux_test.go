// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

const reconcileTestReceipt = `{"version":"fi-generation-recorded/0.1","descriptor":{"version":"fi-generation-descriptor/0.1","source_id":"iss-fs-01.iss.local","generation_id":"20260919T184530.695418700Z-ed9f36afc547f5f3","canonical_version":"fi-generation-canonical/0.1","data_encoding":"zstd","artifact_count":2,"source_bytes":33551875,"canonical_bytes":33552192,"canonical_sha256":"0480672f3e576249fc6aa2bbdfb10b280f5533d551075525182c2de35baf40ab","encoded_data_bytes":1550297,"encoded_data_sha256":"6dd5503eab9e856b5ba853384c34988796d26ec649ea5972898ea6f983520f0c"},"metadata_bytes":2839,"metadata_sha256":"92ebdc2b279759a874631ac1f4e4853c046fe5886aeb3905229a21f72d64874b","transfer_bytes":1553156,"transfer_sha256":"004b309cee0cb8b4680f94f450a96066b9ef375dffa7c5e4f826017f2e1308a9","batch_count":1,"data_bytes":33551261,"record_count":7492}
`

func TestDiscoverRecordedReceipts(t *testing.T) {
	root := t.TempDir()
	raw := []byte(reconcileTestReceipt)
	receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
	if err != nil {
		t.Fatalf("UnmarshalRecordedReceipt() error = %v", err)
	}

	name := generationrecorder.RecordedReceiptObjectName(receipt.Descriptor.SourceID, receipt.Descriptor.GenerationID)
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0o400); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	candidates, err := DiscoverRecordedReceipts(root, "")
	if err != nil {
		t.Fatalf("DiscoverRecordedReceipts() error = %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(candidates))
	}

	candidate := candidates[0]
	digest := sha256.Sum256(raw)
	if candidate.SourceID != receipt.Descriptor.SourceID ||
		candidate.GenerationID != receipt.Descriptor.GenerationID ||
		candidate.TransferSHA256 != receipt.TransferSHA256 ||
		candidate.ReceiptSHA256 != hex.EncodeToString(digest[:]) ||
		candidate.BatchCount != receipt.BatchCount ||
		candidate.DataBytes != receipt.DataBytes ||
		candidate.RecordCount != receipt.RecordCount {
		t.Fatalf("candidate = %+v, receipt = %+v", candidate, receipt)
	}
}

func TestDiscoverRecordedReceiptsSourceFilter(t *testing.T) {
	root := t.TempDir()
	raw := []byte(reconcileTestReceipt)
	receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
	if err != nil {
		t.Fatalf("UnmarshalRecordedReceipt() error = %v", err)
	}

	path := filepath.Join(root, generationrecorder.RecordedReceiptObjectName(receipt.Descriptor.SourceID, receipt.Descriptor.GenerationID))
	if err := os.WriteFile(path, raw, 0o400); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	candidates, err := DiscoverRecordedReceipts(root, "different-source")
	if err != nil {
		t.Fatalf("DiscoverRecordedReceipts() error = %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidate count = %d, want 0", len(candidates))
	}
}

func TestEvaluateExistingGeneration(t *testing.T) {
	candidate := RecordedReceiptCandidate{
		BatchCount:     1,
		DataBytes:      33551261,
		ReceiptSHA256:  "469c7223f32eea690cd21eaeab81780a2ef28a2dcbf393f949c4db016d6b96d4",
		RecordCount:    7492,
		TransferSHA256: "004b309cee0cb8b4680f94f450a96066b9ef375dffa7c5e4f826017f2e1308a9",
	}

	snapshot := existingGenerationSnapshot{
		ActualBatchCount:       1,
		ActualDataBytes:        33551261,
		ActualRecordCount:      7492,
		DeclaredBatchCount:     1,
		DeclaredDataBytes:      33551261,
		DeclaredRecordCount:    7492,
		MissingProjectionCount: 0,
		ReceiptSHA256:          candidate.ReceiptSHA256,
		TransferSHA256:         candidate.TransferSHA256,
	}

	state, detail := evaluateExistingGeneration(candidate, snapshot)
	if state != ReconcileStateAccepted || detail != "" {
		t.Fatalf("state=%q detail=%q, want Accepted with empty detail", state, detail)
	}

	snapshot.ActualRecordCount--
	state, detail = evaluateExistingGeneration(candidate, snapshot)
	if state != ReconcileStateConflict || detail == "" {
		t.Fatalf("state=%q detail=%q, want Conflict with detail", state, detail)
	}

	snapshot.ActualRecordCount++
	snapshot.MissingProjectionCount = 1
	state, detail = evaluateExistingGeneration(candidate, snapshot)
	if state != ReconcileStateConflict || detail == "" {
		t.Fatalf("state=%q detail=%q, want projection Conflict with detail", state, detail)
	}
}
