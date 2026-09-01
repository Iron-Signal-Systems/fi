// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"encoding/binary"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

func TestFinalPathBufferLengthAcceptsBoundedLength(t *testing.T) {
	got, err := finalPathBufferLength(512)
	if err != nil {
		t.Fatal(err)
	}
	if got != 513 {
		t.Fatalf("size = %d, want 513", got)
	}

	got, err = finalPathBufferLength(maximumFinalPathUTF16Units - 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != maximumFinalPathUTF16Units {
		t.Fatalf("size = %d, want %d", got, maximumFinalPathUTF16Units)
	}
}

func TestFinalPathBufferLengthRejectsCeiling(t *testing.T) {
	if _, err := finalPathBufferLength(maximumFinalPathUTF16Units); err == nil {
		t.Fatal("expected final-path allocation ceiling rejection")
	}
}

func TestInterruptedRecoveryEnabledByDefault(t *testing.T) {
	if !shouldRecoverInterrupted(context.Background()) {
		t.Fatal("standalone USN operation unexpectedly suppressed restart recovery")
	}
}

func TestWithoutInterruptedRecovery(t *testing.T) {
	ctx := WithoutInterruptedRecovery(context.Background())
	if shouldRecoverInterrupted(ctx) {
		t.Fatal("nested USN operation did not suppress restart recovery")
	}
}

func TestReobservationOperationOutcomeCompleteForExpectedStates(t *testing.T) {
	result := ReobservationBatch{
		Reobservations: []ChangeReobservation{
			{Status: ReobservationObserved},
			{Status: ReobservationOutsideGovernedRoot},
			{Status: ReobservationUnavailable},
		},
	}
	outcome, reason := reobservationOperationOutcome(context.Background(), result)
	if outcome != records.OperationComplete || reason != "" {
		t.Fatalf("got %q %q", outcome, reason)
	}
}

func TestReobservationOperationOutcomePartialOnCollectionError(t *testing.T) {
	result := ReobservationBatch{
		Reobservations: []ChangeReobservation{{Status: ReobservationError}},
	}
	outcome, reason := reobservationOperationOutcome(context.Background(), result)
	if outcome != records.OperationPartial || reason != "OneOrMoreReobservationsFailed" {
		t.Fatalf("got %q %q", outcome, reason)
	}
}

func TestReobservationOperationOutcomeInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, reason := reobservationOperationOutcome(ctx, ReobservationBatch{})
	if outcome != records.OperationInterrupted || reason != "ContextCanceled" {
		t.Fatalf("got %q %q", outcome, reason)
	}
}

func TestDistinctReobservationCandidatesDeduplicatesObject(t *testing.T) {
	identity := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: "283510",
		SequenceNumber:      "19",
	}
	changes := []records.USNChangeObservation{
		{FileIdentity: identity, USN: "100"},
		{FileIdentity: identity, USN: "200"},
		{FileIdentity: identity, USN: "200"},
		{
			FileIdentity: records.NTFSObjectIdentity{
				MethodVersion:       ntfs.IdentityMethodVersion,
				FileReferenceNumber: "144588",
				SequenceNumber:      "8",
			},
			USN: "300",
		},
	}

	got := distinctReobservationCandidates(changes)
	if len(got) != 2 {
		t.Fatalf("candidates = %d, want 2", len(got))
	}
	if got[0].identity != identity {
		t.Fatalf("first identity = %+v", got[0].identity)
	}
	if len(got[0].triggerUSNs) != 2 || got[0].triggerUSNs[0] != "100" || got[0].triggerUSNs[1] != "200" {
		t.Fatalf("first trigger USNs = %v", got[0].triggerUSNs)
	}
}

func TestReobserveBatchObservesObjectInsideGovernedRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")
	if err := os.WriteFile(target, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}

	original, err := ntfs.CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}

	batch := records.USNReadBatch{
		ScopeID: "scope-test",
		Records: []records.USNChangeObservation{
			{FileIdentity: original.ObjectIdentity, USN: "100"},
			{FileIdentity: original.ObjectIdentity, USN: "200"},
		},
	}
	result := ReobserveBatch(context.Background(), root, batch)
	if len(result.Reobservations) != 1 {
		t.Fatalf("reobservations = %d", len(result.Reobservations))
	}
	got := result.Reobservations[0]
	if got.Status != ReobservationObserved {
		t.Fatalf("status = %q, error = %q", got.Status, got.Error)
	}
	if got.Observation == nil || got.Observation.ObjectIdentity != original.ObjectIdentity {
		t.Fatalf("observation = %+v", got.Observation)
	}
	if got.Observation.CollectionEntryMethod != ntfs.CollectionEntryNTFSFileID {
		t.Fatalf("entry method = %q", got.Observation.CollectionEntryMethod)
	}
}

func TestReobserveBatchMarksObjectOutsideGovernedRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "governed")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	outsideObservation, err := ntfs.CollectPath(context.Background(), "scope-wide", base, outside)
	if err != nil {
		t.Fatal(err)
	}

	batch := records.USNReadBatch{
		ScopeID: "scope-test",
		Records: []records.USNChangeObservation{
			{FileIdentity: outsideObservation.ObjectIdentity, USN: "100"},
		},
	}
	result := ReobserveBatch(context.Background(), root, batch)
	if len(result.Reobservations) != 1 {
		t.Fatalf("reobservations = %d, want 1", len(result.Reobservations))
	}
	got := result.Reobservations[0]
	if got.Status != ReobservationOutsideGovernedRoot || got.ReasonCode != "OutsideGovernedRoot" {
		t.Fatalf("result = %+v", got)
	}
	if got.Observation != nil {
		t.Fatalf("outside object unexpectedly produced observation: %+v", got.Observation)
	}
}

func TestReobserveBatchMarksDeletedObjectUnavailable(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "deleted.txt")
	if err := os.WriteFile(target, []byte("delete me"), 0o600); err != nil {
		t.Fatal(err)
	}

	original, err := ntfs.CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	batch := records.USNReadBatch{
		ScopeID: "scope-test",
		Records: []records.USNChangeObservation{
			{FileIdentity: original.ObjectIdentity, USN: "100"},
		},
	}
	result := ReobserveBatch(context.Background(), root, batch)
	if len(result.Reobservations) != 1 {
		t.Fatalf("reobservations = %d", len(result.Reobservations))
	}
	got := result.Reobservations[0]
	if got.Status != ReobservationUnavailable {
		t.Fatalf("status = %q, reason = %q, error = %q", got.Status, got.ReasonCode, got.Error)
	}
	if got.ReasonCode != "ObjectUnavailableAfterUSN" {
		t.Fatalf("reason = %q", got.ReasonCode)
	}
}

func TestReobserveBatchDoesNotObserveReplacementAtDeletedPath(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "recreated.txt")

	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	original, err := ntfs.CollectPath(
		context.Background(),
		"scope-test",
		root,
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	replacement, err := ntfs.CollectPath(
		context.Background(),
		"scope-test",
		root,
		target,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ObjectIdentity == original.ObjectIdentity {
		t.Fatal("recreated pathname unexpectedly retained the deleted object's NTFS identity")
	}

	batch := records.USNReadBatch{
		ScopeID: "scope-test",
		Records: []records.USNChangeObservation{
			{FileIdentity: original.ObjectIdentity, USN: "100"},
		},
	}

	result := ReobserveBatch(context.Background(), root, batch)
	if len(result.Reobservations) != 1 {
		t.Fatalf("reobservations = %d, want 1", len(result.Reobservations))
	}

	got := result.Reobservations[0]
	if got.Status != ReobservationUnavailable {
		t.Fatalf(
			"status = %q, reason = %q, error = %q",
			got.Status,
			got.ReasonCode,
			got.Error,
		)
	}
	if got.ReasonCode != "ObjectUnavailableAfterUSN" {
		t.Fatalf("reason = %q", got.ReasonCode)
	}
	if got.Observation != nil {
		t.Fatalf(
			"stale USN identity unexpectedly observed recreated pathname object: %+v",
			got.Observation,
		)
	}
}
func TestIdentityFromReference(t *testing.T) {
	reference := uint64(144588) | uint64(8)<<48
	identity := identityFromReference(reference)
	if identity.FileReferenceNumber != "144588" || identity.SequenceNumber != "8" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestReasonNames(t *testing.T) {
	got := reasonNames(0x00000100 | 0x00000800 | 0x80000000)
	want := []string{"Close", "FileCreate", "SecurityChange"}
	if len(got) != len(want) {
		t.Fatalf("reasonNames = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reasonNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseReadBufferV2(t *testing.T) {
	nameUnits := utf16.Encode([]rune("file.txt"))
	nameBytes := make([]byte, len(nameUnits)*2)
	for i, unit := range nameUnits {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], unit)
	}

	recordLength := usnV2HeaderSize + len(nameBytes)
	if rem := recordLength % 8; rem != 0 {
		recordLength += 8 - rem
	}
	buffer := make([]byte, 8+recordLength)
	binary.LittleEndian.PutUint64(buffer[:8], 200)
	record := buffer[8:]
	binary.LittleEndian.PutUint32(record[0:4], uint32(recordLength))
	binary.LittleEndian.PutUint16(record[4:6], 2)
	binary.LittleEndian.PutUint16(record[6:8], 0)
	binary.LittleEndian.PutUint64(record[8:16], uint64(144588)|uint64(8)<<48)
	binary.LittleEndian.PutUint64(record[16:24], uint64(103695)|uint64(8)<<48)
	binary.LittleEndian.PutUint64(record[24:32], 150)
	binary.LittleEndian.PutUint64(record[32:40], 134000000000000000)
	binary.LittleEndian.PutUint32(record[40:44], 0x00000100)
	binary.LittleEndian.PutUint32(record[48:52], 7)
	binary.LittleEndian.PutUint32(record[52:56], 32)
	binary.LittleEndian.PutUint16(record[56:58], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint16(record[58:60], usnV2HeaderSize)
	copy(record[usnV2HeaderSize:], nameBytes)

	next, changes, err := parseReadBuffer(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if next != 200 || len(changes) != 1 {
		t.Fatalf("next=%d changes=%d", next, len(changes))
	}
	if changes[0].FileIdentity.FileReferenceNumber != "144588" ||
		changes[0].FileIdentity.SequenceNumber != "8" ||
		changes[0].ParentIdentity.FileReferenceNumber != "103695" {
		t.Fatalf("unexpected identities: %+v", changes[0])
	}
}

func TestParseReadBufferRejectsUnsupportedVersion(t *testing.T) {
	buffer := make([]byte, 8+usnV2HeaderSize)
	binary.LittleEndian.PutUint64(buffer[:8], 200)
	binary.LittleEndian.PutUint32(buffer[8:12], usnV2HeaderSize)
	binary.LittleEndian.PutUint16(buffer[12:14], 3)
	if _, _, err := parseReadBuffer(buffer); err == nil {
		t.Fatal("expected unsupported-version error")
	}
}
