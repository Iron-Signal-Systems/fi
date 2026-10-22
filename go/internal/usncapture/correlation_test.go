// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func corrID(reference, sequence string) records.NTFSObjectIdentity {
	return records.NTFSObjectIdentity{
		MethodVersion: "NTFSFileIdInfo", FileReferenceNumber: reference, SequenceNumber: sequence,
	}
}

func corrChange(file, parent records.NTFSObjectIdentity, usn string) records.USNChangeObservation {
	return records.USNChangeObservation{
		MajorVersion: "2", MinorVersion: "0", FileIdentity: file, ParentIdentity: parent,
		USN: usn, Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		ReasonRaw: "256", ReasonNames: []string{"FileCreate"}, SourceInfoRaw: "0",
		SecurityID: "0", FileAttributesRaw: "32",
		FileNameUTF16LEBase64URL: base64.RawURLEncoding.EncodeToString([]byte{'x', 0}),
	}
}

func sampleCorrelationBatch() records.USNReadBatch {
	root := corrID("10", "1")
	dir := corrID("20", "1")
	file := corrID("30", "1")
	moved := corrID("40", "1")
	hardlink := corrID("50", "1")
	outside := corrID("90", "1")
	b := exampleBatch(exampleAnchor(), 100, 200)
	b.Records = []records.USNChangeObservation{
		corrChange(dir, root, "101"),
		corrChange(file, dir, "105"),
		corrChange(moved, root, "110"),
		corrChange(moved, outside, "115"),
		corrChange(hardlink, root, "118"),
		corrChange(hardlink, outside, "119"),
		corrChange(corrID("20", "2"), outside, "130"), // reused MFT ref, new sequence
		corrChange(corrID("70", "1"), corrID("20", "2"), "150"),
		corrChange(outside, corrID("80", "1"), "160"),
	}
	return b
}

func TestCorrelationPreservesMovesHardlinksAndSourceHistory(t *testing.T) {
	s, _ := exampleStore(t, DefaultMaxPendingBytes)
	batch := sampleCorrelationBatch()
	if err := s.Append(batch); err != nil {
		t.Fatal(err)
	}
	correlation, ok, err := s.CorrelateNext(corrID("10", "1"))
	if err != nil || !ok {
		t.Fatalf("correlate next: %t %v", ok, err)
	}
	if len(correlation.Work) != 7 || len(batch.Records) != 9 {
		t.Fatalf("distinct objects must not delete source changes: %d %d", len(correlation.Work), len(batch.Records))
	}
	byRef := map[string]CorrelatedObject{}
	for _, w := range correlation.Work {
		byRef[w.FileIdentity.FileReferenceNumber+":"+w.FileIdentity.SequenceNumber] = w
	}
	if byRef["20:1"].ScopeHint != ScopeHintDirectParent || byRef["30:1"].ScopeHint != ScopeHintPossibleChain {
		t.Fatalf("lost direct parent or ancestry hint: %+v", byRef)
	}
	if byRef["40:1"].ScopeHint != ScopeHintDirectParent || !reflect.DeepEqual(byRef["40:1"].TriggerUSNs, []string{"110", "115"}) || !reflect.DeepEqual(byRef["40:1"].DirectUSNs, []string{"110"}) {
		t.Fatalf("move history must retain both sides: %+v", byRef["40:1"])
	}
	if byRef["50:1"].ScopeHint != ScopeHintDirectParent || len(byRef["50:1"].ParentIdentities) != 2 || len(byRef["50:1"].DirectUSNs) != 1 {
		t.Fatalf("hardlink parents lost: %+v", byRef["50:1"])
	}
	if byRef["70:1"].ScopeHint != ScopeHintUnresolved || byRef["20:2"].ScopeHint != ScopeHintUnresolved {
		t.Fatalf("MFT record reuse incorrectly inherited old scope: %+v", byRef)
	}
	if s.ProcessingCursor().NextUSN != "100" || s.CaptureCursor().NextUSN != "200" {
		t.Fatal("correlation must never update processing cursor")
	}
	seg, found, err := s.Next()
	if err != nil || !found || len(seg.Batch.Records) != 9 {
		t.Fatalf("source batch changed: %v %v", found, err)
	}
}

func TestCorrelationIdempotentAcrossRestartAndWrongRootFailClosed(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := s.Append(sampleCorrelationBatch()); err != nil {
		t.Fatal(err)
	}
	root := corrID("10", "1")
	first, ok, err := s.CorrelateNext(root)
	if !ok || err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	second, ok, err := recovered.CorrelateNext(root)
	if !ok || err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("replay changed derived work: %v %v", ok, err)
	}
	_, _, err = recovered.CorrelateNext(corrID("11", "1"))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("reused cache across distinct governed roots: %v", err)
	}
}

func TestCorrelationTamperFailsClosed(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := s.Append(sampleCorrelationBatch()); err != nil {
		t.Fatal(err)
	}
	root := corrID("10", "1")
	_, ok, err := s.CorrelateNext(root)
	if !ok || err != nil {
		t.Fatal(err)
	}
	seg, _, _ := s.Next()
	path := filepath.Join(dir, correlationFileName(seg))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corr Correlation
	if err := json.Unmarshal(original, &corr); err != nil {
		t.Fatal(err)
	}
	corr.Work[0].ScopeHint = ScopeHintUnresolved
	broken, _ := json.Marshal(corr)
	if err := os.WriteFile(path, broken, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.CorrelateNext(root)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("undetected corrupted correlation artifact: %v", err)
	}
	// Even a recomputed checksum must fail the deterministic source comparison.
	checksum, err := correlationDigest(corr)
	if err != nil {
		t.Fatal(err)
	}
	corr.SHA256 = checksum
	resigned, _ := json.Marshal(corr)
	if err := os.WriteFile(path, resigned, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.CorrelateNext(root)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted tampered cache re-signed by attacker: %v", err)
	}
}

func TestCorrelationCycleRemainsUnresolved(t *testing.T) {
	s, _ := exampleStore(t, DefaultMaxPendingBytes)
	b := exampleBatch(exampleAnchor(), 100, 200)
	a, c := corrID("100", "1"), corrID("101", "1")
	b.Records = []records.USNChangeObservation{corrChange(a, c, "111"), corrChange(c, a, "112")}
	if err := s.Append(b); err != nil {
		t.Fatal(err)
	}
	corr, ok, err := s.CorrelateNext(corrID("10", "1"))
	if err != nil || !ok {
		t.Fatal(err)
	}
	if len(corr.Work) != 2 || corr.Work[0].ScopeHint != ScopeHintUnresolved || corr.Work[1].ScopeHint != ScopeHintUnresolved {
		t.Fatalf("cycle was incorrectly promoted to governed: %+v", corr.Work)
	}
}

func TestCorrelationCannotAdvanceProcessingCheckpoint(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := s.Append(sampleCorrelationBatch()); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.CorrelateNext(corrID("10", "1"))
	if err != nil {
		t.Fatal(err)
	}
	cursorRaw, err := os.ReadFile(filepath.Join(dir, processedName))
	if err != nil {
		t.Fatal(err)
	}
	var cursor Cursor
	if err := json.Unmarshal(cursorRaw, &cursor); err != nil || cursor.NextUSN != "100" {
		t.Fatalf("correlator moved authoritative FI cursor: %+v %v", cursor, err)
	}
}

func TestCorrelationSharesDiskBudgetWithRawUSNCache(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := s.Append(sampleCorrelationBatch()); err != nil {
		t.Fatal(err)
	}
	seg, ok, err := s.Next()
	if err != nil || !ok {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, seg.Name))
	if err != nil {
		t.Fatal(err)
	}
	// This limited queue has enough room for the original source records,
	// but not the derived correlation artifact.
	limited, err := Open(dir, uint64(info.Size()+1))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = limited.CorrelateNext(corrID("10", "1"))
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("correlation exceeded queue disk budget: %v", err)
	}
	if limited.CaptureCursor().NextUSN != "200" || limited.ProcessingCursor().NextUSN != "100" {
		t.Fatal("queue exhaustion changed checkpoints")
	}
	if _, err := os.Stat(filepath.Join(dir, correlationFileName(seg))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial correlation published after budget failure: %v", err)
	}
}
