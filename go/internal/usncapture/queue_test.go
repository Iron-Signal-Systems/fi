// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func exampleAnchor() Cursor {
	return Cursor{Version: SchemaVersion, ScopeID: "root-test", JournalID: "19", VolumeIdentity: records.VolumeIdentity{MethodVersion: "ntfs-volume/1", VolumeGUID: `\\?\Volume{11111111-2222-3333-4444-555555555555}\`, VolumeSerial: "9"}, NextUSN: "100"}
}
func exampleBatch(c Cursor, start, end uint64) records.USNReadBatch {
	return records.USNReadBatch{ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"), CollectionMethod: "WindowsNTFSUSNJournalV0", ScopeID: c.ScopeID, JournalID: c.JournalID, VolumeIdentity: c.VolumeIdentity, StartUSN: strconv.FormatUint(start, 10), NextUSN: strconv.FormatUint(end, 10)}
}
func exampleStore(t *testing.T, capacity uint64) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "capture")
	if err := Initialize(dir, exampleAnchor()); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, capacity)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestSeparateCaptureAndProcessingCheckpoints(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	original := exampleBatch(exampleAnchor(), 100, 200)
	if err := s.Append(original); err != nil {
		t.Fatal(err)
	}
	if s.CaptureCursor().NextUSN != "200" || s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("capture must advance alone")
	}
	recovered, err := Open(dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	item, ok, err := recovered.Next()
	if err != nil || !ok || item.Batch.NextUSN != "200" {
		t.Fatalf("recovery: %+v %t %v", item, ok, err)
	}
	if err := recovered.CommitProcessed(item, ""); err == nil {
		t.Fatal("accepted missing spool proof")
	}
	if recovered.ProcessingCursor().NextUSN != "100" {
		t.Fatal("processed before durable FI publication")
	}
	if err := recovered.CommitProcessed(item, "verified-FI-batch-manifest:example"); err != nil {
		t.Fatal(err)
	}
	if recovered.ProcessingCursor().NextUSN != "200" {
		t.Fatal("processing checkpoint did not advance")
	}
	next, ok, err := recovered.Next()
	if err != nil || ok {
		t.Fatalf("unexpected pending after processing: %+v %v %v", next, ok, err)
	}
	if _, err := os.Stat(filepath.Join(dir, item.Name)); err != nil {
		t.Fatal("source history should remain retained", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "receipt-"+item.Name)); err != nil {
		t.Fatal("processing receipt should remain durable", err)
	}
}

func TestCrashAfterBatchPublishBeforeCaptureCursor(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	b := exampleBatch(exampleAnchor(), 100, 150)
	raw, _ := json.Marshal(b)
	digest := sha256Sum(raw)
	data, _ := json.Marshal(Envelope{Version: SchemaVersion, Batch: b, Work: DistinctWork(b), SHA256: digest})
	if err := atomicWrite(filepath.Join(dir, segmentName(100)), data); err != nil {
		t.Fatal(err)
	}
	next, err := Open(dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	if next.CaptureCursor().NextUSN != "150" {
		t.Fatal("uncommitted but durable batch not recovered")
	}
	if next.ProcessingCursor().NextUSN != "100" {
		t.Fatal("advanced processed on recovery")
	}
	if err := s.Append(b); err == nil {
		t.Fatal("stale owner was allowed to overwrite recovered batch")
	}
}
func TestRejectInterruptedOrGappedQueue(t *testing.T) {
	_, dir := exampleStore(t, DefaultMaxPendingBytes)
	cursor := exampleAnchor()
	cursor.NextUSN = "300"
	if err := atomicWrite(filepath.Join(dir, captureName), mustJSON(cursor)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, DefaultMaxPendingBytes); !errors.Is(err, ErrGap) {
		t.Fatalf("expected missing segment gap, got %v", err)
	}
}
func TestCapacityFailClosedWithoutCursorAdvance(t *testing.T) {
	s, _ := exampleStore(t, 1)
	err := s.Append(exampleBatch(exampleAnchor(), 100, 101))
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity outcome: %v", err)
	}
	if s.CaptureCursor().NextUSN != "100" {
		t.Fatal("advanced capture despite full cache")
	}
}
func TestRejectWrongJournalAndDiscontinuity(t *testing.T) {
	s, _ := exampleStore(t, DefaultMaxPendingBytes)
	b := exampleBatch(exampleAnchor(), 100, 150)
	b.JournalID = "20"
	if !errors.Is(s.Append(b), ErrConflict) {
		t.Fatal("accepted new journal identity")
	}
	b = exampleBatch(exampleAnchor(), 110, 150)
	if !errors.Is(s.Append(b), ErrConflict) {
		t.Fatal("skipped source USN span")
	}
}
func TestTamperingFailsClosed(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := s.Append(exampleBatch(exampleAnchor(), 100, 150)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, segmentName(100))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry Envelope
	if err := json.Unmarshal(b, &entry); err != nil {
		t.Fatal(err)
	}
	entry.Batch.NextUSN = "151"
	raw, _ := json.Marshal(entry)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, DefaultMaxPendingBytes); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected corruption, got %v", err)
	}
}
func TestMultiBatchReplayAndConsumerOrdering(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	for i := uint64(100); i < 400; i += 100 {
		if err := s.Append(exampleBatch(exampleAnchor(), i, i+100)); err != nil {
			t.Fatal(err)
		}
	}
	recovered, err := Open(dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(100); i < 400; i += 100 {
		seg, ok, err := recovered.Next()
		if err != nil || !ok {
			t.Fatalf("no batch %d: %v", i, err)
		}
		if seg.Batch.StartUSN != strconv.FormatUint(i, 10) {
			t.Fatalf("wrong order %s", seg.Batch.StartUSN)
		}
		if err := recovered.CommitProcessed(seg, "spool-verified"); err != nil {
			t.Fatal(err)
		}
	}
	if recovered.CaptureCursor().NextUSN != "400" || recovered.ProcessingCursor().NextUSN != "400" {
		t.Fatal("unexpected independent cursors")
	}
}
func TestInvalidAnchorAndSourceContent(t *testing.T) {
	s, _ := exampleStore(t, DefaultMaxPendingBytes)
	bad := exampleBatch(exampleAnchor(), 100, 150)
	bad.Records = []records.USNChangeObservation{{}}
	if err := s.Append(bad); err == nil {
		t.Fatal("accepted malformed journal facts")
	}
}
func sha256Sum(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func TestDistinctWorkRetainsEveryChangeAndAllParents(t *testing.T) {
	a := records.NTFSObjectIdentity{MethodVersion: "ref", FileReferenceNumber: "11", SequenceNumber: "1"}
	b := records.NTFSObjectIdentity{MethodVersion: "ref", FileReferenceNumber: "22", SequenceNumber: "1"}
	p1 := records.NTFSObjectIdentity{MethodVersion: "ref", FileReferenceNumber: "2", SequenceNumber: "1"}
	p2 := records.NTFSObjectIdentity{MethodVersion: "ref", FileReferenceNumber: "3", SequenceNumber: "1"}
	batch := exampleBatch(exampleAnchor(), 100, 200)
	batch.Records = []records.USNChangeObservation{{FileIdentity: a, ParentIdentity: p1, USN: "111"}, {FileIdentity: b, ParentIdentity: p1, USN: "112"}, {FileIdentity: a, ParentIdentity: p2, USN: "113"}, {FileIdentity: a, ParentIdentity: p2, USN: "114"}}
	objects := DistinctWork(batch)
	if len(objects) != 2 || len(objects[0].TriggerUSNs) != 3 || len(objects[0].ParentIdentities) != 2 || objects[0].Scope != ScopeUnknown {
		t.Fatalf("lost change or parent identity: %+v", objects)
	}
	if len(batch.Records) != 4 {
		t.Fatal("distinct work modified original source history")
	}
}

func TestReclaimOnlyAfterAcknowledgement(t *testing.T) {
	s, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := s.Append(exampleBatch(exampleAnchor(), 100, 200)); err != nil {
		t.Fatal(err)
	}
	count, _, err := s.ReclaimAcknowledged()
	if err != nil || count != 0 {
		t.Fatal("reclaimed an unpublished source batch", count, err)
	}
	seg, ok, err := s.Next()
	if err != nil || !ok {
		t.Fatal(err)
	}
	if err := s.CommitProcessed(seg, "verified-spool-generation"); err != nil {
		t.Fatal(err)
	}
	count, bytes, err := s.ReclaimAcknowledged()
	if err != nil || count != 1 || bytes == 0 {
		t.Fatalf("acknowledged reclaim %d %d %v", count, bytes, err)
	}
	if _, err := os.Stat(filepath.Join(dir, seg.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("acknowledged batch not removed")
	}
	if _, err := Open(dir, DefaultMaxPendingBytes); err != nil {
		t.Fatalf("restart following reclaim must work: %v", err)
	}
}
