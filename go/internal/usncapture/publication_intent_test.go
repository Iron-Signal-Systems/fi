// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The source queue can advance while processing is stopped on an ambiguous
// publication. A restart MUST NOT return the same interval to a new writer.
func TestInterruptedScopedPublicationBlocksReplayButNotCapture(t *testing.T) {
	store, dir := exampleStore(t, DefaultMaxPendingBytes)
	for start := uint64(100); start < 300; start += 100 {
		if err := store.Append(exampleBatch(exampleAnchor(), start, start+100)); err != nil {
			t.Fatal(err)
		}
	}
	first, ok, err := store.Next()
	if err != nil || !ok {
		t.Fatalf("missing first segment: %v", err)
	}
	if err := store.BeginScopedPublication(first); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after writing an unknown amount of FI sender spool
	// data, before the durable publication receipt was written.
	restarted, err := Open(dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := restarted.Next(); ok || !errors.Is(err, ErrAmbiguousPublication) {
		t.Fatalf("ambiguous source interval was republished: pending=%t err=%v", ok, err)
	}
	if err := restarted.BeginScopedPublication(first); !errors.Is(err, ErrAmbiguousPublication) {
		t.Fatalf("duplicate publication intent accepted: %v", err)
	}
	if err := restarted.Append(exampleBatch(exampleAnchor(), 300, 400)); err != nil {
		t.Fatalf("raw capture must remain independent of processing: %v", err)
	}
	if restarted.CaptureCursor().NextUSN != "400" ||
		restarted.ProcessingCursor().NextUSN != "100" {
		t.Fatal("processing changed while publication outcome was ambiguous")
	}
	if _, err := os.Stat(filepath.Join(dir, first.Name)); err != nil {
		t.Fatal("original raw source segment lost", err)
	}
}

// A syntactically plausible receipt without a pre-publication intent must
// never be permitted to advance the processed cursor.
func TestScopedPublicationCommitRequiresPriorDurableIntent(t *testing.T) {
	store, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := store.Append(exampleBatch(exampleAnchor(), 100, 200)); err != nil {
		t.Fatal(err)
	}
	seg, ok, err := store.Next()
	if err != nil || !ok {
		t.Fatal("missing captured source", err)
	}
	if err := store.CommitProcessed(seg, testScopedSpoolProof()); !errors.Is(err, ErrConflict) {
		t.Fatalf("processed without pre-publication intent: %v", err)
	}
	if err := store.BeginScopedPublication(seg); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitProcessed(seg, testScopedSpoolProof()); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.ProcessingCursor().NextUSN != "200" {
		t.Fatal("durably completed publication did not survive restart")
	}
	if _, ok, err := restarted.Next(); err != nil || ok {
		t.Fatalf("completed source was replayed: pending=%t err=%v", ok, err)
	}
}

func TestCorruptScopedPublicationIntentFailsClosed(t *testing.T) {
	store, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := store.Append(exampleBatch(exampleAnchor(), 100, 200)); err != nil {
		t.Fatal(err)
	}
	seg, ok, err := store.Next()
	if err != nil || !ok {
		t.Fatal("missing source", err)
	}
	if err := store.BeginScopedPublication(seg); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(publicationIntentPath(dir, seg), []byte(`{"version":"forged"}`)); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := restarted.Next(); ok || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt intent permitted replay: pending=%t err=%v", ok, err)
	}
}

func TestReceiptWithoutDurableIntentCannotRecoverProcessedCursor(t *testing.T) {
	store, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := store.Append(exampleBatch(exampleAnchor(), 100, 200)); err != nil {
		t.Fatal(err)
	}
	seg, ok, err := store.Next()
	if err != nil || !ok {
		t.Fatal("missing source", err)
	}
	// An attacker or interrupted legacy publisher cannot write a plausible
	// receipt and skip the required pre-publication ordering barrier.
	receipt := map[string]string{
		"version": SchemaVersion,
		"source_batch_sha256": seg.SHA256,
		"spool_proof": testScopedSpoolProof().Receipt(),
		"start_usn": seg.Batch.StartUSN,
		"next_usn": seg.Batch.NextUSN,
	}
	if err := atomicWrite(filepath.Join(dir, "receipt-"+seg.Name), mustJSON(receipt)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, DefaultMaxPendingBytes); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("receipt without prior publication intent advanced processed cursor: %v", err)
	}
}

func TestReclaimRejectsInvalidSpoolReceiptAndRetainsSource(t *testing.T) {
	store, dir := exampleStore(t, DefaultMaxPendingBytes)
	if err := store.Append(exampleBatch(exampleAnchor(), 100, 200)); err != nil {
		t.Fatal(err)
	}
	seg, ok, err := store.Next()
	if err != nil || !ok {
		t.Fatal("missing source", err)
	}
	if err := store.BeginScopedPublication(seg); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitProcessed(seg, testScopedSpoolProof()); err != nil {
		t.Fatal(err)
	}
	receipt := map[string]string{
		"version": SchemaVersion,
		"source_batch_sha256": seg.SHA256,
		"spool_proof": "unverified source",
		"start_usn": seg.Batch.StartUSN,
		"next_usn": seg.Batch.NextUSN,
	}
	if err := atomicWrite(filepath.Join(dir, "receipt-"+seg.Name), mustJSON(receipt)); err != nil {
		t.Fatal(err)
	}
	if reclaimed, _, err := store.ReclaimAcknowledged(); reclaimed != 0 || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("malformed publication receipt reclaimed original source: count=%d err=%v", reclaimed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, seg.Name)); err != nil {
		t.Fatalf("original captured source lost after invalid reclaim: %v", err)
	}
}

func TestUnverifiedScopedPublicationCapabilityIsRejected(t *testing.T) {
	store, _ := exampleStore(t, DefaultMaxPendingBytes)
	if err := store.Append(exampleBatch(exampleAnchor(), 100, 200)); err != nil { t.Fatal(err) }
	seg, ok, err := store.Next()
	if err != nil || !ok { t.Fatal("missing captured source", err) }
	if err := store.BeginScopedPublication(seg); err != nil { t.Fatal(err) }
	if err := store.CommitProcessed(seg, ScopedPublicationProof{}); err == nil {
		t.Fatal("zero-value publication capability advanced processed cursor")
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("processed source advanced without verified local publication")
	}
}
