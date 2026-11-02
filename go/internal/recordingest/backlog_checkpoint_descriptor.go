// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

const backlogCheckpointDescriptorVersion = "fi-backlog-checkpoint-descriptor/1"

// BacklogCheckpointDescriptor is an advisory, deterministic identity for one
// window of the ORIGINAL signed generation. It is not a signature, a database
// checkpoint, an accepted generation, or permission to publish partial records.
//
// A durable checkpoint must later bind this descriptor to a separately
// authenticated completion proof in a private, non-queryable staging authority.
type BacklogCheckpointDescriptor struct {
	Version              string
	SourceID             string
	GenerationID         string
	ReceiptSHA256        string
	TransferSHA256       string
	FirstBatchID         string
	LastBatchID          string
	StartBatch           int
	EndBatch             int
	StartRecord          uint64
	EndRecord            uint64
	DataBytes            uint64
	PreviousDigestSHA256 string
	DigestSHA256         string
}

// DescribeBacklogWindows binds every whole-source-batch planning window to the
// exact previously verified custody receipt and ordered batch manifests.
//
// It does not perform I/O, create persistent state, mutate PreparedGeneration,
// grant schema rights, or change the existing one-transaction SoR ingest.
func DescribeBacklogWindows(g *PreparedGeneration, limits BacklogWindowLimits) ([]BacklogCheckpointDescriptor, error) {
	windows, err := PlanBacklogWindows(g, limits)
	if err != nil {
		return nil, err
	}
	source := g.Receipt.Descriptor.SourceID
	generation := g.Receipt.Descriptor.GenerationID
	if source == "" || generation == "" {
		return nil, fmt.Errorf("FI backlog checkpoint: signed generation identity required")
	}
	for name, value := range map[string]string{
		"receipt_sha256":  g.ReceiptSHA256,
		"transfer_sha256": g.Receipt.TransferSHA256,
	} {
		if !canonicalDigest(value) {
			return nil, fmt.Errorf("FI backlog checkpoint: invalid %s", name)
		}
	}

	out := make([]BacklogCheckpointDescriptor, 0, len(windows))
	previous := strings.Repeat("0", 64) // chain genesis, not an accepted checkpoint
	for _, w := range windows {
		desc := BacklogCheckpointDescriptor{
			Version:        backlogCheckpointDescriptorVersion,
			SourceID:       source,
			GenerationID:   generation,
			ReceiptSHA256:  g.ReceiptSHA256,
			TransferSHA256: g.Receipt.TransferSHA256,
			FirstBatchID:   g.Batches[w.StartBatch].BatchID,
			LastBatchID:    g.Batches[w.EndBatch-1].BatchID,
			StartBatch:     w.StartBatch, EndBatch: w.EndBatch,
			StartRecord: w.StartRecord, EndRecord: w.EndRecord,
			DataBytes:            w.DataBytes,
			PreviousDigestSHA256: previous,
		}
		h := sha256.New()
		for _, v := range []string{
			desc.Version, desc.SourceID, desc.GenerationID,
			desc.ReceiptSHA256, desc.TransferSHA256,
			desc.FirstBatchID, desc.LastBatchID, desc.PreviousDigestSHA256,
		} {
			backlogDigestString(h, v)
		}
		for _, n := range []uint64{
			uint64(w.StartBatch), uint64(w.EndBatch),
			w.StartRecord, w.EndRecord, w.DataBytes,
		} {
			backlogDigestNumber(h, n)
		}
		for i := w.StartBatch; i < w.EndBatch; i++ {
			b := g.Batches[i]
			if !canonicalDigest(b.ManifestSHA256) || !canonicalDigest(b.Manifest.DataSHA256) {
				return nil, fmt.Errorf("FI backlog checkpoint: batch %d digest missing or malformed", i)
			}
			backlogDigestString(h, b.BatchID)
			backlogDigestString(h, b.ManifestSHA256)
			backlogDigestString(h, b.Manifest.DataSHA256)
			backlogDigestNumber(h, uint64(b.Manifest.RecordCount))
			backlogDigestNumber(h, uint64(b.Manifest.DataBytes))
		}
		desc.DigestSHA256 = hex.EncodeToString(h.Sum(nil))
		previous = desc.DigestSHA256
		out = append(out, desc)
	}
	return out, nil
}

// VerifyBacklogWindowDescriptions detects omitted, duplicated, reordered,
// changed, or cross-generation descriptions by regenerating the expected
// deterministic chain from an independently validated PreparedGeneration.
// Equality alone is NOT evidence of completed ingestion.
func VerifyBacklogWindowDescriptions(g *PreparedGeneration, limits BacklogWindowLimits, got []BacklogCheckpointDescriptor) error {
	want, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("FI backlog checkpoint: window count mismatch got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			return fmt.Errorf("FI backlog checkpoint: descriptor mismatch at window %d", i)
		}
	}
	return nil
}

func canonicalDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(v)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == v
}

func backlogDigestNumber(h hash.Hash, n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	_, _ = h.Write(b[:])
}

func backlogDigestString(h hash.Hash, s string) {
	backlogDigestNumber(h, uint64(len(s)))
	_, _ = h.Write([]byte(s))
}
