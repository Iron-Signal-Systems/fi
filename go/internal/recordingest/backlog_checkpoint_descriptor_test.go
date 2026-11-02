// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func signedBacklogCheckpointFixture() *PreparedGeneration {
	g := backlogWindowFixture([]int{8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192}, 12<<20)
	g.Receipt.Descriptor.SourceID = "fi-checkpoint-test.iss.local"
	g.Receipt.Descriptor.GenerationID = "20261101T110000.000000000Z-test"
	g.ReceiptSHA256 = strings.Repeat("a", 64)
	g.Receipt.TransferSHA256 = strings.Repeat("b", 64)
	for i := range g.Batches {
		g.Batches[i].ManifestSHA256 = fmt.Sprintf("%064x", i+1)
		g.Batches[i].Manifest.DataSHA256 = fmt.Sprintf("%064x", i+1001)
	}
	return g
}

func TestBacklogCheckpointDescriptorsBindOriginalSignedReceiptAndManifestSequence(t *testing.T) {
	g := signedBacklogCheckpointFixture()
	limits := BacklogWindowLimits{MaxRecords: 32768, MaxDataBytes: 128 << 20}
	beforeReceipt := g.Receipt
	beforeBatches := append([]PreparedBatch(nil), g.Batches...)
	got, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("windows=%d want 3", len(got))
	}
	if got[0].StartRecord != 0 || got[0].EndRecord != 32768 || got[1].StartRecord != 32768 || got[2].EndRecord != 73728 {
		t.Fatalf("bad ranges: %+v", got)
	}
	if got[1].PreviousDigestSHA256 != got[0].DigestSHA256 || got[2].PreviousDigestSHA256 != got[1].DigestSHA256 {
		t.Fatal("broken descriptor chain")
	}
	if got[0].ReceiptSHA256 != g.ReceiptSHA256 || got[0].GenerationID != g.Receipt.Descriptor.GenerationID {
		t.Fatal("lost original signed receipt identity")
	}
	if err := VerifyBacklogWindowDescriptions(g, limits, got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeReceipt, g.Receipt) || !reflect.DeepEqual(beforeBatches, g.Batches) {
		t.Fatal("describing windows modified the original signed generation")
	}
}

func TestBacklogCheckpointDescriptorsRejectMissingReorderedOrChangedWindows(t *testing.T) {
	g := signedBacklogCheckpointFixture()
	limits := BacklogWindowLimits{MaxRecords: 32768, MaxDataBytes: 128 << 20}
	want, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]BacklogCheckpointDescriptor) []BacklogCheckpointDescriptor{
		"missing": func(in []BacklogCheckpointDescriptor) []BacklogCheckpointDescriptor { return in[:len(in)-1] },
		"reordered": func(in []BacklogCheckpointDescriptor) []BacklogCheckpointDescriptor {
			in[0], in[1] = in[1], in[0]
			return in
		},
		"changed-record-offset": func(in []BacklogCheckpointDescriptor) []BacklogCheckpointDescriptor { in[1].StartRecord++; return in },
		"changed-digest": func(in []BacklogCheckpointDescriptor) []BacklogCheckpointDescriptor {
			in[0].DigestSHA256 = strings.Repeat("f", 64)
			return in
		},
		"changed-receipt": func(in []BacklogCheckpointDescriptor) []BacklogCheckpointDescriptor {
			in[1].ReceiptSHA256 = strings.Repeat("c", 64)
			return in
		},
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			testCopy := append([]BacklogCheckpointDescriptor(nil), want...)
			if err := VerifyBacklogWindowDescriptions(g, limits, modify(testCopy)); err == nil {
				t.Fatal("invalid descriptor chain accepted")
			}
		})
	}
}

func TestBacklogCheckpointDescriptorsRejectTamperedSourceManifest(t *testing.T) {
	g := signedBacklogCheckpointFixture()
	limits := BacklogWindowLimits{MaxRecords: 32768, MaxDataBytes: 128 << 20}
	baseline, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		t.Fatal(err)
	}
	g.Batches[2].ManifestSHA256 = strings.Repeat("d", 64)
	if err := VerifyBacklogWindowDescriptions(g, limits, baseline); err == nil {
		t.Fatal("changed source manifest digest was accepted")
	}
	g = signedBacklogCheckpointFixture()
	g.Batches[4].Manifest.DataSHA256 = strings.Repeat("e", 64)
	if err := VerifyBacklogWindowDescriptions(g, limits, baseline); err == nil {
		t.Fatal("changed source data digest was accepted")
	}
	g = signedBacklogCheckpointFixture()
	g.Receipt.TransferSHA256 = strings.Repeat("f", 64)
	if err := VerifyBacklogWindowDescriptions(g, limits, baseline); err == nil {
		t.Fatal("changed transfer digest was accepted")
	}
}

func TestBacklogCheckpointDescriptorsFailClosed(t *testing.T) {
	g := signedBacklogCheckpointFixture()
	limits := BacklogWindowLimits{MaxRecords: 32768, MaxDataBytes: 128 << 20}
	g.ReceiptSHA256 = "NOT SHA256"
	if _, err := DescribeBacklogWindows(g, limits); err == nil {
		t.Fatal("invalid receipt hash was accepted")
	}
	g = signedBacklogCheckpointFixture()
	g.Batches[0].ManifestSHA256 = ""
	if _, err := DescribeBacklogWindows(g, limits); err == nil {
		t.Fatal("missing manifest hash was accepted")
	}
	g = signedBacklogCheckpointFixture()
	g.Receipt.Descriptor.GenerationID = ""
	if _, err := DescribeBacklogWindows(g, limits); err == nil {
		t.Fatal("empty signed generation identity was accepted")
	}
}
