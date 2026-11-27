//go:build freebsd && fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// This constructs a GENUINELY SIGNED isolated transport generation using
// the existing FreeBSD receiver/custody fixture. C1 must parse the original
// immutable transfer, original recorded receipt, manifests and JSONL as its
// own signed bootstrap source, and reject tampering. No real FI host or DB.
package recordingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func TestC1OriginalSignedManifestReaderUsesReceiverCustody(t *testing.T) {
	root := t.TempDir()
	source := "c1-signed-fixture.iss.local"
	for _, name := range []string{
		"custody", "recorded", "ready",
		filepath.Join("recorded", "sources", source),
	} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	signed := m1WriteSignedGeneration(t, root, source)
	cfg := c1NativeBCustodyConfig{
		CustodyRoot: filepath.Join(root, "custody"),
		RecordedRoot: filepath.Join(root, "recorded"),
		SourceNamespaces: true,
		MaxCanonicalBytes: 64 << 20,
		MaxEncodedBytes: 64 << 20,
		MaxManifestBytes: 1 << 20,
	}
	lookups := 0
	trust := func(requested string) (generationTrustBundle, error) {
		lookups++
		if requested != source {
			return generationTrustBundle{}, fmt.Errorf("foreign source %q", requested)
		}
		return signed.Trust, nil
	}
	original, err := c1StreamOriginalSignedManifestPlanWithTrust(
		context.Background(), source, signed.GenerationID, cfg, trust)
	if err != nil {
		t.Fatalf("C1 original signed receiver custody preflight: %v", err)
	}
	rawReceipt, err := os.ReadFile(signed.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rawReceipt)
	if lookups != 1 ||
		original.Receipt.Descriptor.SourceID != signed.SourceID ||
		original.Receipt.Descriptor.GenerationID != signed.GenerationID ||
		original.ReceiptSHA256 != hex.EncodeToString(digest[:]) ||
		original.Receipt.RecordCount != 1 ||
		original.Receipt.BatchCount != 1 ||
		len(original.Batches) != 1 ||
		original.Batches[0].Manifest.RecordCount != 1 ||
		original.Batches[0].Manifest.DataBytes <= 0 ||
		original.Batches[0].ManifestSHA256 == "" {
		t.Fatalf("C1 original signed manifest drift: %#v (trust lookup=%d)", original, lookups)
	}
	if _, err := c1StreamOriginalSignedManifestPlanWithTrust(
		context.Background(), source, signed.GenerationID, cfg, nil); err == nil {
		t.Fatal("C1 accepted unavailable original receiver trust")
	}
	if _, err := c1StreamOriginalSignedManifestPlanWithTrust(
		context.Background(), "wrong-source.iss.local", signed.GenerationID, cfg, trust); err == nil {
		t.Fatal("C1 accepted wrong original source receipt")
	}
	// Compromise the on-disk signed transfer while keeping its file mode 0400:
	// independent authentication must reject the original source, not retry
	// with mutable manifests or produce signed SQL staging metadata.
	custody := filepath.Join(cfg.CustodyRoot,
		transportgeneration.DurableCustodyObjectName(source, signed.GenerationID))
	if err := os.Chmod(custody, 0600); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(custody)
	if err != nil || len(bytes) < 64 {
		t.Fatalf("C1 fixture custody unavailable: %v size=%d", err, len(bytes))
	}
	bytes[len(bytes)-1] ^= 0xff
	if err := os.WriteFile(custody, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(custody, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = c1StreamOriginalSignedManifestPlanWithTrust(
		context.Background(), source, signed.GenerationID, cfg, trust); err == nil {
		t.Fatal("C1 original signed custody tampering produced a valid SQL manifest")
	}
	t.Log("PASS: genuinely signed receiver generation, original receipt, manifest and JSONL validated; tampering rejected")
}
