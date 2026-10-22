// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Test fixture writes the canonical format independently of the production
// streaming implementation to catch ordering, sizes, and framing mistakes.
func expectedFrozenCanonicalFacts(t *testing.T, dir string) CanonicalGenerationFacts {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	var buf bytes.Buffer
	buf.WriteString("FI-GENERATION-CANONICAL-V1\x00")
	if err := binary.Write(&buf, binary.BigEndian, uint64(len(names))); err != nil {
		t.Fatal(err)
	}
	var sourceBytes uint64
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(name))); err != nil {
			t.Fatal(err)
		}
		buf.WriteString(name)
		for offset := 0; offset < len(raw); offset += 1024 * 1024 {
			end := offset + 1024*1024
			if end > len(raw) {
				end = len(raw)
			}
			if err := binary.Write(&buf, binary.BigEndian, uint32(end-offset)); err != nil {
				t.Fatal(err)
			}
			buf.Write(raw[offset:end])
		}
		if err := binary.Write(&buf, binary.BigEndian, uint32(0)); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(&buf, binary.BigEndian, uint64(len(raw))); err != nil {
			t.Fatal(err)
		}
		sourceBytes += uint64(len(raw))
	}
	sum := sha256.Sum256(buf.Bytes())
	return CanonicalGenerationFacts{
		GenerationID: "m5a-test", ArtifactCount: uint64(len(names)),
		SourceBytes: sourceBytes, CanonicalBytes: uint64(buf.Len()),
		CanonicalSHA256: hex.EncodeToString(sum[:]),
	}
}

func frozenCanonicalFixture(t *testing.T) (*Store, SourceManifestLedger, string, CanonicalGenerationFacts) {
	t.Helper()
	store, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	raw := freezeTestSpool(t, dir)
	ledger, err := store.RecordSourceManifestLedger(seg, corr, dir)
	if err != nil {
		t.Fatal(err)
	}
	return store, ledger, raw, expectedFrozenCanonicalFacts(t, raw)
}

func TestM5CFrozenSourceMatchesCanonicalDescriptorWithoutCommitting(t *testing.T) {
	store, ledger, raw, facts := frozenCanonicalFixture(t)
	proof, err := VerifyFrozenSourceCanonical(ledger, raw, facts)
	if err != nil {
		t.Fatal(err)
	}
	if proof.SourceManifestLedgerSHA256 != ledger.SHA256 || proof.CanonicalSHA256 != facts.CanonicalSHA256 ||
		proof.SourceBytes != facts.SourceBytes || proof.CanonicalBytes != facts.CanonicalBytes ||
		proof.GenerationID != facts.GenerationID {
		t.Fatalf("wrong canonical source proof: %+v", proof)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("read-only canonical check advanced processing")
	}
}

func TestM5CFrozenSourceRejectsWrongDescriptorAndGeneration(t *testing.T) {
	_, ledger, raw, facts := frozenCanonicalFixture(t)
	altered := facts
	altered.CanonicalSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := VerifyFrozenSourceCanonical(ledger, raw, altered); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong canonical digest accepted: %v", err)
	}
	altered = facts
	altered.ArtifactCount++
	if _, err := VerifyFrozenSourceCanonical(ledger, raw, altered); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong file count accepted: %v", err)
	}
	altered = facts
	altered.GenerationID = "other"
	if _, err := VerifyFrozenSourceCanonical(ledger, raw, altered); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong generation identity accepted: %v", err)
	}
}

func TestM5CFrozenSourceRejectsRemovedAndMutatedOriginals(t *testing.T) {
	_, ledger, raw, facts := frozenCanonicalFixture(t)
	manifest := filepath.Join(raw, ledger.Manifests[0].Name)
	if err := os.WriteFile(manifest, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFrozenSourceCanonical(ledger, raw, facts); err == nil {
		t.Fatal("tampered source manifest accepted")
	}
	if err := os.RemoveAll(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFrozenSourceCanonical(ledger, raw, facts); err == nil {
		t.Fatal("absent frozen source accepted")
	}
}

func TestM5CFrozenSourceRejectsAddedFilesAndRewrittenLedger(t *testing.T) {
	_, ledger, raw, facts := frozenCanonicalFixture(t)
	tampered := ledger
	tampered.SpoolProof = "unrelated-proof"
	if _, err := VerifyFrozenSourceCanonical(tampered, raw, facts); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered ledger accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(raw, "unknown"), []byte("surplus"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFrozenSourceCanonical(ledger, raw, facts); !errors.Is(err, ErrConflict) {
		t.Fatalf("surplus artifact accepted: %v", err)
	}
}

func TestM5CFrozenSourceRejectsSymbolicLinkDirectory(t *testing.T) {
	_, ledger, raw, facts := frozenCanonicalFixture(t)
	link := filepath.Join(t.TempDir(), "generation-m5a-test")
	if err := os.Symlink(raw, link); err != nil {
		t.Skip(err)
	}
	if _, err := VerifyFrozenSourceCanonical(ledger, link, facts); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("linked frozen dir accepted: %v", err)
	}
}
