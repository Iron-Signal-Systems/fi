// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// CanonicalGenerationFacts are the canonical fields of an independently
// authenticated FI sealed-generation descriptor. The caller MUST establish
// signature validity and that the sealed payload matches that descriptor.
// Passing arbitrary facts cannot authenticate a generation.
type CanonicalGenerationFacts struct {
	GenerationID    string
	ArtifactCount   uint64
	SourceBytes     uint64
	CanonicalBytes  uint64
	CanonicalSHA256 string
}

// FrozenSourceCanonicalProof states that a still-present frozen raw generation
// matches the M5B source ledger and the supplied canonical descriptor fields.
// It is an observation, not a durable sender receipt or processing-cursor
// authorization. It does not decompress or authenticate the sealed payload.
type FrozenSourceCanonicalProof struct {
	GenerationID               string
	SourceManifestLedgerSHA256 string
	ArtifactCount              uint64
	SourceBytes                uint64
	CanonicalBytes             uint64
	CanonicalSHA256            string
}

const (
	frozenCanonicalMagic      = "FI-GENERATION-CANONICAL-V1\x00"
	frozenCanonicalChunkBytes = 1024 * 1024
)

// VerifyFrozenSourceCanonical compares the full frozen directory's canonical
// bytes against the generation descriptor and checks each ledger source
// manifest and its data against the original verified hashes. It only reads.
//
// IMPORTANT: Call this while raw custody still exists. A successful result is
// NOT proof that the compressed payload actually decompresses to these bytes,
// or that the descriptor's signature was valid. It must NOT commit a cursor.
func VerifyFrozenSourceCanonical(
	ledger SourceManifestLedger,
	frozenDir string,
	expected CanonicalGenerationFacts,
) (FrozenSourceCanonicalProof, error) {
	if ledger.Version != sourceManifestLedgerVersion ||
		ledger.SHA256 == "" || ledger.SHA256 != hashLedger(ledger) ||
		ledger.SpoolProof == "" || len(ledger.Manifests) == 0 {
		return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: invalid source ledger", ErrCorrupt)
	}
	if !filepath.IsAbs(frozenDir) || expected.GenerationID == "" ||
		strings.ContainsAny(expected.GenerationID, "/\\\x00\r\n") ||
		filepath.Base(filepath.Clean(frozenDir)) != "generation-"+expected.GenerationID {
		return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: raw generation path/identity mismatch", ErrConflict)
	}
	if ledger.CustodyKind != PublicationCustodyActive && ledger.CustodyKind != PublicationCustodyFrozenRaw {
		return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: invalid source ledger custody", ErrCorrupt)
	}
	if ledger.CustodyKind == PublicationCustodyFrozenRaw &&
		ledger.GenerationID != filepath.Base(filepath.Clean(frozenDir)) {
		return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: source ledger belongs to another raw generation", ErrConflict)
	}
	if len(expected.CanonicalSHA256) != 64 || expected.ArtifactCount == 0 ||
		expected.CanonicalBytes == 0 || expected.SourceBytes == 0 {
		return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: incomplete canonical generation facts", ErrConflict)
	}
	dirInfo, err := os.Lstat(frozenDir)
	if err != nil {
		return FrozenSourceCanonicalProof{}, err
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: frozen source is not a real directory", ErrCorrupt)
	}
	entries, err := os.ReadDir(frozenDir)
	if err != nil {
		return FrozenSourceCanonicalProof{}, err
	}
	if len(entries) == 0 || uint64(len(entries)) != expected.ArtifactCount {
		return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: canonical artifact count mismatch", ErrConflict)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || !utf8.ValidString(name) || filepath.Base(name) != name ||
			strings.ContainsAny(name, "/\\\x00\r\n") || entry.IsDir() ||
			entry.Type()&os.ModeSymlink != 0 ||
			(entry.Type() != 0 && !entry.Type().IsRegular()) {
			return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: invalid frozen artifact %q", ErrCorrupt, name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if err := verifyFrozenSourceManifestIdentities(ledger, frozenDir, names); err != nil {
		return FrozenSourceCanonicalProof{}, err
	}
	hasher := sha256.New()
	counter := &canonicalSourceCounter{writer: hasher}
	if _, err := io.WriteString(counter, frozenCanonicalMagic); err != nil {
		return FrozenSourceCanonicalProof{}, err
	}
	if err := writeCanonicalUint64(counter, uint64(len(names))); err != nil {
		return FrozenSourceCanonicalProof{}, err
	}
	buffer := make([]byte, frozenCanonicalChunkBytes)
	var sourceBytes uint64
	for _, name := range names {
		if uint64(len(name)) > uint64(^uint32(0)) {
			return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: oversized artifact name", ErrCorrupt)
		}
		if err := writeCanonicalUint32(counter, uint32(len(name))); err != nil {
			return FrozenSourceCanonicalProof{}, err
		}
		if _, err := io.WriteString(counter, name); err != nil {
			return FrozenSourceCanonicalProof{}, err
		}
		path := filepath.Join(frozenDir, name)
		before, err := os.Lstat(path)
		if err != nil {
			return FrozenSourceCanonicalProof{}, err
		}
		if !before.Mode().IsRegular() {
			return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: nonregular frozen artifact", ErrCorrupt)
		}
		file, err := os.Open(path)
		if err != nil {
			return FrozenSourceCanonicalProof{}, err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(before, opened) {
			_ = file.Close()
			return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: frozen artifact changed during open: %v", ErrCorrupt, err)
		}
		var fileBytes uint64
		for {
			n, readErr := io.ReadFull(file, buffer)
			if n > 0 {
				if err := writeCanonicalUint32(counter, uint32(n)); err != nil {
					_ = file.Close()
					return FrozenSourceCanonicalProof{}, err
				}
				if _, err := counter.Write(buffer[:n]); err != nil {
					_ = file.Close()
					return FrozenSourceCanonicalProof{}, err
				}
				fileBytes += uint64(n)
			}
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				break
			}
			if readErr != nil {
				_ = file.Close()
				return FrozenSourceCanonicalProof{}, readErr
			}
		}
		closeErr := file.Close()
		after, statErr := os.Lstat(path)
		if closeErr != nil || statErr != nil || !os.SameFile(opened, after) ||
			opened.Size() != after.Size() || uint64(after.Size()) != fileBytes {
			return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: frozen artifact changed during scan", ErrCorrupt)
		}
		if sourceBytes > ^uint64(0)-fileBytes {
			return FrozenSourceCanonicalProof{}, ErrCapacity
		}
		sourceBytes += fileBytes
		if err := writeCanonicalUint32(counter, 0); err != nil {
			return FrozenSourceCanonicalProof{}, err
		}
		if err := writeCanonicalUint64(counter, fileBytes); err != nil {
			return FrozenSourceCanonicalProof{}, err
		}
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if sourceBytes != expected.SourceBytes || counter.count != expected.CanonicalBytes ||
		!strings.EqualFold(digest, expected.CanonicalSHA256) {
		return FrozenSourceCanonicalProof{}, fmt.Errorf("%w: frozen canonical bytes differ from generation descriptor", ErrConflict)
	}
	return FrozenSourceCanonicalProof{
		GenerationID:               expected.GenerationID,
		SourceManifestLedgerSHA256: ledger.SHA256,
		ArtifactCount:              uint64(len(names)),
		SourceBytes:                sourceBytes,
		CanonicalBytes:             counter.count,
		CanonicalSHA256:            digest,
	}, nil
}

func verifyFrozenSourceManifestIdentities(
	ledger SourceManifestLedger, dir string, names []string,
) error {
	found := make(map[string]bool, len(ledger.Manifests))
	namesSet := make(map[string]bool, len(names))
	for _, name := range names {
		namesSet[name] = true
	}
	previous := ""
	for _, entry := range ledger.Manifests {
		if entry.Name <= previous || entry.BatchID == "" || entry.DataBytes < 0 ||
			!strings.HasPrefix(entry.Name, "batch-") || !strings.HasSuffix(entry.Name, ".manifest.json") ||
			len(entry.ManifestSHA256) != 64 || len(entry.DataSHA256) != 64 || !namesSet[entry.Name] {
			return fmt.Errorf("%w: invalid or missing source manifest identity", ErrConflict)
		}
		previous = entry.Name
		if found[entry.Name] {
			return fmt.Errorf("%w: repeated source manifest", ErrConflict)
		}
		found[entry.Name] = true
		manifestPath := filepath.Join(dir, entry.Name)
		current, err := inspectSourceManifestIdentity(manifestPath)
		if err != nil {
			return err
		}
		if current != entry {
			return fmt.Errorf("%w: source manifest changed before sealing", ErrConflict)
		}
		verified, err := spool.VerifyManifest(manifestPath)
		if err != nil || !verified.Verified {
			return fmt.Errorf("%w: source manifest verification failed: %v", ErrCorrupt, err)
		}
		if !namesSet[filepath.Base(verified.DataPath)] || filepath.Clean(filepath.Dir(verified.DataPath)) != filepath.Clean(dir) {
			return fmt.Errorf("%w: source data is not in frozen generation", ErrConflict)
		}
	}
	return nil
}

type canonicalSourceCounter struct {
	writer hash.Hash
	count  uint64
}

func (c *canonicalSourceCounter) Write(p []byte) (int, error) {
	if uint64(len(p)) > ^uint64(0)-c.count {
		return 0, ErrCapacity
	}
	n, err := c.writer.Write(p)
	c.count += uint64(n)
	return n, err
}
func writeCanonicalUint32(w io.Writer, n uint32) error {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], n)
	_, err := w.Write(value[:])
	return err
}
func writeCanonicalUint64(w io.Writer, n uint64) error {
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], n)
	_, err := w.Write(value[:])
	return err
}
