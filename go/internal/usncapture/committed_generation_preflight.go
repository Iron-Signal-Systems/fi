// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// CommittedGenerationPreflight describes one verified point-in-time binding
// between reclaimed-or-retained USN source inventories and a sealed generation.
// It is NOT a sender-retirement authorization, a receiver acknowledgement, or
// evidence of PKI chain/revocation authorization. Nothing is persisted here.
// The caller MUST exclude simultaneous raw-generation mutation or retirement.
type CommittedGenerationPreflight struct {
	GenerationID         string
	SourceID             string
	SignedMetadataSHA256 string
	CanonicalSHA256      string
	EncodedSHA256        string
	SourceBatchSHA256    []string
	SourceLedgerSHA256   []string
}

// VerifyCommittedGenerationPreflight checks the exact set of captured USN
// sources against the original frozen FI manifests and the signed, fully
// verified sealed generation. Unlike M5D/M5E's original APIs it does not
// require retained capture segments, a collector Store, or cursor ownership.
//
// Unrelated FI manifests may coexist in a generation; all raw artifacts are
// still included in the single complete canonical-generation comparison.
// This read-only API deliberately cannot authorize raw deletion.
// VerifyCommittedGenerationPreflight verifies the normal frozen namespace.
// A retired tombstone cannot be supplied through this entrypoint.
func VerifyCommittedGenerationPreflight(
	ctx context.Context,
	rawDir, sealedDir, expectedSourceID string,
	ledgers []SourceManifestLedger,
) (CommittedGenerationPreflight, error) {
	return verifyCommittedGenerationPreflight(
		ctx, rawDir, sealedDir, expectedSourceID, ledgers, false,
	)
}

// VerifyCommittedRetiredGenerationPreflight verifies the physical raw
// tombstone while retaining the ORIGINAL logical generation identity.
// It does not restore, promote, reclaim, or delete any artifact.
func VerifyCommittedRetiredGenerationPreflight(
	ctx context.Context,
	retiredDir, sealedDir, expectedSourceID string,
	ledgers []SourceManifestLedger,
) (CommittedGenerationPreflight, error) {
	return verifyCommittedGenerationPreflight(
		ctx, retiredDir, sealedDir, expectedSourceID, ledgers, true,
	)
}

// committedGenerationDirectoryName makes the accepted physical namespace
// explicit. The logical generation ID remains the signed descriptor ID.
func committedGenerationDirectoryName(
	generationID string,
	retired bool,
) string {
	if retired {
		return ".fi-usn-raw-retired-" + generationID
	}
	return "generation-" + generationID
}
func verifyCommittedGenerationPreflight(
	ctx context.Context,
	rawDir, sealedDir, expectedSourceID string,
	ledgers []SourceManifestLedger,
	retired bool,
) (CommittedGenerationPreflight, error) {
	if ctx == nil {
		return CommittedGenerationPreflight{}, errors.New("FI committed generation preflight requires context")
	}
	if err := ctx.Err(); err != nil {
		return CommittedGenerationPreflight{}, err
	}
	if !filepath.IsAbs(rawDir) || !filepath.IsAbs(sealedDir) ||
		strings.TrimSpace(expectedSourceID) == "" || len(ledgers) == 0 {
		return CommittedGenerationPreflight{}, fmt.Errorf("%w: frozen source, sealed generation and committed ledgers required", ErrConflict)
	}
	if info, err := os.Lstat(rawDir); err != nil {
		return CommittedGenerationPreflight{}, err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return CommittedGenerationPreflight{}, fmt.Errorf("%w: frozen source must be a real directory", ErrCorrupt)
	}

	published, err := transportgeneration.LoadSealedGeneration(sealedDir)
	if err != nil {
		return CommittedGenerationPreflight{}, fmt.Errorf("load FI sealed generation: %w", err)
	}
	desc := published.Signed.Descriptor
	if desc.SourceID != expectedSourceID ||
		filepath.Base(filepath.Clean(rawDir)) != committedGenerationDirectoryName(desc.GenerationID, retired) {
		return CommittedGenerationPreflight{}, fmt.Errorf("%w: source or frozen-generation identity mismatch", ErrConflict)
	}

	// Validate the independent committed inventories before looking at source
	// bytes. No caller-supplied hash alone authenticates an original ledger.
	bySource := make(map[string]SourceManifestLedger, len(ledgers))
	byManifest := make(map[string]SourceManifestIdentity)
	manifestOwner := make(map[string]string)
	result := CommittedGenerationPreflight{
		GenerationID: desc.GenerationID, SourceID: desc.SourceID,
		SourceBatchSHA256:  make([]string, 0, len(ledgers)),
		SourceLedgerSHA256: make([]string, 0, len(ledgers)),
	}
	for _, ledger := range ledgers {
		if err := ctx.Err(); err != nil {
			return CommittedGenerationPreflight{}, err
		}
		if ledger.Version != sourceManifestLedgerVersion ||
			ledger.SHA256 == "" || ledger.SHA256 != hashLedger(ledger) ||
			len(ledger.SourceBatchSHA256) != 64 ||
			ledger.SpoolProof == "" || len(ledger.Manifests) == 0 ||
			(ledger.CustodyKind != PublicationCustodyActive && ledger.CustodyKind != PublicationCustodyFrozenRaw) ||
			(ledger.CustodyKind == PublicationCustodyActive && ledger.GenerationID != "") ||
			(ledger.CustodyKind == PublicationCustodyFrozenRaw && ledger.GenerationID != committedGenerationDirectoryName(desc.GenerationID, false)) {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: invalid committed source inventory", ErrCorrupt)
		}
		if _, err := hex.DecodeString(ledger.SourceBatchSHA256); err != nil {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: invalid source digest", ErrCorrupt)
		}
		if _, exists := bySource[ledger.SourceBatchSHA256]; exists {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: repeated captured source", ErrConflict)
		}
		bySource[ledger.SourceBatchSHA256] = ledger
		for _, manifest := range ledger.Manifests {
			if manifest.Name == "" || filepath.Base(manifest.Name) != manifest.Name ||
				!strings.HasPrefix(manifest.Name, "batch-") ||
				!strings.HasSuffix(manifest.Name, ".manifest.json") {
				return CommittedGenerationPreflight{}, fmt.Errorf("%w: invalid source manifest name", ErrCorrupt)
			}
			if _, exists := manifestOwner[manifest.Name]; exists {
				return CommittedGenerationPreflight{}, fmt.Errorf("%w: repeated source manifest ownership", ErrConflict)
			}
			manifestOwner[manifest.Name] = ledger.SourceBatchSHA256
			byManifest[manifest.Name] = manifest
		}
		result.SourceBatchSHA256 = append(result.SourceBatchSHA256, ledger.SourceBatchSHA256)
		result.SourceLedgerSHA256 = append(result.SourceLedgerSHA256, ledger.SHA256)
	}
	sort.Strings(result.SourceBatchSHA256)
	sort.Strings(result.SourceLedgerSHA256)

	entries, err := os.ReadDir(rawDir)
	if err != nil {
		return CommittedGenerationPreflight{}, err
	}
	// A synthesized in-memory inventory covers all files, including unrelated
	// manifests. Only separately validated committed ledgers identify USN owners.
	// VerifyFrozenSourceCanonical then hashes the entire raw generation once.
	combined := SourceManifestLedger{
		Version:      sourceManifestLedgerVersion,
		SpoolProof:   "read-only-full-generation-preflight",
		CustodyKind:  PublicationCustodyFrozenRaw,
		GenerationID: committedGenerationDirectoryName(desc.GenerationID, false),
	}
	boundaries := make(map[string]int)
	observedManifests := make(map[string]bool)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return CommittedGenerationPreflight{}, err
		}
		if !strings.HasSuffix(entry.Name(), ".manifest.json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: nonregular frozen manifest", ErrCorrupt)
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "batch-") {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: unexpected frozen manifest name", ErrCorrupt)
		}
		path := filepath.Join(rawDir, name)
		verified, err := spool.VerifyManifest(path)
		if err != nil || !verified.Verified {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: invalid frozen FI manifest %q: %v", ErrCorrupt, name, err)
		}
		identity, err := inspectSourceManifestIdentity(path)
		if err != nil {
			return CommittedGenerationPreflight{}, err
		}
		if expected, exists := byManifest[name]; exists && identity != expected {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: original source-manifest identity changed", ErrConflict)
		}
		observedManifests[name] = true
		combined.Manifests = append(combined.Manifests, identity)
		sourceRecords, err := scanCommittedGenerationSourceRecords(ctx, verified.DataPath, name, bySource, manifestOwner, boundaries)
		if err != nil {
			return CommittedGenerationPreflight{}, err
		}
		if _, owned := manifestOwner[name]; owned && sourceRecords == 0 {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: claimed source manifest contains no captured USN records", ErrConflict)
		}
	}
	if len(combined.Manifests) == 0 || len(observedManifests) < len(byManifest) {
		return CommittedGenerationPreflight{}, fmt.Errorf("%w: missing frozen source manifest", ErrConflict)
	}
	for name := range byManifest {
		if !observedManifests[name] {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: missing original source manifest %s", ErrConflict, name)
		}
	}
	if len(boundaries) != len(bySource) {
		return CommittedGenerationPreflight{}, fmt.Errorf("%w: incomplete frozen source-range census", ErrConflict)
	}
	for source := range bySource {
		if boundaries[source] != 1 {
			return CommittedGenerationPreflight{}, fmt.Errorf("%w: missing or repeated USN boundary for %s", ErrConflict, source)
		}
	}

	sort.Slice(combined.Manifests, func(i, j int) bool {
		return combined.Manifests[i].Name < combined.Manifests[j].Name
	})
	combined.SHA256 = hashLedger(combined)
	facts := CanonicalGenerationFacts{
		GenerationID: desc.GenerationID, ArtifactCount: desc.ArtifactCount,
		SourceBytes: desc.SourceBytes, CanonicalBytes: desc.CanonicalBytes,
		CanonicalSHA256: desc.CanonicalSHA256,
	}
	if _, err := verifyFrozenSourceCanonicalAt(combined, rawDir, facts, retired); err != nil {
		return CommittedGenerationPreflight{}, fmt.Errorf("verify complete frozen canonical source: %w", err)
	}
	if err := transportgeneration.VerifyPublishedGenerationPayload(published); err != nil {
		return CommittedGenerationPreflight{}, fmt.Errorf("verify sealed payload: %w", err)
	}
	if err := verifyDecodedSealedCanonical(published.PayloadPath, desc.CanonicalBytes, desc.CanonicalSHA256); err != nil {
		return CommittedGenerationPreflight{}, fmt.Errorf("verify decoded sealed canonical payload: %w", err)
	}
	metadata, err := os.ReadFile(published.MetadataPath)
	if err != nil {
		return CommittedGenerationPreflight{}, err
	}
	reloaded, err := transportgeneration.LoadSealedGeneration(sealedDir)
	if err != nil {
		return CommittedGenerationPreflight{}, err
	}
	after, err := os.ReadFile(reloaded.MetadataPath)
	if err != nil {
		return CommittedGenerationPreflight{}, err
	}
	if !equalSignedGeneration(published.Signed, reloaded.Signed) || !bytes.Equal(metadata, after) {
		return CommittedGenerationPreflight{}, fmt.Errorf("%w: sealed-generation metadata changed", ErrConflict)
	}
	digest := sha256.Sum256(metadata)
	result.SignedMetadataSHA256 = hex.EncodeToString(digest[:])
	result.CanonicalSHA256 = desc.CanonicalSHA256
	result.EncodedSHA256 = desc.EncodedDataSHA256
	return result, nil
}

// scanCommittedGenerationSourceRecords performs a complete original USN source
// census and refuses to attribute records to any unrelated FI spool manifest.
func scanCommittedGenerationSourceRecords(
	ctx context.Context, path, manifestName string,
	bySource map[string]SourceManifestLedger, manifestOwner map[string]string,
	boundaries map[string]int,
) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), int(spool.DefaultMaxBatchBytes)+1)
	var sourceRecords int
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var record spool.Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return 0, fmt.Errorf("%w: malformed frozen record: %v", ErrCorrupt, err)
		}
		if record.Version != spool.RecordVersion || record.ScopeID == "" {
			return 0, fmt.Errorf("%w: invalid frozen FI record envelope", ErrCorrupt)
		}
		if record.RecordKind != "USNReadBoundary" && record.RecordKind != "USNObjectObservation" {
			continue
		}
		var source struct {
			SourceBatchSHA256 string `json:"source_batch_sha256"`
		}
		if err := json.Unmarshal(record.Payload, &source); err != nil {
			return 0, fmt.Errorf("%w: malformed frozen source record", ErrCorrupt)
		}
		ledger, exists := bySource[source.SourceBatchSHA256]
		if !exists || manifestOwner[manifestName] != source.SourceBatchSHA256 || ledger.ScopeID != record.ScopeID {
			return 0, fmt.Errorf("%w: frozen source record has unaccounted ownership", ErrConflict)
		}
		if record.RecordKind == "USNReadBoundary" {
			var boundary SpoolBoundary
			if err := json.Unmarshal(record.Payload, &boundary); err != nil ||
				boundary.CorrelationSHA256 != ledger.CorrelationSHA256 ||
				boundary.RootIdentity != ledger.RootIdentity ||
				boundary.JournalID != ledger.JournalID ||
				boundary.StartUSN != ledger.StartUSN ||
				boundary.NextUSN != ledger.NextUSN {
				return 0, fmt.Errorf("%w: frozen USN boundary differs from committed inventory", ErrConflict)
			}
			boundaries[source.SourceBatchSHA256]++
		}
		sourceRecords++
	}
	return sourceRecords, scanner.Err()
}
