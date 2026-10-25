// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

const (
	sourceManifestLedgerVersion = "fi-usn-source-manifest-inventory/1"
	maximumSourceManifestBytes  = 256 << 10
	maximumSourceLedgerBytes    = 1 << 20
)

// SourceManifestIdentity captures the exact FI manifest and data identities
// verified while the original publication still exists. It does not certify
// inclusion in a subsequently sealed generation or a receiver acknowledgement.
type SourceManifestIdentity struct {
	Name           string `json:"name"`
	ManifestSHA256 string `json:"manifest_sha256"`
	BatchID        string `json:"batch_id"`
	DataSHA256     string `json:"data_sha256"`
	DataBytes      int64  `json:"data_bytes"`
}

// SourceManifestLedger is a durable snapshot of the original source-bound
// publication. It is deliberately NOT a processing receipt and MUST NOT be used
// as authorization to replay, commit, retire, or reset any USN checkpoint.
// Inclusion in sealed transport bytes still requires a separate sender proof.
type SourceManifestLedger struct {
	Version           string                     `json:"version"`
	SourceBatchSHA256 string                     `json:"source_batch_sha256"`
	CorrelationSHA256 string                     `json:"correlation_sha256"`
	ScopeID           string                     `json:"scope_id"`
	JournalID         string                     `json:"journal_id"`
	StartUSN          string                     `json:"start_usn"`
	NextUSN           string                     `json:"next_usn"`
	RootIdentity      records.NTFSObjectIdentity `json:"root_identity"`
	CustodyKind       PublicationCustodyKind     `json:"custody_kind"`
	GenerationID      string                     `json:"generation_id,omitempty"`
	SpoolProof        string                     `json:"spool_proof"`
	Manifests         []SourceManifestIdentity   `json:"manifests"`
	SHA256            string                     `json:"sha256"`
}

func (s *Store) sourceManifestLedgerPath(seg Segment) string {
	return filepath.Join(s.dir, "source-manifests-"+seg.Name)
}

func hashLedger(value SourceManifestLedger) string {
	value.SHA256 = ""
	digest := sha256.Sum256(mustJSON(value))
	return hex.EncodeToString(digest[:])
}

func inspectSourceManifestIdentity(path string) (SourceManifestIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return SourceManifestIdentity{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumSourceManifestBytes {
		return SourceManifestIdentity{}, fmt.Errorf("%w: manifest is not a bounded regular file", ErrCorrupt)
	}
	verified, err := spool.VerifyManifest(path)
	if err != nil || !verified.Verified {
		return SourceManifestIdentity{}, fmt.Errorf("%w: source manifest verification failed: %v", ErrCorrupt, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return SourceManifestIdentity{}, err
	}
	if len(raw) == 0 || len(raw) > maximumSourceManifestBytes {
		return SourceManifestIdentity{}, fmt.Errorf("%w: source manifest changed size", ErrCorrupt)
	}
	digest := sha256.Sum256(raw)
	return SourceManifestIdentity{
		Name: filepath.Base(path), ManifestSHA256: hex.EncodeToString(digest[:]),
		BatchID: verified.Manifest.BatchID, DataSHA256: verified.Manifest.DataSHA256,
		DataBytes: verified.Manifest.DataBytes,
	}, nil
}

func (s *Store) readSourceManifestLedgerLocked(seg Segment, corr Correlation) (SourceManifestLedger, bool, error) {
	path := s.sourceManifestLedgerPath(seg)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return SourceManifestLedger{}, false, nil
	}
	if err != nil {
		return SourceManifestLedger{}, false, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumSourceLedgerBytes {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: source manifest ledger is not a bounded regular file", ErrCorrupt)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return SourceManifestLedger{}, false, err
	}
	if len(raw) == 0 || len(raw) > maximumSourceLedgerBytes {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: source manifest ledger changed size", ErrCorrupt)
	}
	var ledger SourceManifestLedger
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: source manifest ledger malformed: %v", ErrCorrupt, err)
	}
	if ledger.Version != sourceManifestLedgerVersion || !strings.EqualFold(ledger.SHA256, hashLedger(ledger)) {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: source manifest ledger integrity mismatch", ErrCorrupt)
	}
	if ledger.SourceBatchSHA256 != seg.SHA256 || ledger.CorrelationSHA256 != corr.SHA256 ||
		ledger.ScopeID != seg.Batch.ScopeID || ledger.JournalID != seg.Batch.JournalID ||
		ledger.StartUSN != seg.Batch.StartUSN || ledger.NextUSN != seg.Batch.NextUSN ||
		ledger.RootIdentity != corr.RootIdentity || ledger.SpoolProof == "" || len(ledger.Manifests) == 0 {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: source manifest ledger identity mismatch", ErrConflict)
	}
	if ledger.CustodyKind != PublicationCustodyActive && ledger.CustodyKind != PublicationCustodyFrozenRaw {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: invalid source manifest custody kind", ErrCorrupt)
	}
	if ledger.CustodyKind == PublicationCustodyActive && ledger.GenerationID != "" ||
		ledger.CustodyKind == PublicationCustodyFrozenRaw &&
			(!strings.HasPrefix(ledger.GenerationID, "generation-") || len(ledger.GenerationID) == len("generation-")) {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: invalid generation identity", ErrCorrupt)
	}
	previous := ""
	for _, v := range ledger.Manifests {
		if v.Name <= previous || !strings.HasPrefix(v.Name, "batch-") || !strings.HasSuffix(v.Name, ".manifest.json") ||
			len(v.ManifestSHA256) != 64 || len(v.DataSHA256) != 64 || v.BatchID == "" || v.DataBytes < 0 {
			return SourceManifestLedger{}, false, fmt.Errorf("%w: invalid or repeated source manifest identity", ErrCorrupt)
		}
		previous = v.Name
	}
	return ledger, true, nil
}

// ReadSourceManifestLedger validates the durable, locally integrity-checked
// inventory WITHOUT checking current spool custody, committing any cursor, or
// asserting that FISender included these records in a sealed generation.
func (s *Store) ReadSourceManifestLedger(seg Segment, corr Correlation) (SourceManifestLedger, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := intentFor(seg, corr); err != nil {
		return SourceManifestLedger{}, false, err
	}
	return s.readSourceManifestLedgerLocked(seg, corr)
}

// RecordSourceManifestLedger inventories original, verified source manifests
// while they can still be read from active or frozen-raw custody. It writes a
// durable, integrity-checked inventory BEFORE any later sender proof is
// expected. A return of nil does not advance the processing cursor and is NOT
// permission to repeat a missing publication after sender rollover.
func (s *Store) RecordSourceManifestLedger(seg Segment, corr Correlation, spoolDir string) (SourceManifestLedger, error) {
	locations, err := s.InspectPendingPublicationCustody(seg, corr, spoolDir)
	if err != nil {
		return SourceManifestLedger{}, err
	}
	if len(locations) != 1 {
		return SourceManifestLedger{}, fmt.Errorf("%w: source publication is present in ambiguous custody locations", ErrConflict)
	}
	loc := locations[0]
	return s.recordSourceManifestLedger(seg, corr, loc)
}

// RecordActiveSourceManifestLedger records a known active-spool publication
// without rescanning unrelated spool and raw-generation contents. The caller
// MUST hold spool.AcquirePublishBoundary from before the final source-manifest
// verification until after this call and the processed-cursor commit.
//
// This method independently validates the entire source-bound publication.
// A durable ledger is an inventory, not proof of sender transport or receiver
// acknowledgement, and cannot authorize re-publication or cursor advancement.
func (s *Store) RecordActiveSourceManifestLedger(
	seg Segment, corr Correlation, spoolDir string, manifests []string,
) (SourceManifestLedger, error) {
	physical, err := spool.PhysicalSpoolDir(spoolDir)
	if err != nil {
		return SourceManifestLedger{}, err
	}
	loc := PublicationCustodyLocation{
		Kind:          PublicationCustodyActive,
		Directory:     physical,
		ManifestPaths: manifests,
	}
	return s.recordSourceManifestLedger(seg, corr, loc)
}

// recordSourceManifestLedger verifies and atomically records one known
// custody location. It never advances the processing cursor.
func (s *Store) recordSourceManifestLedger(
	seg Segment, corr Correlation, loc PublicationCustodyLocation,
) (SourceManifestLedger, error) {
	proof, err := VerifySpoolPublication(seg, corr, loc.Directory, loc.ManifestPaths)
	if err != nil {
		return SourceManifestLedger{}, err
	}
	ledger := SourceManifestLedger{
		Version: sourceManifestLedgerVersion, SourceBatchSHA256: seg.SHA256,
		CorrelationSHA256: corr.SHA256, ScopeID: seg.Batch.ScopeID,
		JournalID: seg.Batch.JournalID, StartUSN: seg.Batch.StartUSN,
		NextUSN: seg.Batch.NextUSN, RootIdentity: corr.RootIdentity,
		CustodyKind: loc.Kind, SpoolProof: proof,
		Manifests: make([]SourceManifestIdentity, 0, len(loc.ManifestPaths)),
	}
	if loc.Kind == PublicationCustodyFrozenRaw {
		ledger.GenerationID = filepath.Base(loc.Directory)
	}
	for _, manifestPath := range loc.ManifestPaths {
		entry, err := inspectSourceManifestIdentity(manifestPath)
		if err != nil {
			return SourceManifestLedger{}, err
		}
		ledger.Manifests = append(ledger.Manifests, entry)
	}
	sort.Slice(ledger.Manifests, func(i, j int) bool { return ledger.Manifests[i].Name < ledger.Manifests[j].Name })
	ledger.SHA256 = hashLedger(ledger)
	encoded := mustJSON(ledger)
	if len(encoded) > maximumSourceLedgerBytes {
		return SourceManifestLedger{}, ErrCapacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if seg.Batch.StartUSN != s.processed.NextUSN {
		return SourceManifestLedger{}, fmt.Errorf("%w: source is not at processing cursor", ErrConflict)
	}
	pending, err := s.readPublicationIntentLocked(seg, corr)
	if err != nil || !pending {
		if err != nil {
			return SourceManifestLedger{}, err
		}
		return SourceManifestLedger{}, fmt.Errorf("%w: publication intent was removed", ErrConflict)
	}
	existing, found, err := s.readSourceManifestLedgerLocked(seg, corr)
	if err != nil {
		return SourceManifestLedger{}, err
	}
	if found {
		if existing.SpoolProof != ledger.SpoolProof || !reflect.DeepEqual(existing.Manifests, ledger.Manifests) {
			return SourceManifestLedger{}, fmt.Errorf("%w: existing inventory describes a different publication", ErrConflict)
		}
		return existing, nil
	}
	used, err := s.pendingBytesLocked()
	if err != nil {
		return SourceManifestLedger{}, err
	}
	if uint64(len(encoded)) > s.maxBytes || used > s.maxBytes-uint64(len(encoded)) {
		return SourceManifestLedger{}, ErrCapacity
	}
	if err := atomicWrite(s.sourceManifestLedgerPath(seg), encoded); err != nil {
		return SourceManifestLedger{}, err
	}
	return ledger, nil
}
