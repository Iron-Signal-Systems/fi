// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const (
	sealedSourceHandoffVersion = "fi-usn-sealed-source-handoff/1"
	maximumSealedHandoffBytes  = 16 << 10
)

// SealedSourceHandoff records a verified, point-in-time relationship between a
// captured USN range, its original FI spool manifests, and signed generation
// content. It is NOT an acknowledgement, a sender-retirement authorization, a
// source-trust-chain decision, or permission to advance the processing cursor.
// The SHA256 field detects accidental local corruption, not malicious rewriting.
type SealedSourceHandoff struct {
	Version              string `json:"version"`
	SourceBatchSHA256    string `json:"source_batch_sha256"`
	CorrelationSHA256    string `json:"correlation_sha256"`
	SourceLedgerSHA256   string `json:"source_ledger_sha256"`
	SpoolProof           string `json:"spool_proof"`
	ScopeID              string `json:"scope_id"`
	JournalID            string `json:"journal_id"`
	StartUSN             string `json:"start_usn"`
	NextUSN              string `json:"next_usn"`
	SourceID             string `json:"source_id"`
	GenerationID         string `json:"generation_id"`
	SignedMetadataSHA256 string `json:"signed_metadata_sha256"`
	EncodedSHA256        string `json:"encoded_sha256"`
	EncodedBytes         uint64 `json:"encoded_bytes"`
	CanonicalSHA256      string `json:"canonical_sha256"`
	CanonicalBytes       uint64 `json:"canonical_bytes"`
	SHA256               string `json:"sha256"`
}

func sealedHandoffHash(value SealedSourceHandoff) string {
	value.SHA256 = ""
	digest := sha256.Sum256(mustJSON(value))
	return hex.EncodeToString(digest[:])
}

func (s *Store) sealedHandoffPath(seg Segment) string {
	return filepath.Join(s.dir, "sealed-handoff-"+seg.Name)
}

// VerifyAndRecordSealedHandoff independently checks the still-present frozen
// source and a completed, cryptographically self-consistent sealed generation.
// It verifies the exact encoded bytes AND streams the decoded canonical bytes.
// This must eventually be called by FISender inside its pre-raw-retirement
// critical section. This milestone does not hook that call into the sender.
//
// The signed metadata certificate's chain, revocation, and FI trust policy are
// not established by this function. Receiver authorization remains separate.
// No USN cursor is moved and no source files are deleted.
func (s *Store) VerifyAndRecordSealedHandoff(
	seg Segment, corr Correlation, frozenDir, sealedDir, expectedSourceID string,
) (SealedSourceHandoff, error) {
	if expectedSourceID == "" || !filepath.IsAbs(frozenDir) || !filepath.IsAbs(sealedDir) {
		return SealedSourceHandoff{}, fmt.Errorf("%w: source and absolute custody paths required", ErrConflict)
	}
	ledger, found, err := s.ReadSourceManifestLedger(seg, corr)
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	if !found {
		return SealedSourceHandoff{}, ErrPublicationPending
	}

	published, err := transportgeneration.LoadSealedGeneration(sealedDir)
	if err != nil {
		return SealedSourceHandoff{}, fmt.Errorf("load signed generation: %w", err)
	}
	desc := published.Signed.Descriptor
	if desc.SourceID != expectedSourceID || desc.GenerationID == "" ||
		filepath.Base(filepath.Clean(frozenDir)) != "generation-"+desc.GenerationID {
		return SealedSourceHandoff{}, fmt.Errorf("%w: source or generation identity mismatch", ErrConflict)
	}
	facts := CanonicalGenerationFacts{
		GenerationID: desc.GenerationID, ArtifactCount: desc.ArtifactCount,
		SourceBytes: desc.SourceBytes, CanonicalBytes: desc.CanonicalBytes,
		CanonicalSHA256: desc.CanonicalSHA256,
	}
	if _, err := VerifyFrozenSourceCanonical(ledger, frozenDir, facts); err != nil {
		return SealedSourceHandoff{}, fmt.Errorf("verify original manifest and canonical source: %w", err)
	}
	if err := transportgeneration.VerifyPublishedGenerationPayload(published); err != nil {
		return SealedSourceHandoff{}, fmt.Errorf("verify signed encoded payload: %w", err)
	}
	if err := verifyDecodedSealedCanonical(published.PayloadPath, desc.CanonicalBytes, desc.CanonicalSHA256); err != nil {
		return SealedSourceHandoff{}, fmt.Errorf("verify decoded sealed canonical payload: %w", err)
	}
	metadata, err := os.ReadFile(published.MetadataPath)
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	// Recheck the metadata after payload verification; a changed descriptor or
	// signature must not be associated with the verified content.
	current, err := transportgeneration.LoadSealedGeneration(sealedDir)
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	if current.Signed.Descriptor != desc || !equalSignedGeneration(current.Signed, published.Signed) {
		return SealedSourceHandoff{}, fmt.Errorf("%w: signed generation changed during verification", ErrConflict)
	}
	// The exact metadata bytes must also stay stable while the payload is checked.
	metadataAfter, err := os.ReadFile(current.MetadataPath)
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	if !bytes.Equal(metadata, metadataAfter) {
		return SealedSourceHandoff{}, fmt.Errorf("%w: signed metadata bytes changed during verification", ErrConflict)
	}
	md := sha256.Sum256(metadata)
	handoff := SealedSourceHandoff{
		Version:           sealedSourceHandoffVersion,
		SourceBatchSHA256: seg.SHA256, CorrelationSHA256: corr.SHA256,
		SourceLedgerSHA256: ledger.SHA256, SpoolProof: ledger.SpoolProof,
		ScopeID: seg.Batch.ScopeID, JournalID: seg.Batch.JournalID,
		StartUSN: seg.Batch.StartUSN, NextUSN: seg.Batch.NextUSN,
		SourceID: desc.SourceID, GenerationID: desc.GenerationID,
		SignedMetadataSHA256: hex.EncodeToString(md[:]),
		EncodedSHA256:        desc.EncodedDataSHA256, EncodedBytes: desc.EncodedDataBytes,
		CanonicalSHA256: desc.CanonicalSHA256, CanonicalBytes: desc.CanonicalBytes,
	}
	handoff.SHA256 = sealedHandoffHash(handoff)
	encoded := mustJSON(handoff)
	if len(encoded) > maximumSealedHandoffBytes {
		return SealedSourceHandoff{}, ErrCapacity
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Sender can freeze multiple queued USN ranges before NTFS processing
	// advances. Verify immutable queue membership rather than requiring this
	// range to be exactly at the processing cursor. A handoff remains a custody
	// receipt only; this cannot advance any cursor or permit retirement.
	start, startErr := strconv.ParseUint(seg.Batch.StartUSN, 10, 64)
	end, endErr := strconv.ParseUint(seg.Batch.NextUSN, 10, 64)
	processed, processedErr := strconv.ParseUint(s.processed.NextUSN, 10, 64)
	captured, capturedErr := strconv.ParseUint(s.capture.NextUSN, 10, 64)
	if startErr != nil || endErr != nil || processedErr != nil || capturedErr != nil ||
		start < processed || end <= start || end > captured ||
		!matchesBatch(s.capture, seg.Batch) {
		return SealedSourceHandoff{}, fmt.Errorf("%w: range is outside pending captured custody", ErrConflict)
	}
	stored, err := s.loadSegmentLocked(seg.Name)
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	if stored.SHA256 != seg.SHA256 || stored.Batch.StartUSN != seg.Batch.StartUSN ||
		stored.Batch.NextUSN != seg.Batch.NextUSN {
		return SealedSourceHandoff{}, fmt.Errorf("%w: captured range changed", ErrCorrupt)
	}
	currentLedger, found, err := s.readSourceManifestLedgerLocked(seg, corr)
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	if !found || currentLedger.SHA256 != ledger.SHA256 {
		return SealedSourceHandoff{}, fmt.Errorf("%w: manifest inventory changed", ErrConflict)
	}
	pending, err := s.readPublicationIntentLocked(seg, corr)
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	if !pending {
		return SealedSourceHandoff{}, fmt.Errorf("%w: publication intent absent", ErrConflict)
	}

	previous, exists, err := s.readSealedHandoffLocked(seg, corr, ledger)
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	if exists {
		if previous != handoff {
			return SealedSourceHandoff{}, fmt.Errorf("%w: sealed handoff changed", ErrConflict)
		}
		return previous, nil
	}
	used, err := s.pendingBytesLocked()
	if err != nil {
		return SealedSourceHandoff{}, err
	}
	if uint64(len(encoded)) > s.maxBytes || used > s.maxBytes-uint64(len(encoded)) {
		return SealedSourceHandoff{}, ErrCapacity
	}
	if err := atomicWrite(s.sealedHandoffPath(seg), encoded); err != nil {
		return SealedSourceHandoff{}, err
	}
	return handoff, nil
}

func equalSignedGeneration(a, b transportgeneration.SignedGeneration) bool {
	return a.Version == b.Version && a.Descriptor == b.Descriptor &&
		bytes.Equal(a.Signature, b.Signature) &&
		bytes.Equal(a.BatchSigningCertificateDER, b.BatchSigningCertificateDER)
}

// verifyDecodedSealedCanonical verifies signed canonical byte count and digest
// over the ENTIRE bounded zstd-decoded payload. The decoder enforces FI's
// 16 MiB zstd window ceiling; the signed logical size enforces output bounds.
func verifyDecodedSealedCanonical(path string, expectedBytes uint64, expectedSHA string) error {
	if expectedBytes == 0 || expectedBytes >= uint64(math.MaxInt64) || len(expectedSHA) != 64 {
		return fmt.Errorf("%w: invalid signed canonical extent", ErrConflict)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("%w: payload not regular", ErrCorrupt)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) {
		return fmt.Errorf("%w: payload changed during open", ErrCorrupt)
	}
	decoder, err := transportencoding.NewZstdDecoder(file)
	if err != nil {
		return err
	}
	defer decoder.Close()
	result, err := verifyCanonicalStream(io.LimitReader(decoder, int64(expectedBytes)+1), expectedBytes, expectedSHA)
	if err != nil {
		return err
	}
	if !result {
		return fmt.Errorf("%w: canonical bytes/digest mismatch", ErrConflict)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, after) || opened.Size() != after.Size() {
		return fmt.Errorf("%w: encoded payload changed during canonical verification", ErrCorrupt)
	}
	return nil
}

// verifyCanonicalStream is deliberately codec-independent for independent
// testing of the bounded logical payload verifier.
func verifyCanonicalStream(reader io.Reader, expectedBytes uint64, expectedSHA string) (bool, error) {
	h := sha256.New()
	n, err := io.Copy(h, reader)
	if err != nil {
		return false, err
	}
	return uint64(n) == expectedBytes && strings.EqualFold(hex.EncodeToString(h.Sum(nil)), expectedSHA), nil
}

func (s *Store) readSealedHandoffLocked(seg Segment, corr Correlation, ledger SourceManifestLedger) (SealedSourceHandoff, bool, error) {
	path := s.sealedHandoffPath(seg)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return SealedSourceHandoff{}, false, nil
	}
	if err != nil {
		return SealedSourceHandoff{}, false, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumSealedHandoffBytes {
		return SealedSourceHandoff{}, false, fmt.Errorf("%w: invalid sealed handoff file", ErrCorrupt)
	}
	file, err := os.Open(path)
	if err != nil {
		return SealedSourceHandoff{}, false, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return SealedSourceHandoff{}, false, fmt.Errorf("%w: sealed handoff changed during open", ErrCorrupt)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximumSealedHandoffBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return SealedSourceHandoff{}, false, readErr
	}
	if closeErr != nil {
		return SealedSourceHandoff{}, false, closeErr
	}
	if len(raw) == 0 || len(raw) > maximumSealedHandoffBytes {
		return SealedSourceHandoff{}, false, fmt.Errorf("%w: oversized sealed handoff", ErrCorrupt)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() {
		return SealedSourceHandoff{}, false, fmt.Errorf("%w: sealed handoff changed while reading", ErrCorrupt)
	}
	var record SealedSourceHandoff
	if err := json.Unmarshal(raw, &record); err != nil {
		return SealedSourceHandoff{}, false, fmt.Errorf("%w: malformed handoff: %v", ErrCorrupt, err)
	}
	if record.Version != sealedSourceHandoffVersion || record.SHA256 != sealedHandoffHash(record) ||
		record.SourceBatchSHA256 != seg.SHA256 || record.CorrelationSHA256 != corr.SHA256 ||
		record.SourceLedgerSHA256 != ledger.SHA256 || record.SpoolProof != ledger.SpoolProof ||
		record.ScopeID != seg.Batch.ScopeID || record.JournalID != seg.Batch.JournalID ||
		record.StartUSN != seg.Batch.StartUSN || record.NextUSN != seg.Batch.NextUSN ||
		record.SourceID == "" || record.GenerationID == "" || record.EncodedBytes == 0 ||
		record.CanonicalBytes == 0 || len(record.SignedMetadataSHA256) != 64 ||
		len(record.CanonicalSHA256) != 64 || len(record.EncodedSHA256) != 64 {
		return SealedSourceHandoff{}, false, fmt.Errorf("%w: sealed handoff integrity or source mismatch", ErrCorrupt)
	}
	return record, true, nil
}

// ReadSealedSourceHandoff reads the historical verification receipt, not the
// current availability, integrity or authorization of a transported generation.
func (s *Store) ReadSealedSourceHandoff(seg Segment, corr Correlation) (SealedSourceHandoff, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, found, err := s.readSourceManifestLedgerLocked(seg, corr)
	if err != nil {
		return SealedSourceHandoff{}, false, err
	}
	if !found {
		return SealedSourceHandoff{}, false, nil
	}
	return s.readSealedHandoffLocked(seg, corr, ledger)
}
