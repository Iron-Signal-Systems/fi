// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const maximumProcessingReceiptBytes int64 = 16 << 10

// committedSourceReceipt is the durable processing receipt created by
// CommitProcessed. It is an attribution record, not downstream custody or
// sender-retirement authorization.
type committedSourceReceipt struct {
	Version           string `json:"version"`
	SourceBatchSHA256 string `json:"source_batch_sha256"`
	SpoolProof        string `json:"spool_proof"`
	StartUSN          string `json:"start_usn"`
	NextUSN           string `json:"next_usn"`
}

// readBoundedCustodyArtifact rejects reparse points, changing file identities,
// nonregular files, empty files and oversized files. It never writes state.
func readBoundedCustodyArtifact(path string, maximum int64) ([]byte, bool, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return nil, false, fmt.Errorf("%w: invalid custody artifact: %s", ErrCorrupt, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, false, fmt.Errorf("%w: custody artifact changed at open: %s", ErrCorrupt, path)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, false, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) ||
		opened.Size() != after.Size() || int64(len(content)) != after.Size() ||
		len(content) == 0 || int64(len(content)) > maximum {
		return nil, false, fmt.Errorf("%w: custody artifact changed during read: %s", ErrCorrupt, path)
	}
	return content, true, nil
}

// ReadCommittedSourceLedger retrieves a source-manifest inventory after the
// original captured segment has been reclaimed. It requires an exact durable
// processing receipt, a matching immutable inventory, and a processed cursor
// covering the complete source range. No USN batches are reopened.
//
// A matching local receipt and ledger are NOT a cryptographic sender handoff,
// receiver acknowledgement, source trust decision or permission to delete raw
// generations. The sender must independently verify sealed generation custody.
//
// found=false is returned only when neither receipt nor ledger exists. A
// missing counterpart or conflicting artifact fails closed instead.
func (s *Store) ReadCommittedSourceLedger(startUSN string) (SourceManifestLedger, bool, error) {
	if s == nil || !canonicalDecimal(startUSN) {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: invalid source range start", ErrConflict)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	name := segmentNameMust(startUSN)
	receiptBytes, hasReceipt, err := readBoundedCustodyArtifact(
		filepath.Join(s.dir, "receipt-"+name), maximumProcessingReceiptBytes,
	)
	if err != nil {
		return SourceManifestLedger{}, false, err
	}
	ledgerBytes, hasLedger, err := readBoundedCustodyArtifact(
		filepath.Join(s.dir, "source-manifests-"+name), maximumSourceLedgerBytes,
	)
	if err != nil {
		return SourceManifestLedger{}, false, err
	}
	if !hasReceipt && !hasLedger {
		return SourceManifestLedger{}, false, nil
	}
	if !hasReceipt || !hasLedger {
		return SourceManifestLedger{}, false, ErrPublicationPending
	}

	var receipt committedSourceReceipt
	decoder := json.NewDecoder(bytes.NewReader(receiptBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: invalid processing receipt: %v", ErrCorrupt, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: trailing processing receipt content", ErrCorrupt)
	}

	start, startErr := strconv.ParseUint(startUSN, 10, 64)
	end, endErr := strconv.ParseUint(receipt.NextUSN, 10, 64)
	processed, processedErr := strconv.ParseUint(s.processed.NextUSN, 10, 64)
	_, digestErr := hex.DecodeString(receipt.SourceBatchSHA256)
	if receipt.Version != SchemaVersion ||
		receipt.StartUSN != startUSN || !canonicalDecimal(receipt.NextUSN) ||
		startErr != nil || endErr != nil || processedErr != nil ||
		end <= start || end > processed || receipt.SpoolProof == "" ||
		len(receipt.SourceBatchSHA256) != 64 || digestErr != nil {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: processing receipt outside committed custody", ErrConflict)
	}

	// The immutable inventory contains the root identity and correlation hash.
	// Reuse its full existing validation against the verified receipt rather
	// than assuming the original batch file is available to reconstruct them.
	var hint struct {
		CorrelationSHA256 string                     `json:"correlation_sha256"`
		RootIdentity      records.NTFSObjectIdentity `json:"root_identity"`
	}
	if err := json.Unmarshal(ledgerBytes, &hint); err != nil {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: malformed committed source inventory: %v", ErrCorrupt, err)
	}
	segment := Segment{
		Name:   name,
		SHA256: receipt.SourceBatchSHA256,
		Batch: records.USNReadBatch{
			ScopeID:   s.processed.ScopeID,
			JournalID: s.processed.JournalID,
			StartUSN:  startUSN,
			NextUSN:   receipt.NextUSN,
		},
	}
	correlation := Correlation{SHA256: hint.CorrelationSHA256, RootIdentity: hint.RootIdentity}
	ledger, found, err := s.readSourceManifestLedgerLocked(segment, correlation)
	if err != nil || !found {
		if err != nil {
			return SourceManifestLedger{}, false, err
		}
		return SourceManifestLedger{}, false, ErrPublicationPending
	}
	if ledger.SpoolProof != receipt.SpoolProof || ledger.SourceBatchSHA256 != receipt.SourceBatchSHA256 ||
		ledger.StartUSN != receipt.StartUSN || ledger.NextUSN != receipt.NextUSN {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: processing receipt and source inventory disagree", ErrConflict)
	}
	return ledger, true, nil
}

const maximumSnapshotCursorBytes int64 = 16 << 10

// ReadCommittedSourceLedgerSnapshot provides a read-only view of one committed
// USN publication without opening the collector-owned Store. FISender must not
// acquire a second processing owner or call Open on the active capture queue.
//
// The source files are written with atomic renames and are immutable once
// published. An absent, malformed or inconsistent cursor fails closed. A
// successful lookup proves local receipt/ledger consistency only; it does not
// authenticate the Windows service principal, a sealed generation or a remote
// receiver acknowledgement, and is not raw-retirement authorization.
func ReadCommittedSourceLedgerSnapshot(queueDir, startUSN string) (SourceManifestLedger, bool, error) {
	if !filepath.IsAbs(queueDir) || !canonicalDecimal(startUSN) {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: absolute queue path and source USN required", ErrConflict)
	}
	queueDir = filepath.Clean(queueDir)
	info, err := os.Lstat(queueDir)
	if err != nil {
		return SourceManifestLedger{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: capture queue must be a real directory", ErrCorrupt)
	}

	capture, err := readSnapshotCursor(filepath.Join(queueDir, captureName))
	if err != nil {
		return SourceManifestLedger{}, false, fmt.Errorf("read capture snapshot: %w", err)
	}
	processed, err := readSnapshotCursor(filepath.Join(queueDir, processedName))
	if err != nil {
		return SourceManifestLedger{}, false, fmt.Errorf("read processed snapshot: %w", err)
	}
	if !sameIdentity(capture, processed) {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: capture and processed snapshot identities differ", ErrConflict)
	}
	capturedUSN, _ := strconv.ParseUint(capture.NextUSN, 10, 64)
	processedUSN, _ := strconv.ParseUint(processed.NextUSN, 10, 64)
	if processedUSN > capturedUSN {
		return SourceManifestLedger{}, false, fmt.Errorf("%w: processed cursor exceeds captured cursor", ErrConflict)
	}

	// This temporary read-only view never opens a Store, writes a cursor,
	// reclaims a batch or claims process ownership of the live queue.
	view := &Store{dir: queueDir, capture: capture, processed: processed}
	return view.ReadCommittedSourceLedger(startUSN)
}

// readSnapshotCursor bounds and identity-checks a cursor file before parsing.
// A missing cursor is corruption of the required snapshot, not an empty queue.
func readSnapshotCursor(path string) (Cursor, error) {
	value, found, err := readBoundedCustodyArtifact(path, maximumSnapshotCursorBytes)
	if err != nil {
		return Cursor{}, err
	}
	if !found {
		return Cursor{}, fmt.Errorf("%w: missing capture cursor", ErrCorrupt)
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var cursor Cursor
	if err := decoder.Decode(&cursor); err != nil {
		return Cursor{}, fmt.Errorf("%w: malformed capture cursor: %v", ErrCorrupt, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Cursor{}, fmt.Errorf("%w: extra cursor content", ErrCorrupt)
	}
	if err := validateCursor(cursor); err != nil {
		return Cursor{}, fmt.Errorf("%w: invalid snapshot cursor: %v", ErrCorrupt, err)
	}
	return cursor, nil
}
