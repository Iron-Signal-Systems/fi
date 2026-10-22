// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package usncapture preserves complete volume-wide NTFS USN batches ahead of
// potentially slow governed-root correlation and NTFS re-observation.
//
// Capture and processing cursors have different custody meanings. A capture
// cursor proves that original USN change records were durably queued; the
// processing cursor advances only after a consumer supplies a successful,
// verified FI spool publication outcome. A queued USN batch is never a claim
// that its files were re-observed at the time of each historical change.
package usncapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	SchemaVersion                 = "fi-usn-capture/1"
	DefaultMaxPendingBytes uint64 = 64 << 30 // 64 GiB, fail closed at capacity
	maxEnvelopeBytes       int64  = 64 << 20 // 64 MiB, independent of read buffer
	captureName                   = "capture.json"
	processedName                 = "processed.json"
)

var (
	ErrCapacity = errors.New("FI USN capture queue capacity reached")
	ErrConflict = errors.New("FI USN capture cursor or identity conflict")
	ErrCorrupt  = errors.New("FI USN capture queue corruption")
	ErrGap      = errors.New("FI USN capture queue is not contiguous")
)

type Cursor struct {
	Version        string                 `json:"version"`
	ScopeID        string                 `json:"scope_id"`
	JournalID      string                 `json:"journal_id"`
	VolumeIdentity records.VolumeIdentity `json:"volume_identity"`
	NextUSN        string                 `json:"next_usn"`
}

type Envelope struct {
	Version string               `json:"version"`
	Batch   records.USNReadBatch `json:"batch"`
	Work    []ObjectWork         `json:"work"`
	SHA256  string               `json:"sha256"`
}

// Segment contains a verified, immutable source batch. Caller MUST publish
// its derived observations to the verified FI spool before CommitProcessed.
// It is not safe to infer governed-root membership from current parent alone.
type Segment struct {
	Name   string
	Batch  records.USNReadBatch
	Work   []ObjectWork
	SHA256 string
}

// Store requires one process owner per scope. The FI collector's existing
// process ownership provides that exclusion; this package does not implement
// cross-process locking. Never place its directory in the FI sender spool.
type Store struct {
	mu        sync.Mutex
	dir       string
	maxBytes  uint64
	capture   Cursor
	processed Cursor
}

// Open recovers after a crash, including the case in which a segment was
// published but the independent capture cursor wasn't advanced. Both cursors
// must have been explicitly initialized at an established source boundary.
func Open(dir string, maxPendingBytes uint64) (*Store, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) == "." {
		return nil, errors.New("FI USN capture directory must be absolute")
	}
	if maxPendingBytes == 0 {
		return nil, errors.New("FI USN capture capacity must be positive")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("FI USN capture root must be a real directory")
	}
	s := &Store{dir: dir, maxBytes: maxPendingBytes}
	s.capture, err = readCursor(filepath.Join(dir, captureName))
	if err != nil {
		return nil, fmt.Errorf("load capture cursor: %w", err)
	}
	s.processed, err = readCursor(filepath.Join(dir, processedName))
	if err != nil {
		return nil, fmt.Errorf("load processing cursor: %w", err)
	}
	if !sameIdentity(s.capture, s.processed) {
		return nil, fmt.Errorf("%w: capture and processing source identity", ErrConflict)
	}
	if err := s.recoverLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// Initialize creates a new, empty queue at a previously validated and durable
// baseline/checkpoint. It refuses existing entries. NEVER use Initialize to
// bypass a continuity gap or to replace a queue after an outage.
func Initialize(dir string, anchor Cursor) error {
	if err := validateCursor(anchor); err != nil {
		return err
	}
	if !filepath.IsAbs(dir) {
		return errors.New("FI USN capture directory must be absolute")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("create exclusive capture directory: %w", err)
	}
	if err := atomicWrite(filepath.Join(dir, captureName), mustJSON(anchor)); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, processedName), mustJSON(anchor))
}

func (s *Store) CaptureCursor() Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capture
}

func (s *Store) ProcessingCursor() Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.processed
}

// Append durably saves one complete, volume-wide USN batch BEFORE advancing
// the capture cursor. Replayed segments at the same start are accepted only
// when every original byte agrees. No historical source record is deduplicated.
func (s *Store) Append(batch records.USNReadBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateBatch(batch); err != nil {
		return err
	}
	if !matchesBatch(s.capture, batch) || batch.StartUSN != s.capture.NextUSN {
		return fmt.Errorf("%w: unexpected capture start or source identity", ErrConflict)
	}
	start, _ := strconv.ParseUint(batch.StartUSN, 10, 64)
	end, _ := strconv.ParseUint(batch.NextUSN, 10, 64)
	if end <= start {
		return errors.New("capture batch must make forward progress")
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if int64(len(payload)) > maxEnvelopeBytes {
		return errors.New("capture batch exceeds maximum durable record size")
	}
	digest := sha256.Sum256(payload)
	entry := Envelope{Version: SchemaVersion, Batch: batch, Work: DistinctWork(batch), SHA256: hex.EncodeToString(digest[:])}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > maxEnvelopeBytes {
		return errors.New("capture envelope exceeds maximum durable record size")
	}
	used, err := s.pendingBytesLocked()
	if err != nil {
		return err
	}
	if uint64(len(encoded)) > s.maxBytes || used > s.maxBytes-uint64(len(encoded)) {
		return ErrCapacity
	}
	path := filepath.Join(s.dir, segmentName(start))
	// An orphaned segment must be recovered by Open, rather than replaced.
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%w: segment already exists at start %d", ErrConflict, start)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := atomicWrite(path, encoded); err != nil {
		return fmt.Errorf("persist source batch: %w", err)
	}
	newCursor := s.capture
	newCursor.NextUSN = batch.NextUSN
	if err := atomicWrite(filepath.Join(s.dir, captureName), mustJSON(newCursor)); err != nil {
		return err
	}
	s.capture = newCursor
	return nil
}

// Next returns the earliest unprocessed segment, even if NTFS has now aged
// its underlying change records out of the live journal. The immutable cached
// records can still be processed, but re-observation sees current NTFS state.
func (s *Store) Next() (Segment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.listLocked()
	if err != nil {
		return Segment{}, false, err
	}
	for _, name := range items {
		value, err := s.loadSegmentLocked(name)
		if err != nil {
			return Segment{}, false, err
		}
		start, _ := strconv.ParseUint(value.Batch.StartUSN, 10, 64)
		processed, _ := strconv.ParseUint(s.processed.NextUSN, 10, 64)
		if start < processed {
			end, _ := strconv.ParseUint(value.Batch.NextUSN, 10, 64)
			if end > processed {
				return Segment{}, false, fmt.Errorf("%w: segment overlaps processing cursor", ErrCorrupt)
			}
			continue // acknowledged but not yet garbage collected
		}
		if start != processed {
			return Segment{}, false, ErrGap
		}
		return value, true, nil
	}
	if s.processed.NextUSN != s.capture.NextUSN {
		return Segment{}, false, ErrGap
	}
	return Segment{}, false, nil
}

// CommitProcessed is ONLY for a consumer that has already durably finalized
// and verified all FI spool batches and necessary correlation state. The
// publishedProof is an opaque nonempty reference to that independently verified
// publication, or a separately recorded no-governed-object scope decision.
// After a crash before cursor advancement, reprocessing must be idempotent.
func (s *Store) CommitProcessed(seg Segment, publishedProof string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(publishedProof) == "" {
		return errors.New("verified FI publication proof is required")
	}
	if seg.Name != segmentNameMust(seg.Batch.StartUSN) || seg.Batch.StartUSN != s.processed.NextUSN || !matchesBatch(s.processed, seg.Batch) {
		return fmt.Errorf("%w: unexpected processing segment", ErrConflict)
	}
	current, err := s.loadSegmentLocked(seg.Name)
	if err != nil {
		return err
	}
	if current.SHA256 != seg.SHA256 || current.Batch.NextUSN != seg.Batch.NextUSN {
		return fmt.Errorf("%w: processing segment changed", ErrCorrupt)
	}
	next := s.processed
	next.NextUSN = current.Batch.NextUSN
	// Persist receipt first. This is for attribution/recovery, not the FI
	// spool's authoritative verified-publication boundary.
	receipt := struct {
		Version           string `json:"version"`
		SourceBatchSHA256 string `json:"source_batch_sha256"`
		SpoolProof        string `json:"spool_proof"`
		StartUSN          string `json:"start_usn"`
		NextUSN           string `json:"next_usn"`
	}{SchemaVersion, seg.SHA256, publishedProof, seg.Batch.StartUSN, seg.Batch.NextUSN}
	if err := atomicWrite(filepath.Join(s.dir, "receipt-"+seg.Name), mustJSON(receipt)); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(s.dir, processedName), mustJSON(next)); err != nil {
		return err
	}
	s.processed = next
	// Source batch deletion is deliberately deferred. Only a separately
	// controlled retention/garbage-collection policy may remove original data.
	return nil
}

func (s *Store) pendingBytesLocked() (uint64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, e := range entries {
		// Both original journal facts and writable correlation caches consume
		// the SAME disk budget. Otherwise the derived index could grow without
		// bound even while the source queue's capacity appeared healthy.
		captureBatch := strings.HasPrefix(e.Name(), "batch-") && strings.HasSuffix(e.Name(), ".json")
		correlation := strings.HasPrefix(e.Name(), "correlation-batch-") && strings.HasSuffix(e.Name(), ".json")
		intent := strings.HasPrefix(e.Name(), "publication-batch-") && strings.HasSuffix(e.Name(), ".json")
		ledger := strings.HasPrefix(e.Name(), "source-manifests-batch-") && strings.HasSuffix(e.Name(), ".json")
		handoff := strings.HasPrefix(e.Name(), "sealed-handoff-batch-") && strings.HasSuffix(e.Name(), ".json")
		if !captureBatch && !correlation && !intent && !ledger && !handoff {
			continue
		}
		if !e.Type().IsRegular() {
			return 0, fmt.Errorf("%w: nonregular queue entry", ErrCorrupt)
		}
		info, err := e.Info()
		if err != nil {
			return 0, err
		}
		total += uint64(info.Size())
	}
	return total, nil
}

func (s *Store) listLocked() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		n := entry.Name()
		if !strings.HasPrefix(n, "batch-") || !strings.HasSuffix(n, ".json") {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("%w: nonregular queue entry %q", ErrCorrupt, n)
		}
		if len(n) != len(segmentName(0)) {
			return nil, fmt.Errorf("%w: malformed segment name %q", ErrCorrupt, n)
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(n, "batch-"), ".json"), 10, 64); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) loadSegmentLocked(name string) (Segment, error) {
	path := filepath.Join(s.dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return Segment{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxEnvelopeBytes {
		return Segment{}, fmt.Errorf("%w: invalid capture file", ErrCorrupt)
	}
	f, err := os.Open(path)
	if err != nil {
		return Segment{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxEnvelopeBytes+1))
	if err != nil {
		return Segment{}, err
	}
	if int64(len(raw)) > maxEnvelopeBytes {
		return Segment{}, fmt.Errorf("%w: oversized capture segment", ErrCorrupt)
	}
	var entry Envelope
	if err := json.Unmarshal(raw, &entry); err != nil {
		return Segment{}, fmt.Errorf("%w: invalid JSON: %v", ErrCorrupt, err)
	}
	if entry.Version != SchemaVersion {
		return Segment{}, fmt.Errorf("%w: unknown capture version", ErrCorrupt)
	}
	if err := validateBatch(entry.Batch); err != nil {
		return Segment{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	digestRaw, err := json.Marshal(entry.Batch)
	if err != nil {
		return Segment{}, err
	}
	digest := sha256.Sum256(digestRaw)
	if !reflect.DeepEqual(entry.Work, DistinctWork(entry.Batch)) {
		return Segment{}, fmt.Errorf("%w: distinct work index mismatch", ErrCorrupt)
	}
	if !strings.EqualFold(entry.SHA256, hex.EncodeToString(digest[:])) {
		return Segment{}, fmt.Errorf("%w: checksum mismatch", ErrCorrupt)
	}
	if name != segmentNameMust(entry.Batch.StartUSN) || !matchesBatch(s.capture, entry.Batch) {
		return Segment{}, fmt.Errorf("%w: segment identity mismatch", ErrCorrupt)
	}
	return Segment{Name: name, Batch: entry.Batch, Work: entry.Work, SHA256: entry.SHA256}, nil
}

func (s *Store) recoverLocked() error {
	processed, _ := strconv.ParseUint(s.processed.NextUSN, 10, 64)
	capture, _ := strconv.ParseUint(s.capture.NextUSN, 10, 64)
	if processed > capture {
		return fmt.Errorf("%w: processed cursor ahead of capture", ErrConflict)
	}
	items, err := s.listLocked()
	if err != nil {
		return err
	}
	position := processed
	for _, name := range items {
		seg, err := s.loadSegmentLocked(name)
		if err != nil {
			return err
		}
		start, _ := strconv.ParseUint(seg.Batch.StartUSN, 10, 64)
		end, _ := strconv.ParseUint(seg.Batch.NextUSN, 10, 64)
		if end <= processed {
			continue
		}
		if start != position {
			return fmt.Errorf("%w: expected %d, got %d", ErrGap, position, start)
		}
		position = end
	}
	if position < capture {
		return fmt.Errorf("%w: capture cursor outran durable segments", ErrGap)
	}
	if position > capture {
		updated := s.capture
		updated.NextUSN = strconv.FormatUint(position, 10)
		if err := atomicWrite(filepath.Join(s.dir, captureName), mustJSON(updated)); err != nil {
			return err
		}
		s.capture = updated
	}
	return nil
}

func atomicWrite(path string, data []byte) (retErr error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".fi-usn-capture-*.tmp")
	if err != nil {
		return err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return commitRename(f.Name(), path)
}

func readCursor(path string) (Cursor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Cursor{}, err
	}
	var value Cursor
	if err := json.Unmarshal(raw, &value); err != nil {
		return Cursor{}, err
	}
	if err := validateCursor(value); err != nil {
		return Cursor{}, err
	}
	return value, nil
}

func validateCursor(c Cursor) error {
	if c.Version != SchemaVersion || c.ScopeID == "" {
		return errors.New("invalid capture cursor version or scope")
	}
	if err := records.ValidateVolumeIdentity(c.VolumeIdentity); err != nil {
		return err
	}
	if !canonicalDecimal(c.JournalID) || !canonicalDecimal(c.NextUSN) {
		return errors.New("invalid capture cursor decimal")
	}
	return nil
}

func validateBatch(batch records.USNReadBatch) error {
	if err := records.ValidateUSNReadBatch(batch); err != nil {
		return err
	}
	if !canonicalDecimal(batch.StartUSN) || !canonicalDecimal(batch.NextUSN) || !canonicalDecimal(batch.JournalID) {
		return errors.New("noncanonical USN batch decimal")
	}
	start, _ := strconv.ParseUint(batch.StartUSN, 10, 64)
	end, _ := strconv.ParseUint(batch.NextUSN, 10, 64)
	if end <= start {
		return errors.New("USN capture batch does not advance")
	}
	for _, change := range batch.Records {
		position, err := strconv.ParseUint(change.USN, 10, 64)
		if err != nil || position < start || position >= end {
			return errors.New("USN record outside captured range")
		}
	}
	return nil
}

func matchesBatch(cursor Cursor, batch records.USNReadBatch) bool {
	return cursor.ScopeID == batch.ScopeID && cursor.JournalID == batch.JournalID && reflect.DeepEqual(cursor.VolumeIdentity, batch.VolumeIdentity)
}

func sameIdentity(a, b Cursor) bool {
	return a.ScopeID == b.ScopeID && a.JournalID == b.JournalID && reflect.DeepEqual(a.VolumeIdentity, b.VolumeIdentity)
}
func canonicalDecimal(s string) bool {
	n, e := strconv.ParseUint(s, 10, 64)
	return e == nil && strconv.FormatUint(n, 10) == s
}
func segmentName(start uint64) string { return fmt.Sprintf("batch-%020d.json", start) }
func segmentNameMust(start string) string {
	n, e := strconv.ParseUint(start, 10, 64)
	if e != nil {
		return ""
	}
	return segmentName(n)
}
func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

// ReclaimAcknowledged removes only source segments whose captured range is
// behind the processing cursor and whose durable receipt matches the original
// batch checksum. Receipts stay available for recovery and later inspection.
// Run only after verified FI spool publication and recorded scope decisions.
func (s *Store) ReclaimAcknowledged() (int, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.listLocked()
	if err != nil {
		return 0, 0, err
	}
	processed, _ := strconv.ParseUint(s.processed.NextUSN, 10, 64)
	count := 0
	var reclaimed uint64
	for _, name := range items {
		seg, err := s.loadSegmentLocked(name)
		if err != nil {
			return count, reclaimed, err
		}
		end, _ := strconv.ParseUint(seg.Batch.NextUSN, 10, 64)
		if end > processed {
			continue
		}
		path := filepath.Join(s.dir, "receipt-"+name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return count, reclaimed, fmt.Errorf("%w: missing durable processing receipt for %s: %v", ErrCorrupt, name, err)
		}
		var receipt struct {
			Version           string `json:"version"`
			SourceBatchSHA256 string `json:"source_batch_sha256"`
			SpoolProof        string `json:"spool_proof"`
			StartUSN          string `json:"start_usn"`
			NextUSN           string `json:"next_usn"`
		}
		if err := json.Unmarshal(raw, &receipt); err != nil {
			return count, reclaimed, fmt.Errorf("%w: processing receipt invalid JSON", ErrCorrupt)
		}
		if receipt.Version != SchemaVersion || receipt.SourceBatchSHA256 != seg.SHA256 || strings.TrimSpace(receipt.SpoolProof) == "" || receipt.StartUSN != seg.Batch.StartUSN || receipt.NextUSN != seg.Batch.NextUSN {
			return count, reclaimed, fmt.Errorf("%w: processing receipt mismatch for %s", ErrCorrupt, name)
		}
		info, err := os.Stat(filepath.Join(s.dir, name))
		if err != nil {
			return count, reclaimed, err
		}
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil {
			return count, reclaimed, err
		}
		count++
		reclaimed += uint64(info.Size())
	}
	return count, reclaimed, nil
}
