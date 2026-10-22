// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// SpoolBoundary is the capture-specific binding inside the existing FI
// USNReadBoundary record. It must be appended before the object observations.
// These additional fields never transform USN facts into historical NTFS state.
// The producer must still publish the normal scope counts and operation IDs.
type SpoolBoundary struct {
	SourceBatchSHA256         string                     `json:"source_batch_sha256"`
	CorrelationSHA256         string                     `json:"correlation_sha256"`
	RootIdentity              records.NTFSObjectIdentity `json:"root_identity"`
	JournalID                 string                     `json:"journal_id"`
	StartUSN                  string                     `json:"start_usn"`
	NextUSN                   string                     `json:"next_usn"`
	SourceRecordCount         int                        `json:"source_record_count"`
	SourceDistinctObjectCount int                        `json:"source_distinct_object_count"`
}

// VerifySpoolPublication validates a complete set of FI spool manifests AND
// their source-to-observation mapping. It refuses to accept a generic "success"
// string, an unrelated previously published FI batch, missing observations, or
// an observation that omits a source USN event. Every distinct source File-ID
// must have an explicit record, including unavailable and unresolved objects.
//
// The caller must ensure spool publication/transport rollover serialization.
// This method does not provide that Windows process-level boundary itself.
func VerifySpoolPublication(
	seg Segment, correlation Correlation, spoolDir string, manifests []string,
) (string, error) {
	if len(manifests) == 0 || !filepath.IsAbs(spoolDir) {
		return "", errors.New("FI verified spool directory and manifests required")
	}
	// The FI spool writer resolves its configured directory to the actual
	// publication directory (including Windows junctions and path aliases).
	// Compare against that same physical directory, not the caller's spelling.
	physicalSpoolDir, err := spool.PhysicalSpoolDir(spoolDir)
	if err != nil {
		return "", fmt.Errorf("inspect FI spool publication directory: %w", err)
	}
	canonical, err := BuildCorrelation(seg, correlation.RootIdentity)
	if err != nil || !reflect.DeepEqual(canonical, correlation) {
		return "", fmt.Errorf("%w: correlation differs from source", ErrConflict)
	}
	expected := make(map[records.NTFSObjectIdentity][]records.USNChangeObservation)
	for _, change := range seg.Batch.Records {
		expected[change.FileIdentity] = append(expected[change.FileIdentity], change)
	}
	seenObjects := make(map[records.NTFSObjectIdentity]bool)
	seenManifests := make(map[string]bool)
	boundaryCount := 0
	proofs := make([]string, 0, len(manifests))
	for _, path := range manifests {
		cleanPath := filepath.Clean(path)
		if !filepath.IsAbs(path) ||
			filepath.Dir(cleanPath) != physicalSpoolDir ||
			seenManifests[cleanPath] {
			return "", fmt.Errorf("%w: unrelated or repeated FI manifest", ErrConflict)
		}
		seenManifests[cleanPath] = true
		verification, err := spool.VerifyManifest(path)
		if err != nil || !verification.Verified {
			return "", fmt.Errorf("%w: FI spool manifest not verified: %v", ErrCorrupt, err)
		}
		file, err := os.Open(verification.DataPath)
		if err != nil {
			return "", err
		}
		scan := bufio.NewScanner(file)
		scan.Buffer(make([]byte, 4096), int(spool.DefaultMaxBatchBytes)+1)
		for scan.Scan() {
			var record spool.Record
			if err := json.Unmarshal(scan.Bytes(), &record); err != nil {
				file.Close()
				return "", fmt.Errorf("%w: FI spool JSON: %v", ErrCorrupt, err)
			}
			if record.ScopeID != seg.Batch.ScopeID || record.Version != spool.RecordVersion {
				file.Close()
				return "", fmt.Errorf("%w: FI spool source scope/version mismatch", ErrConflict)
			}
			switch record.RecordKind {
			case "USNReadBoundary":
				boundaryCount++
				var b SpoolBoundary
				if err := json.Unmarshal(record.Payload, &b); err != nil ||
					b.SourceBatchSHA256 != seg.SHA256 ||
					b.CorrelationSHA256 != correlation.SHA256 ||
					b.RootIdentity != correlation.RootIdentity ||
					b.JournalID != seg.Batch.JournalID ||
					b.StartUSN != seg.Batch.StartUSN || b.NextUSN != seg.Batch.NextUSN ||
					b.SourceRecordCount != len(seg.Batch.Records) ||
					b.SourceDistinctObjectCount != len(seg.Work) {
					file.Close()
					return "", fmt.Errorf("%w: FI spool boundary does not match captured USN range", ErrConflict)
				}
			case "USNObjectObservation":
				var v struct {
					SourceBatchSHA256 string                         `json:"source_batch_sha256"`
					FileIdentity      records.NTFSObjectIdentity     `json:"file_identity"`
					Changes           []records.USNChangeObservation `json:"changes"`
					Status            string                         `json:"status"`
					ScopeBasis        string                         `json:"scope_basis"`
					NTFS              json.RawMessage                `json:"ntfs_observation"`
					ContentHashes     json.RawMessage                `json:"content_hashes"`
				}
				if err := json.Unmarshal(record.Payload, &v); err != nil {
					file.Close()
					return "", fmt.Errorf("%w: malformed USN object observation", ErrCorrupt)
				}
				changes, exists := expected[v.FileIdentity]
				if !exists || seenObjects[v.FileIdentity] || !reflect.DeepEqual(changes, v.Changes) {
					file.Close()
					return "", fmt.Errorf("%w: missing, repeated or altered object USN history", ErrConflict)
				}
				if v.SourceBatchSHA256 != seg.SHA256 {
					file.Close()
					return "", fmt.Errorf("%w: object observation is not bound to source USN batch", ErrConflict)
				}
				if v.ScopeBasis == "" {
					file.Close()
					return "", fmt.Errorf("%w: USN object missing scope decision", ErrConflict)
				}
				switch v.Status {
				case "Observed":
					if len(v.NTFS) == 0 || string(v.NTFS) == "null" || len(v.ContentHashes) == 0 || string(v.ContentHashes) == "null" {
						file.Close()
						return "", fmt.Errorf("%w: observed NTFS object missing metadata or hashes", ErrConflict)
					}
				case "OutsideGovernedRoot", "Unavailable", "Error":
					// Explicit non-observation outcomes must still retain source events.
				default:
					file.Close()
					return "", fmt.Errorf("%w: missing or invalid NTFS observation status", ErrConflict)
				}
				seenObjects[v.FileIdentity] = true
			default:
				file.Close()
				return "", fmt.Errorf("%w: unexpected FI record kind %q in capture publication", ErrConflict, record.RecordKind)
			}
		}
		if err := scan.Err(); err != nil {
			file.Close()
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
		proofs = append(proofs, verification.Manifest.BatchID+":"+verification.Manifest.DataSHA256)
	}
	if boundaryCount != 1 || len(seenObjects) != len(expected) {
		return "", fmt.Errorf("%w: incomplete captured USN spool publication (boundary=%d objects=%d/%d)", ErrConflict, boundaryCount, len(seenObjects), len(expected))
	}
	return "FI-verified-USN:" + seg.SHA256 + ":" + strings.Join(proofs, ","), nil
}

// CommitVerifiedSpool binds the existing processed-cursor transaction to
// independently verified actual FI spool artifacts. Receiver acknowledgements
// and network connectivity are deliberately irrelevant at this boundary.
// Replaying a crashed publisher requires an idempotent publication recovery
// plan before service activation; do not enable this experimental adapter yet.
func (s *Store) CommitVerifiedSpool(
	seg Segment, correlation Correlation, spoolDir string, manifests []string,
) error {
	proof, err := VerifySpoolPublication(seg, correlation, spoolDir, manifests)
	if err != nil {
		return err
	}
	return s.CommitProcessed(seg, proof)
}
