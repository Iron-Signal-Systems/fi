// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/jackc/pgx/v5"
)

const maxReconcileReceiptBytes = 256 << 10

type ReconcileState string

const (
	ReconcileStateAccepted ReconcileState = "Accepted"
	ReconcileStateConflict ReconcileState = "Conflict"
	ReconcileStatePending  ReconcileState = "Pending"
)

// RecordedReceiptCandidate is the immutable recorder identity used for the
// cheap database precheck before any FIGT custody object is reopened.
type RecordedReceiptCandidate struct {
	BatchCount uint64
	DataBytes  uint64

	GenerationID   string
	Path           string
	ReceiptSHA256  string
	RecordCount    uint64
	SourceID       string
	TransferSHA256 string
}

type ReconcilePlanItem struct {
	Candidate RecordedReceiptCandidate
	Detail    string
	State     ReconcileState
}

type ReconcilePlan struct {
	Accepted   uint64
	Conflict   uint64
	Discovered uint64
	Items      []ReconcilePlanItem
	Pending    uint64
}

type existingGenerationSnapshot struct {
	ActualBatchCount       int64
	ActualDataBytes        int64
	ActualRecordCount      int64
	MissingProjectionCount int64

	DeclaredBatchCount  int64
	DeclaredDataBytes   int64
	DeclaredRecordCount int64

	ReceiptSHA256  string
	TransferSHA256 string
}

// DiscoverRecordedReceipts reads only immutable recorder receipt objects. It
// never walks custody looking for guessed data files. Every selected receipt
// must be a 0400 regular file whose deterministic filename agrees with the
// receipt's signed source/generation identity contract.
func DiscoverRecordedReceipts(recordedRoot string, sourceFilter string) ([]RecordedReceiptCandidate, error) {
	if recordedRoot == "" {
		return nil, errors.New("FI Phase 3 recorded receipt root is required")
	}
	if !filepath.IsAbs(recordedRoot) {
		return nil, errors.New("FI Phase 3 recorded receipt root must be absolute")
	}

	resolvedRoot, err := filepath.EvalSymlinks(recordedRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve FI Phase 3 recorded receipt root: %w", err)
	}
	if filepath.Clean(resolvedRoot) != filepath.Clean(recordedRoot) {
		return nil, errors.New("FI Phase 3 recorded receipt root must not traverse symlinks")
	}

	rootInfo, err := os.Lstat(recordedRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect FI Phase 3 recorded receipt root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, errors.New("FI Phase 3 recorded receipt root must be a real directory")
	}
	if rootInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf(
			"FI Phase 3 recorded receipt root must not be group- or other-writable: mode=%04o",
			rootInfo.Mode().Perm(),
		)
	}

	entries, err := os.ReadDir(recordedRoot)
	if err != nil {
		return nil, fmt.Errorf("read FI Phase 3 recorded receipt root: %w", err)
	}

	candidates := make([]RecordedReceiptCandidate, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "generation-") || !strings.HasSuffix(name, ".record.json") {
			continue
		}

		path := filepath.Join(recordedRoot, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect FI Phase 3 recorded receipt %q: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
			return nil, fmt.Errorf("FI Phase 3 recorded receipt %q must be a 0400 regular file", path)
		}
		if info.Size() <= 0 || info.Size() > maxReconcileReceiptBytes {
			return nil, fmt.Errorf("FI Phase 3 recorded receipt %q size is outside bounds", path)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read FI Phase 3 recorded receipt %q: %w", path, err)
		}
		receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
		if err != nil {
			return nil, fmt.Errorf("decode FI Phase 3 recorded receipt %q: %w", path, err)
		}

		expectedName := generationrecorder.RecordedReceiptObjectName(
			receipt.Descriptor.SourceID,
			receipt.Descriptor.GenerationID,
		)
		if name != expectedName {
			return nil, fmt.Errorf(
				"FI Phase 3 recorded receipt filename %q does not match deterministic identity %q",
				name,
				expectedName,
			)
		}
		if sourceFilter != "" && receipt.Descriptor.SourceID != sourceFilter {
			continue
		}

		digest := sha256.Sum256(raw)
		candidates = append(candidates, RecordedReceiptCandidate{
			BatchCount:     receipt.BatchCount,
			DataBytes:      receipt.DataBytes,
			GenerationID:   receipt.Descriptor.GenerationID,
			Path:           path,
			ReceiptSHA256:  hex.EncodeToString(digest[:]),
			RecordCount:    receipt.RecordCount,
			SourceID:       receipt.Descriptor.SourceID,
			TransferSHA256: receipt.TransferSHA256,
		})
	}

	sort.Slice(candidates, func(left int, right int) bool {
		if candidates[left].SourceID == candidates[right].SourceID {
			return candidates[left].GenerationID < candidates[right].GenerationID
		}
		return candidates[left].SourceID < candidates[right].SourceID
	})

	return candidates, nil
}

func PlanRecordedGenerations(
	ctx context.Context,
	connection *pgx.Conn,
	recordedRoot string,
	sourceFilter string,
) (ReconcilePlan, error) {
	if ctx == nil {
		return ReconcilePlan{}, errors.New("FI Phase 3 reconcile context is required")
	}
	if connection == nil {
		return ReconcilePlan{}, errors.New("FI Phase 3 PostgreSQL connection is required")
	}

	candidates, err := DiscoverRecordedReceipts(recordedRoot, sourceFilter)
	if err != nil {
		return ReconcilePlan{}, err
	}

	plan := ReconcilePlan{
		Discovered: uint64(len(candidates)),
		Items:      make([]ReconcilePlanItem, 0, len(candidates)),
	}

	for _, candidate := range candidates {
		state, detail, err := inspectRecordedReceiptState(ctx, connection, candidate)
		if err != nil {
			return ReconcilePlan{}, err
		}
		plan.Items = append(plan.Items, ReconcilePlanItem{
			Candidate: candidate,
			Detail:    detail,
			State:     state,
		})

		switch state {
		case ReconcileStateAccepted:
			plan.Accepted++
		case ReconcileStateConflict:
			plan.Conflict++
		case ReconcileStatePending:
			plan.Pending++
		default:
			return ReconcilePlan{}, fmt.Errorf("unsupported FI Phase 3 reconcile state %q", state)
		}
	}

	return plan, nil
}

func evaluateExistingGeneration(
	candidate RecordedReceiptCandidate,
	snapshot existingGenerationSnapshot,
) (ReconcileState, string) {
	if strings.TrimSpace(snapshot.ReceiptSHA256) != candidate.ReceiptSHA256 ||
		strings.TrimSpace(snapshot.TransferSHA256) != candidate.TransferSHA256 {
		return ReconcileStateConflict,
			"authoritative receipt or transfer identity differs from immutable recorder receipt"
	}

	if snapshot.DeclaredBatchCount != int64(candidate.BatchCount) ||
		snapshot.DeclaredDataBytes != int64(candidate.DataBytes) ||
		snapshot.DeclaredRecordCount != int64(candidate.RecordCount) {
		return ReconcileStateConflict,
			"authoritative generation totals differ from immutable recorder receipt"
	}

	if snapshot.ActualBatchCount != int64(candidate.BatchCount) ||
		snapshot.ActualDataBytes != int64(candidate.DataBytes) ||
		snapshot.ActualRecordCount != int64(candidate.RecordCount) {
		return ReconcileStateConflict,
			"authoritative child rows are incomplete or inconsistent"
	}

	if snapshot.MissingProjectionCount != 0 {
		return ReconcileStateConflict,
			"authoritative source records are missing typed relational projections"
	}

	return ReconcileStateAccepted, ""
}

func inspectRecordedReceiptState(
	ctx context.Context,
	connection *pgx.Conn,
	candidate RecordedReceiptCandidate,
) (ReconcileState, string, error) {
	var snapshot existingGenerationSnapshot

	err := connection.QueryRow(ctx, `
SELECT
    encode(receipt_sha256, 'hex'),
    encode(transfer_sha256, 'hex'),
    batch_count::bigint,
    data_bytes::bigint,
    record_count::bigint,
    (
        SELECT count(*)::bigint
        FROM fi.source_batch sb
        WHERE sb.recorded_generation_id = rg.recorded_generation_id
    ),
    (
        SELECT COALESCE(sum(sr.record_bytes), 0)::bigint
        FROM fi.source_record sr
        JOIN fi.source_batch sb
          ON sb.source_batch_id = sr.source_batch_id
        WHERE sb.recorded_generation_id = rg.recorded_generation_id
    ),
    (
        SELECT count(*)::bigint
        FROM fi.source_record sr
        JOIN fi.source_batch sb
          ON sb.source_batch_id = sr.source_batch_id
        WHERE sb.recorded_generation_id = rg.recorded_generation_id
    ),
    (
        SELECT count(*)::bigint
        FROM fi.source_record sr
        JOIN fi.source_batch sb
          ON sb.source_batch_id = sr.source_batch_id
        WHERE sb.recorded_generation_id = rg.recorded_generation_id
          AND CASE sr.record_kind
            WHEN 'CollectorIdentity' THEN NOT EXISTS (SELECT 1 FROM fi.collector_identity x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'DirectoryPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.directory_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'FileObservation' THEN NOT EXISTS (SELECT 1 FROM fi.file_observation x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'LocalPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.local_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'NTFSCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi.ntfs_collection_error x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'SMBShareSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.smb_share_snapshot x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'SupportingSourceCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi.supporting_source_collection_error x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'USNContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi.usn_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'USNObjectObservation' THEN NOT EXISTS (SELECT 1 FROM fi.usn_object_observation x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'USNReadBoundary' THEN NOT EXISTS (SELECT 1 FROM fi.usn_read_boundary x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'WindowsSecurityContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'WindowsSecurityCoverage' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_coverage x WHERE x.source_record_id=sr.source_record_id)
            WHEN 'WindowsSecurityEvent' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_event x WHERE x.source_record_id=sr.source_record_id)
            ELSE true
          END
    )
FROM fi.recorded_generation rg
WHERE rg.source_id = $1
  AND rg.generation_id = $2
`, candidate.SourceID, candidate.GenerationID).Scan(
		&snapshot.ReceiptSHA256,
		&snapshot.TransferSHA256,
		&snapshot.DeclaredBatchCount,
		&snapshot.DeclaredDataBytes,
		&snapshot.DeclaredRecordCount,
		&snapshot.ActualBatchCount,
		&snapshot.ActualDataBytes,
		&snapshot.ActualRecordCount,
		&snapshot.MissingProjectionCount,
	)

	switch {
	case err == nil:
		state, detail := evaluateExistingGeneration(candidate, snapshot)
		return state, detail, nil

	case errors.Is(err, pgx.ErrNoRows):
		transfer, decodeErr := decodeHex(candidate.TransferSHA256, 32, true, "reconcile.transfer_sha256")
		if decodeErr != nil {
			return "", "", decodeErr
		}
		receipt, decodeErr := decodeHex(candidate.ReceiptSHA256, 32, true, "reconcile.receipt_sha256")
		if decodeErr != nil {
			return "", "", decodeErr
		}

		var collision bool
		if err := connection.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM fi.recorded_generation
    WHERE transfer_sha256 = $1
       OR receipt_sha256 = $2
)
`, transfer, receipt).Scan(&collision); err != nil {
			return "", "", fmt.Errorf("inspect FI Phase 3 reconcile identity collision: %w", err)
		}
		if collision {
			return ReconcileStateConflict,
				"receipt or transfer identity is already bound to another authoritative generation",
				nil
		}
		return ReconcileStatePending, "", nil

	default:
		return "", "", fmt.Errorf("inspect FI Phase 3 authoritative generation: %w", err)
	}
}
