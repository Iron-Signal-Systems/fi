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

type ingestGenerationSnapshot struct {
	DeclaredBatchCount  int64
	DeclaredDataBytes   int64
	DeclaredRecordCount int64
	Found               bool
	GenerationID        string
	ReceiptCollision    bool
	ReceiptSHA256       string
	TransferCollision   bool
	TransferSHA256      string
}

// DiscoverRecordedReceipts reads only immutable recorder receipt objects. It
// never walks custody looking for guessed data files. Every selected receipt
// must be a 0400 regular file whose deterministic filename agrees with the
// receipt's signed source/generation identity contract.
func DiscoverRecordedReceipts(recordedRoot string, sourceFilter string) ([]RecordedReceiptCandidate, error) {
	if err := validateRecordedReceiptRoot(recordedRoot); err != nil {
		return nil, err
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

		candidate, selected, err := discoverRecordedReceipt(
			recordedRoot,
			name,
			sourceFilter,
		)
		if err != nil {
			return nil, err
		}
		if selected {
			candidates = append(candidates, candidate)
		}
	}

	sortRecordedReceiptCandidates(candidates)

	return candidates, nil
}

// DiscoverRecordedReceiptsByName validates a bounded set of exact immutable
// recorder receipt names without enumerating the complete recorded root.
func DiscoverRecordedReceiptsByName(
	recordedRoot string,
	names []string,
	sourceFilter string,
) ([]RecordedReceiptCandidate, error) {
	if err := validateRecordedReceiptRoot(recordedRoot); err != nil {
		return nil, err
	}

	candidates := make(
		[]RecordedReceiptCandidate,
		0,
		len(names),
	)
	seen := make(map[string]struct{}, len(names))

	for _, name := range names {
		if filepath.Base(name) != name ||
			!strings.HasPrefix(name, "generation-") ||
			!strings.HasSuffix(name, ".record.json") {
			return nil, fmt.Errorf(
				"FI Phase 3 recorded receipt name %q is not an exact receipt basename",
				name,
			)
		}

		if _, found := seen[name]; found {
			return nil, fmt.Errorf(
				"FI Phase 3 recorded receipt name %q was supplied more than once",
				name,
			)
		}
		seen[name] = struct{}{}

		candidate, selected, err := discoverRecordedReceipt(
			recordedRoot,
			name,
			sourceFilter,
		)
		if err != nil {
			return nil, err
		}
		if selected {
			candidates = append(candidates, candidate)
		}
	}

	sortRecordedReceiptCandidates(candidates)

	return candidates, nil
}

func discoverRecordedReceipt(
	recordedRoot string,
	name string,
	sourceFilter string,
) (
	RecordedReceiptCandidate,
	bool,
	error,
) {
	path := filepath.Join(recordedRoot, name)
	info, err := os.Lstat(path)
	if err != nil {
		return RecordedReceiptCandidate{},
			false,
			fmt.Errorf(
				"inspect FI Phase 3 recorded receipt %q: %w",
				path,
				err,
			)
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o400 {
		return RecordedReceiptCandidate{},
			false,
			fmt.Errorf(
				"FI Phase 3 recorded receipt %q must be a 0400 regular file",
				path,
			)
	}
	if info.Size() <= 0 || info.Size() > maxReconcileReceiptBytes {
		return RecordedReceiptCandidate{},
			false,
			fmt.Errorf(
				"FI Phase 3 recorded receipt %q size is outside bounds",
				path,
			)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return RecordedReceiptCandidate{},
			false,
			fmt.Errorf(
				"read FI Phase 3 recorded receipt %q: %w",
				path,
				err,
			)
	}

	receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
	if err != nil {
		return RecordedReceiptCandidate{},
			false,
			fmt.Errorf(
				"decode FI Phase 3 recorded receipt %q: %w",
				path,
				err,
			)
	}

	expectedName := generationrecorder.RecordedReceiptObjectName(
		receipt.Descriptor.SourceID,
		receipt.Descriptor.GenerationID,
	)
	if name != expectedName {
		return RecordedReceiptCandidate{},
			false,
			fmt.Errorf(
				"FI Phase 3 recorded receipt filename %q does not match deterministic identity %q",
				name,
				expectedName,
			)
	}
	if sourceFilter != "" && receipt.Descriptor.SourceID != sourceFilter {
		return RecordedReceiptCandidate{}, false, nil
	}

	digest := sha256.Sum256(raw)
	return RecordedReceiptCandidate{
		BatchCount:     receipt.BatchCount,
		DataBytes:      receipt.DataBytes,
		GenerationID:   receipt.Descriptor.GenerationID,
		Path:           path,
		ReceiptSHA256:  hex.EncodeToString(digest[:]),
		RecordCount:    receipt.RecordCount,
		SourceID:       receipt.Descriptor.SourceID,
		TransferSHA256: receipt.TransferSHA256,
	}, true, nil
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

// PlanRecordedGenerationsForIngest performs the steady-state operational
// receipt/database comparison used by the ingest worker. Immutable recorder
// receipts remain authoritative. Unlike PlanRecordedGenerations, this path
// does not re-count authoritative child rows or typed projections for every
// already-accepted generation on every polling cycle.
//
// Deep reconciliation remains the startup/manual audit path.
func PlanRecordedGenerationsForIngest(
	ctx context.Context,
	connection *pgx.Conn,
	recordedRoot string,
	sourceFilter string,
) (ReconcilePlan, error) {
	if ctx == nil {
		return ReconcilePlan{}, errors.New("FI Phase 3 ingest plan context is required")
	}
	if connection == nil {
		return ReconcilePlan{}, errors.New("FI Phase 3 PostgreSQL connection is required")
	}
	if strings.TrimSpace(sourceFilter) == "" {
		return ReconcilePlan{}, errors.New("FI Phase 3 ingest plan requires one source ID")
	}

	candidates, err := DiscoverRecordedReceipts(recordedRoot, sourceFilter)
	if err != nil {
		return ReconcilePlan{}, err
	}

	return PlanRecordedReceiptCandidatesForIngest(
		ctx,
		connection,
		sourceFilter,
		candidates,
	)
}

// PlanRecordedReceiptCandidatesForIngest performs the steady-state set-based
// database comparison for a caller-supplied bounded set of already-validated
// immutable recorder receipt candidates.
func PlanRecordedReceiptCandidatesForIngest(
	ctx context.Context,
	connection *pgx.Conn,
	sourceFilter string,
	candidates []RecordedReceiptCandidate,
) (ReconcilePlan, error) {
	if ctx == nil {
		return ReconcilePlan{}, errors.New("FI Phase 3 ingest plan context is required")
	}
	if connection == nil {
		return ReconcilePlan{}, errors.New("FI Phase 3 PostgreSQL connection is required")
	}
	if strings.TrimSpace(sourceFilter) == "" {
		return ReconcilePlan{}, errors.New("FI Phase 3 ingest plan requires one source ID")
	}

	for _, candidate := range candidates {
		if candidate.SourceID != sourceFilter {
			return ReconcilePlan{}, fmt.Errorf(
				"FI Phase 3 ingest candidate source %q differs from requested source %q",
				candidate.SourceID,
				sourceFilter,
			)
		}
	}

	plan := ReconcilePlan{
		Discovered: uint64(len(candidates)),
		Items:      make([]ReconcilePlanItem, 0, len(candidates)),
	}

	if len(candidates) == 0 {
		return plan, nil
	}

	snapshots, err := loadIngestGenerationSnapshots(
		ctx,
		connection,
		sourceFilter,
		candidates,
	)
	if err != nil {
		return ReconcilePlan{}, err
	}

	if len(snapshots) != len(candidates) {
		return ReconcilePlan{}, errors.New(
			"FI Phase 3 ingest plan database result count differs from recorder candidate count",
		)
	}

	for index, candidate := range candidates {
		snapshot := snapshots[index]

		if snapshot.GenerationID != candidate.GenerationID {
			return ReconcilePlan{}, errors.New(
				"FI Phase 3 ingest plan database result order differs from recorder candidate order",
			)
		}

		state, detail := evaluateIngestGeneration(
			candidate,
			snapshot,
		)

		plan.Items = append(
			plan.Items,
			ReconcilePlanItem{
				Candidate: candidate,
				Detail:    detail,
				State:     state,
			},
		)

		switch state {
		case ReconcileStateAccepted:
			plan.Accepted++

		case ReconcileStateConflict:
			plan.Conflict++

		case ReconcileStatePending:
			plan.Pending++

		default:
			return ReconcilePlan{}, fmt.Errorf(
				"unsupported FI Phase 3 ingest plan state %q",
				state,
			)
		}
	}

	return plan, nil
}

func evaluateIngestGeneration(
	candidate RecordedReceiptCandidate,
	snapshot ingestGenerationSnapshot,
) (ReconcileState, string) {
	if !snapshot.Found {
		if snapshot.ReceiptCollision ||
			snapshot.TransferCollision {
			return ReconcileStateConflict,
				"authoritative receipt or transfer identity is already bound to another generation"
		}

		return ReconcileStatePending, ""
	}

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

	return ReconcileStateAccepted, ""
}

func loadIngestGenerationSnapshots(
	ctx context.Context,
	connection *pgx.Conn,
	sourceID string,
	candidates []RecordedReceiptCandidate,
) ([]ingestGenerationSnapshot, error) {
	if len(candidates) == 0 {
		return []ingestGenerationSnapshot{}, nil
	}

	generationIDs := make([]string, len(candidates))
	receiptSHA256s := make([]string, len(candidates))
	transferSHA256s := make([]string, len(candidates))

	for index, candidate := range candidates {
		generationIDs[index] = candidate.GenerationID
		receiptSHA256s[index] = candidate.ReceiptSHA256
		transferSHA256s[index] = candidate.TransferSHA256
	}

	rows, err := connection.Query(
		ctx,
		`
SELECT
    c.ordinality::bigint,
    c.generation_id,
    rg.recorded_generation_id IS NOT NULL,
    COALESCE(encode(rg.receipt_sha256, 'hex'), ''),
    COALESCE(encode(rg.transfer_sha256, 'hex'), ''),
    COALESCE(rg.batch_count::bigint, 0),
    COALESCE(rg.data_bytes::bigint, 0),
    COALESCE(rg.record_count::bigint, 0),
    EXISTS (
        SELECT 1
        FROM fi.recorded_generation collision
        WHERE collision.transfer_sha256 = decode(c.transfer_sha256, 'hex')
          AND (
              collision.source_id <> $1
              OR collision.generation_id <> c.generation_id
          )
    ),
    EXISTS (
        SELECT 1
        FROM fi.recorded_generation collision
        WHERE collision.receipt_sha256 = decode(c.receipt_sha256, 'hex')
          AND (
              collision.source_id <> $1
              OR collision.generation_id <> c.generation_id
          )
    )
FROM unnest(
    $2::text[],
    $3::text[],
    $4::text[]
) WITH ORDINALITY AS c(
    generation_id,
    transfer_sha256,
    receipt_sha256,
    ordinality
)
LEFT JOIN fi.recorded_generation rg
  ON rg.source_id = $1
 AND rg.generation_id = c.generation_id
ORDER BY c.ordinality
`,
		sourceID,
		generationIDs,
		transferSHA256s,
		receiptSHA256s,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read FI Phase 3 operational generation state: %w",
			err,
		)
	}
	defer rows.Close()

	snapshots := make(
		[]ingestGenerationSnapshot,
		0,
		len(candidates),
	)

	for rows.Next() {
		var ordinal int64
		var snapshot ingestGenerationSnapshot

		if err := rows.Scan(
			&ordinal,
			&snapshot.GenerationID,
			&snapshot.Found,
			&snapshot.ReceiptSHA256,
			&snapshot.TransferSHA256,
			&snapshot.DeclaredBatchCount,
			&snapshot.DeclaredDataBytes,
			&snapshot.DeclaredRecordCount,
			&snapshot.TransferCollision,
			&snapshot.ReceiptCollision,
		); err != nil {
			return nil, fmt.Errorf(
				"scan FI Phase 3 operational generation state: %w",
				err,
			)
		}

		expectedOrdinal := int64(len(snapshots) + 1)
		if ordinal != expectedOrdinal {
			return nil, fmt.Errorf(
				"FI Phase 3 operational generation state ordinal %d, expected %d",
				ordinal,
				expectedOrdinal,
			)
		}

		if snapshot.GenerationID !=
			candidates[len(snapshots)].GenerationID {
			return nil, errors.New(
				"FI Phase 3 operational generation state identity differs from recorder candidate",
			)
		}

		snapshots = append(
			snapshots,
			snapshot,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"read FI Phase 3 operational generation state: %w",
			err,
		)
	}

	if len(snapshots) != len(candidates) {
		return nil, errors.New(
			"FI Phase 3 operational generation state is incomplete",
		)
	}

	return snapshots, nil
}

func sortRecordedReceiptCandidates(
	candidates []RecordedReceiptCandidate,
) {
	sort.Slice(candidates, func(left int, right int) bool {
		if candidates[left].SourceID == candidates[right].SourceID {
			return candidates[left].GenerationID < candidates[right].GenerationID
		}
		return candidates[left].SourceID < candidates[right].SourceID
	})
}

func validateRecordedReceiptRoot(
	recordedRoot string,
) error {
	if recordedRoot == "" {
		return errors.New("FI Phase 3 recorded receipt root is required")
	}
	if !filepath.IsAbs(recordedRoot) {
		return errors.New("FI Phase 3 recorded receipt root must be absolute")
	}

	resolvedRoot, err := filepath.EvalSymlinks(recordedRoot)
	if err != nil {
		return fmt.Errorf("resolve FI Phase 3 recorded receipt root: %w", err)
	}
	if filepath.Clean(resolvedRoot) != filepath.Clean(recordedRoot) {
		return errors.New("FI Phase 3 recorded receipt root must not traverse symlinks")
	}

	rootInfo, err := os.Lstat(recordedRoot)
	if err != nil {
		return fmt.Errorf("inspect FI Phase 3 recorded receipt root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("FI Phase 3 recorded receipt root must be a real directory")
	}
	if rootInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf(
			"FI Phase 3 recorded receipt root must not be group- or other-writable: mode=%04o",
			rootInfo.Mode().Perm(),
		)
	}

	return nil
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
