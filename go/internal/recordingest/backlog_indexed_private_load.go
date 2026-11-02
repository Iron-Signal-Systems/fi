// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/jackc/pgx/v5"
)

// errIndexedPrivateWindowEnd intentionally halts transport decoding after the
// last requested source-batch manifest. It is not complete transfer validation.
var errIndexedPrivateWindowEnd = errors.New("FI indexed private: requested batch range reached")

// LoadIndexedBacklogPrivateWindows is an opt-in PRIVATE-only resume adapter.
// It uses ALL the original batch metadata already written to the private
// shadow by a PREVIOUS complete authenticated custody read, then reads only
// the prefix of immutable custody needed to recover the selected windows.
//
// Crucially: stopping early means this invocation DOES NOT authenticate the
// entire transport transfer. Every encountered batch must match the existing
// shadow hash and count, but only FINAL full signed-custody revalidation may
// authorize authoritative publication. Do not use this function for normal
// source ingest, acceptance, generation completion or query publication.
func LoadIndexedBacklogPrivateWindows(
	ctx context.Context, conn *pgx.Conn, config GenerationLoadConfig,
	generationID string, limits BacklogWindowLimits, startWindow, maxWindows int,
) (*PreparedGeneration, error) {
	if ctx == nil || conn == nil {
		return nil, errors.New("FI indexed private: context and SQL connection required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateGenerationLoadConfig(config, generationID); err != nil {
		return nil, err
	}
	if startWindow < 0 || maxWindows < 1 || maxWindows > 2 {
		return nil, errors.New("FI indexed private: only one or two bounded windows per trial")
	}
	if limits.MaxRecords == 0 || limits.MaxDataBytes == 0 || limits.MaxDataBytes > 256<<20 {
		return nil, errors.New("FI indexed private: bounded window limits required")
	}
	var dbUser, dbName string
	if err := conn.QueryRow(ctx, "SELECT current_user,current_database()").Scan(&dbUser, &dbName); err != nil {
		return nil, err
	}
	if dbUser != "fi_ingest" || dbName != "fi" {
		return nil, errors.New("FI indexed private: wrong PostgreSQL identity")
	}
	root := config.RecordedRoot
	if config.SourceNamespaces {
		var err error
		root, err = generationrecorder.RecordedSourceDirectory(root, config.SourceID)
		if err != nil {
			return nil, err
		}
	}
	raw, err := readImmutableReceipt(filepath.Join(root,
		generationrecorder.RecordedReceiptObjectName(config.SourceID, generationID)))
	if err != nil {
		return nil, fmt.Errorf("FI indexed private: receipt: %w", err)
	}
	receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
	if err != nil {
		return nil, err
	}
	if receipt.Descriptor.SourceID != config.SourceID || receipt.Descriptor.GenerationID != generationID {
		return nil, errors.New("FI indexed private: receipt source/generation mismatch")
	}
	sum := sha256.Sum256(raw)
	receiptSHA := hex.EncodeToString(sum[:])
	receiptHash, err := hex.DecodeString(receiptSHA)
	if err != nil {
		return nil, err
	}
	transferHash, err := hex.DecodeString(receipt.TransferSHA256)
	if err != nil {
		return nil, err
	}

	// The established private shadow was populated from a complete signed
	// loader. It contains metadata for all source batches, not merely the first
	// ten recovery windows. A partial or inconsistent index fails closed.
	rows, err := conn.Query(ctx, `
SELECT sb.manifest_artifact_name,sb.data_artifact_name,sb.manifest_version,
 sb.batch_id,sb.target_batch_size,sb.record_count,sb.data_bytes,
 sb.data_sha256,sb.data_file,sb.collector_executable_path,
 sb.collector_executable_sha256,sb.created_at,sb.completed_at,
 sb.manifest_bytes,sb.manifest_sha256
FROM fi_recovery_projection.source_batch sb
JOIN fi_recovery_projection.recorded_generation g
 ON g.recorded_generation_id=sb.recorded_generation_id
WHERE g.source_id=$1 AND g.generation_id=$2
 AND g.receipt_sha256=$3 AND g.transfer_sha256=$4
ORDER BY sb.batch_id
`, config.SourceID, generationID, receiptHash, transferHash)
	if err != nil {
		return nil, fmt.Errorf("FI indexed private: shadow index: %w", err)
	}
	batches := make([]PreparedBatch, 0, int(receipt.BatchCount))
	for rows.Next() {
		var manifestName, dataName, version, batchID, dataFile, executable string
		var target, count int
		var dataBytes, manifestBytes int64
		var dataHash, executableHash, manifestHash []byte
		var created, completed time.Time
		if err := rows.Scan(&manifestName, &dataName, &version, &batchID, &target, &count,
			&dataBytes, &dataHash, &dataFile, &executable, &executableHash,
			&created, &completed, &manifestBytes, &manifestHash); err != nil {
			rows.Close()
			return nil, err
		}
		if len(dataHash) != 32 || len(executableHash) != 32 || len(manifestHash) != 32 ||
			manifestBytes <= 0 || manifestBytes > int64(config.MaxManifestBytes) {
			rows.Close()
			return nil, errors.New("FI indexed private: invalid shadow batch digests/length")
		}
		batches = append(batches, PreparedBatch{
			BatchID: batchID, DataArtifactName: dataName, ManifestArtifactName: manifestName,
			ManifestBytes: int(manifestBytes), ManifestSHA256: hex.EncodeToString(manifestHash),
			Manifest: spool.Manifest{
				Version: version, BatchID: batchID, TargetBatchSize: target,
				RecordCount: count, DataBytes: dataBytes, DataSHA256: hex.EncodeToString(dataHash),
				DataFile: dataFile, Collector: spool.CollectorIdentity{
					ExecutablePath: executable, ExecutableSHA256: hex.EncodeToString(executableHash),
				},
				CreatedAt:   created.UTC().Format(time.RFC3339Nano),
				CompletedAt: completed.UTC().Format(time.RFC3339Nano),
			},
		})
		if uint64(len(batches)) > receipt.BatchCount {
			rows.Close()
			return nil, errors.New("FI indexed private: excess indexed batches")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if uint64(len(batches)) != receipt.BatchCount {
		return nil, fmt.Errorf("FI indexed private: only %d of %d batch metadata rows", len(batches), receipt.BatchCount)
	}

	g := &PreparedGeneration{Batches: batches, Receipt: receipt,
		ReceiptBytes: len(raw), ReceiptRawBytes: raw, ReceiptSHA256: receiptSHA}
	windows, err := DescribeBacklogWindows(g, limits)
	if err != nil {
		return nil, err
	}
	if startWindow >= len(windows) || startWindow+maxWindows > len(windows) {
		return nil, errors.New("FI indexed private: selected windows outside original generation")
	}
	fromBatch := windows[startWindow].StartBatch
	endBatch := windows[startWindow+maxWindows-1].EndBatch
	if endBatch <= fromBatch {
		return nil, errors.New("FI indexed private: empty selection")
	}

	// Require existing successful prior private checkpoints. This adapter
	// cannot bootstrap a generation or create a new trust authority.
	if startWindow == 0 {
		return nil, errors.New("FI indexed private: first window requires full authenticated loader")
	}
	var previous, sourceRows, typedRows int64
	err = conn.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi_recovery.verified_artifact_window WHERE receipt_sha256=$1 AND window_index=$2),
 (SELECT count(*) FROM fi_recovery.source_window WHERE receipt_sha256=$1 AND window_index=$2),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=$1 AND window_index=$2)
`, receiptHash, startWindow-1).Scan(&previous, &sourceRows, &typedRows)
	if err != nil {
		return nil, err
	}
	if previous != 1 || sourceRows != 1 || typedRows != 1 {
		return nil, errors.New("FI indexed private: previous complete checkpoint not present")
	}

	trust, err := loadInstalledGenerationTrust(config.SourceID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(trust.Source.SourceID, config.SourceID) ||
		trust.Root == nil || trust.BatchIssuer == nil || trust.BatchCRL == nil {
		return nil, errors.New("FI indexed private: enrolled source trust missing")
	}

	stageDir, err := os.MkdirTemp("", "fi-backlog-indexed-private-*")
	if err != nil {
		return nil, err
	}
	lease, err := newGenerationStageLease(stageDir)
	if err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = removeGenerationStageDirectory(stageDir)
			_ = lease.Close()
		}
	}()

	custodyPath := filepath.Join(config.CustodyRoot,
		transportgeneration.DurableCustodyObjectName(config.SourceID, generationID))
	info, err := os.Lstat(custodyPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() <= 0 {
		return nil, errors.New("FI indexed private: immutable custody metadata failed")
	}
	next := 0
	pending := false
	var inspection spool.DataInspection
	factory := func(desc transportgeneration.Descriptor) (transportgeneration.CanonicalArtifactHandler, error) {
		if desc != receipt.Descriptor {
			return nil, errors.New("FI indexed private: transport descriptor mismatch")
		}
		return func(name string, reader io.Reader) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if next >= len(batches) {
				return errors.New("FI indexed private: excess source artifacts")
			}
			b := &batches[next]
			if !pending {
				if name != b.DataArtifactName {
					return fmt.Errorf("FI indexed private: batch %d data name mismatch", next)
				}
				if next >= fromBatch && next < endBatch {
					path := filepath.Join(stageDir, fmt.Sprintf("batch-%08d.data", next))
					f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
					if err != nil {
						return err
					}
					inspection, err = spool.InspectData(io.TeeReader(reader, f))
					err = errors.Join(err, f.Close())
					if err != nil {
						return err
					}
					b.DataPath = path
				} else {
					var err error
					inspection, err = spool.InspectData(reader)
					if err != nil {
						return err
					}
				}
				if inspection.DataBytes != b.Manifest.DataBytes ||
					inspection.DataSHA256 != b.Manifest.DataSHA256 ||
					inspection.RecordCount != b.Manifest.RecordCount {
					return fmt.Errorf("FI indexed private: batch %d differs from previously authenticated shadow metadata", next)
				}
				pending = true
				return nil
			}
			if name != b.ManifestArtifactName {
				return fmt.Errorf("FI indexed private: batch %d manifest name mismatch", next)
			}
			data, err := io.ReadAll(io.LimitReader(reader, int64(config.MaxManifestBytes)+1))
			if err != nil {
				return err
			}
			if len(data) != b.ManifestBytes {
				return errors.New("FI indexed private: manifest length differs from validated shadow")
			}
			h := sha256.Sum256(data)
			if hex.EncodeToString(h[:]) != b.ManifestSHA256 {
				return fmt.Errorf("FI indexed private: batch %d manifest hash differs from validated shadow", next)
			}
			manifest, err := spool.DecodeManifest(bytes.NewReader(data))
			if err != nil {
				return err
			}
			if err := spool.VerifyManifestData(manifest, inspection); err != nil {
				return err
			}
			if manifest.BatchID != b.BatchID || manifest.DataFile != b.DataArtifactName ||
				manifest.DataBytes != b.Manifest.DataBytes || manifest.DataSHA256 != b.Manifest.DataSHA256 ||
				manifest.RecordCount != b.Manifest.RecordCount || manifest.TargetBatchSize != b.Manifest.TargetBatchSize ||
				manifest.Version != b.Manifest.Version {
				return fmt.Errorf("FI indexed private: batch %d manifest content differs from shadow", next)
			}
			if next >= fromBatch && next < endBatch {
				b.ManifestRawBytes = data
			}
			next++
			pending = false
			if next == endBatch {
				return errIndexedPrivateWindowEnd
			}
			return nil
		}, nil
	}
	_, err = transportgeneration.ReadDiscoveredDurableCustodyArtifacts(
		transportgeneration.DiscoveredCustody{Path: custodyPath, Bytes: uint64(info.Size())},
		transportgeneration.CustodyConfig{
			RootDir: config.CustodyRoot,
			Receive: transportgeneration.ReceiveConfig{
				BatchCRL: trust.BatchCRL, BatchIssuer: trust.BatchIssuer, CurrentTime: time.Now(),
				MaxCanonicalBytes: config.MaxCanonicalBytes, MaxEncodedBytes: config.MaxEncodedBytes,
				Root: trust.Root, Source: trust.Source,
			},
		}, factory)
	// The expected deliberate early stop is NOT full transfer verification.
	if !errors.Is(err, errIndexedPrivateWindowEnd) {
		return nil, fmt.Errorf("FI indexed private: selective custody scan failed: %w", err)
	}
	if pending || next != endBatch {
		return nil, errors.New("FI indexed private: incomplete selected batch range")
	}
	for i := fromBatch; i < endBatch; i++ {
		if batches[i].DataPath == "" || len(batches[i].ManifestRawBytes) == 0 {
			return nil, fmt.Errorf("FI indexed private: selected batch %d not retained", i)
		}
	}
	g.stagedDirectory = stageDir
	g.stageLease = lease
	keep = true
	return g, nil
}
