// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const maxIngestRecordedReceiptBytes = 256 << 10

const generationStageLeaseName = ".fi-stage-owner.lock"

type GenerationLoadConfig struct {
	CustodyRoot       string
	MaxCanonicalBytes uint64
	MaxEncodedBytes   uint64
	MaxManifestBytes  uint64
	RecordedRoot      string
	SourceNamespaces  bool
	SourceID          string
}

type PreparedBatch struct {
	BatchID              string
	DataArtifactName     string
	DataPath             string
	Manifest             spool.Manifest
	ManifestArtifactName string
	ManifestBytes        int
	ManifestRawBytes     []byte
	ManifestSHA256       string
}

type PreparedGeneration struct {
	Batches         []PreparedBatch
	Receipt         generationrecorder.RecordedReceipt
	ReceiptBytes    int
	ReceiptRawBytes []byte
	ReceiptSHA256   string
	stagedDirectory string
	stageLease      *os.File
}

// removeGenerationStageDirectory keeps the lease marker until every staged
// artifact has been removed. A failed artifact deletion therefore leaves
// enough ownership information for a later, locked reclamation attempt.
func removeGenerationStageDirectory(directory string) error {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read FI staging directory: %w", err)
	}

	for _, entry := range entries {
		if entry.Name() == generationStageLeaseName {
			continue
		}

		path := filepath.Join(directory, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove FI staged artifact %q: %w", path, err)
		}
	}

	marker := filepath.Join(directory, generationStageLeaseName)
	if err := os.Remove(marker); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove FI staging marker: %w", err)
	}

	if err := os.Remove(directory); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		// All staged artifacts are gone. Restore a marker for later
		// reclamation, not as a live lease. It has a new inode and
		// does not inherit the previous file lock.
		restored, restoreErr := os.OpenFile(
			marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
		)
		if restoreErr == nil {
			restoreErr = restored.Close()
		}
		return errors.Join(
			fmt.Errorf("remove FI staging directory: %w", err),
			restoreErr,
		)
	}

	return nil
}

func (generation *PreparedGeneration) Close() error {
	if generation == nil || generation.stagedDirectory == "" {
		return nil
	}
	path := generation.stagedDirectory
	generation.stagedDirectory = ""
	// Retain the lease until the owned staging directory has been removed.
	// A concurrent reclaimer must never delete a live ingester's files.
	removeErr := removeGenerationStageDirectory(path)
	if generation.stageLease != nil {
		removeErr = errors.Join(removeErr, generation.stageLease.Close())
		generation.stageLease = nil
	}
	return removeErr
}

func LoadRecordedGeneration(config GenerationLoadConfig, generationID string) (*PreparedGeneration, error) {
	return loadRecordedGenerationWithTrust(
		config,
		generationID,
		loadInstalledGenerationTrust,
	)
}

func loadRecordedGenerationWithTrust(
	config GenerationLoadConfig,
	generationID string,
	resolveTrust generationTrustResolver,
) (*PreparedGeneration, error) {
	if err := validateGenerationLoadConfig(config, generationID); err != nil {
		return nil, err
	}
	if resolveTrust == nil {
		return nil, errors.New("FI generation trust resolver is required")
	}

	receiptName := generationrecorder.RecordedReceiptObjectName(config.SourceID, generationID)
	receiptRoot := config.RecordedRoot
	if config.SourceNamespaces {
		sourceRoot, err := generationrecorder.RecordedSourceDirectory(
			config.RecordedRoot,
			config.SourceID,
		)
		if err != nil {
			return nil, err
		}
		receiptRoot = sourceRoot
	}
	receiptPath := filepath.Join(receiptRoot, receiptName)
	receiptRaw, err := readImmutableReceipt(receiptPath)
	if err != nil {
		return nil, fmt.Errorf("read FI Phase 3 recorder receipt: %w", err)
	}

	receipt, err := generationrecorder.UnmarshalRecordedReceipt(receiptRaw)
	if err != nil {
		return nil, fmt.Errorf("decode FI Phase 3 recorder receipt: %w", err)
	}
	if receipt.Descriptor.SourceID != config.SourceID || receipt.Descriptor.GenerationID != generationID {
		return nil, errors.New("FI Phase 3 recorder receipt identity does not match requested source/generation")
	}

	receiptDigest := sha256.Sum256(receiptRaw)
	receiptSHA256 := hex.EncodeToString(receiptDigest[:])

	trust, err := resolveTrust(config.SourceID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(trust.Source.SourceID, config.SourceID) {
		return nil, fmt.Errorf(
			"FI source config identity %q does not match requested source %q",
			trust.Source.SourceID,
			config.SourceID,
		)
	}
	if trust.Root == nil ||
		trust.BatchIssuer == nil ||
		trust.BatchCRL == nil {
		return nil, errors.New(
			"FI generation trust material is incomplete",
		)
	}
	root := trust.Root
	batchIssuer := trust.BatchIssuer
	batchCRL := trust.BatchCRL

	custodyName := transportgeneration.DurableCustodyObjectName(config.SourceID, generationID)
	custodyPath := filepath.Join(config.CustodyRoot, custodyName)
	custodyInfo, err := os.Lstat(custodyPath)
	if err != nil {
		return nil, fmt.Errorf("inspect FI Phase 3 generation custody object: %w", err)
	}
	if !custodyInfo.Mode().IsRegular() || custodyInfo.Mode().Perm() != 0o400 || custodyInfo.Size() <= 0 {
		return nil, errors.New("FI Phase 3 generation custody object failed immutable-file invariants")
	}

	stageDir, err := os.MkdirTemp("", "fi-relational-ingest-generation-*")
	if err != nil {
		return nil, fmt.Errorf("create FI Phase 3 ingest staging directory: %w", err)
	}
	stageLease, err := newGenerationStageLease(stageDir)
	if err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, fmt.Errorf("own FI ingest staging directory: %w", err)
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = removeGenerationStageDirectory(stageDir)
			if stageLease != nil {
				_ = stageLease.Close()
			}
		}
	}()

	artifactNames := make([]string, 0, receipt.Descriptor.ArtifactCount)
	dataInspections := make(map[string]spool.DataInspection)
	factory := func(descriptor transportgeneration.Descriptor) (transportgeneration.CanonicalArtifactHandler, error) {
		if descriptor != receipt.Descriptor {
			return nil, errors.New("FI Phase 3 custody descriptor does not match recorder receipt")
		}
		return func(name string, reader io.Reader) error {
			if filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
				return errors.New("FI Phase 3 canonical artifact name is unsafe")
			}
			path := filepath.Join(stageDir, name)
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			dataArtifact := strings.HasPrefix(name, "batch-") && strings.HasSuffix(name, ".jsonl")
			var inspection spool.DataInspection
			var consumeErr error
			if dataArtifact {
				inspection, consumeErr = inspectStagedBatch(reader, file)
			} else {
				_, consumeErr = io.Copy(file, reader)
			}
			// FreeBSD copies are disposable and recoverable from signed custody.
			// Other platforms retain the existing per-file sync behavior.
			var syncErr error
			if runtime.GOOS != "freebsd" {
				syncErr = file.Sync()
			}
			closeErr := file.Close()
			if err := errors.Join(consumeErr, syncErr, closeErr); err != nil {
				return err
			}
			if dataArtifact {
				dataInspections[name] = inspection
			}
			artifactNames = append(artifactNames, name)
			return nil
		}, nil
	}

	custodyResult, err := transportgeneration.ReadDiscoveredDurableCustodyArtifacts(
		transportgeneration.DiscoveredCustody{Bytes: uint64(custodyInfo.Size()), Path: custodyPath},
		transportgeneration.CustodyConfig{
			RootDir: config.CustodyRoot,
			Receive: transportgeneration.ReceiveConfig{
				BatchCRL:          batchCRL,
				BatchIssuer:       batchIssuer,
				CurrentTime:       time.Now(),
				MaxCanonicalBytes: config.MaxCanonicalBytes,
				MaxEncodedBytes:   config.MaxEncodedBytes,
				Root:              root,
				Source:            trust.Source,
			},
		},
		factory,
	)
	if err != nil {
		return nil, fmt.Errorf("revalidate FI Phase 3 immutable generation custody: %w", err)
	}

	transfer := custodyResult.Transfer
	if transfer.Descriptor != receipt.Descriptor ||
		transfer.MetadataBytes != receipt.MetadataBytes ||
		transfer.MetadataSHA256 != receipt.MetadataSHA256 ||
		transfer.TransferBytes != receipt.TransferBytes ||
		transfer.TransferSHA256 != receipt.TransferSHA256 {
		return nil, errors.New("FI Phase 3 current custody transfer does not match immutable recorder receipt")
	}

	batches, dataBytes, recordCount, err := inspectStagedBatches(stageDir, artifactNames, config.MaxManifestBytes, dataInspections)
	if err != nil {
		return nil, err
	}
	if uint64(len(batches)) != receipt.BatchCount || dataBytes != receipt.DataBytes || recordCount != receipt.RecordCount {
		return nil, errors.New("FI Phase 3 staged collector semantics do not match immutable recorder receipt")
	}

	keepStage = true
	return &PreparedGeneration{
		Batches:         batches,
		Receipt:         receipt,
		ReceiptBytes:    len(receiptRaw),
		ReceiptRawBytes: append([]byte(nil), receiptRaw...),
		ReceiptSHA256:   receiptSHA256,
		stagedDirectory: stageDir,
		stageLease:      stageLease,
	}, nil
}

// inspectStagedBatch verifies the exact bytes written to staging
// without reading the staged file a second time.
func inspectStagedBatch(reader io.Reader, writer io.Writer) (spool.DataInspection, error) {
	return spool.InspectData(io.TeeReader(reader, io.MultiWriter(writer)))
}

func inspectStagedBatches(stageDir string, names []string, maxManifestBytes uint64, dataInspections map[string]spool.DataInspection) ([]PreparedBatch, uint64, uint64, error) {
	if len(names) == 0 || len(names)%2 != 0 {
		return nil, 0, 0, errors.New("FI Phase 3 staged generation does not contain complete data/manifest pairs")
	}
	if !sort.StringsAreSorted(names) {
		return nil, 0, 0, errors.New("FI Phase 3 staged artifact names are not sorted")
	}

	batches := make([]PreparedBatch, 0, len(names)/2)
	var totalDataBytes uint64
	var totalRecords uint64

	for i := 0; i < len(names); i += 2 {
		dataName := names[i]
		manifestName := names[i+1]
		if !strings.HasPrefix(dataName, "batch-") || !strings.HasSuffix(dataName, ".jsonl") {
			return nil, 0, 0, fmt.Errorf("FI Phase 3 unexpected data artifact %q", dataName)
		}
		batchID := strings.TrimSuffix(strings.TrimPrefix(dataName, "batch-"), ".jsonl")
		if batchID == "" || manifestName != "batch-"+batchID+".manifest.json" {
			return nil, 0, 0, errors.New("FI Phase 3 staged batch pair identity mismatch")
		}

		dataPath := filepath.Join(stageDir, dataName)
		inspection, ok := dataInspections[dataName]
		if !ok {
			return nil, 0, 0, fmt.Errorf("missing FI Phase 3 streamed inspection for batch %q", batchID)
		}

		manifestPath := filepath.Join(stageDir, manifestName)
		manifestRaw, err := os.ReadFile(manifestPath)
		if err != nil {
			return nil, 0, 0, err
		}
		if len(manifestRaw) == 0 || uint64(len(manifestRaw)) > maxManifestBytes {
			return nil, 0, 0, fmt.Errorf("FI Phase 3 batch %q manifest byte count is outside bounds", batchID)
		}
		manifest, err := spool.DecodeManifest(bytes.NewReader(manifestRaw))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("decode FI Phase 3 batch %q manifest: %w", batchID, err)
		}
		if manifest.BatchID != batchID || manifest.DataFile != dataName {
			return nil, 0, 0, errors.New("FI Phase 3 manifest identity does not match staged batch pair")
		}
		if err := spool.VerifyManifestData(manifest, inspection); err != nil {
			return nil, 0, 0, fmt.Errorf("verify FI Phase 3 batch %q: %w", batchID, err)
		}
		manifestDigest := sha256.Sum256(manifestRaw)

		batches = append(batches, PreparedBatch{
			BatchID:              batchID,
			DataArtifactName:     dataName,
			DataPath:             dataPath,
			Manifest:             manifest,
			ManifestArtifactName: manifestName,
			ManifestBytes:        len(manifestRaw),
			ManifestRawBytes:     append([]byte(nil), manifestRaw...),
			ManifestSHA256:       hex.EncodeToString(manifestDigest[:]),
		})
		totalDataBytes += uint64(inspection.DataBytes)
		totalRecords += uint64(inspection.RecordCount)
	}
	return batches, totalDataBytes, totalRecords, nil
}

func readImmutableReceipt(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || before.Size() <= 0 || before.Size() > maxIngestRecordedReceiptBytes {
		return nil, errors.New("FI recorder receipt failed immutable-file invariants")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.New("FI recorder receipt changed while being opened")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxIngestRecordedReceiptBytes+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if len(raw) > maxIngestRecordedReceiptBytes || int64(len(raw)) != before.Size() {
		return nil, errors.New("FI recorder receipt byte count changed while being read")
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, errors.New("FI recorder receipt changed during read")
	}
	return raw, nil
}

func validateGenerationLoadConfig(config GenerationLoadConfig, generationID string) error {
	if config.CustodyRoot == "" || !filepath.IsAbs(config.CustodyRoot) {
		return errors.New("FI Phase 3 generation custody root must be absolute")
	}
	if config.RecordedRoot == "" || !filepath.IsAbs(config.RecordedRoot) {
		return errors.New("FI Phase 3 generation recorded root must be absolute")
	}
	if config.SourceID == "" || generationID == "" {
		return errors.New("FI Phase 3 source and generation identities are required")
	}
	if config.MaxCanonicalBytes == 0 || config.MaxEncodedBytes == 0 || config.MaxManifestBytes == 0 {
		return errors.New("FI Phase 3 generation ingest limits must be greater than zero")
	}
	return nil
}
