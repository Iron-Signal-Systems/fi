// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

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
	"sort"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

const maxIngestRecordedReceiptBytes = 256 << 10

type GenerationLoadConfig struct {
	CustodyRoot       string
	MaxCanonicalBytes uint64
	MaxEncodedBytes   uint64
	MaxManifestBytes  uint64
	RecordedRoot      string
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
}

func (generation *PreparedGeneration) Close() error {
	if generation == nil || generation.stagedDirectory == "" {
		return nil
	}
	path := generation.stagedDirectory
	generation.stagedDirectory = ""
	return os.RemoveAll(path)
}

func LoadRecordedGeneration(config GenerationLoadConfig, generationID string) (*PreparedGeneration, error) {
	if err := validateGenerationLoadConfig(config, generationID); err != nil {
		return nil, err
	}

	receiptName := generationrecorder.RecordedReceiptObjectName(config.SourceID, generationID)
	receiptPath := filepath.Join(config.RecordedRoot, receiptName)
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

	root, err := receivertrust.LoadCertificate(receivertrust.RootCAPath)
	if err != nil {
		return nil, err
	}
	batchIssuer, err := receivertrust.LoadCertificate(receivertrust.BatchIssuerPath)
	if err != nil {
		return nil, err
	}
	batchCRL, err := receivertrust.LoadCRL(receivertrust.BatchCRLPath)
	if err != nil {
		return nil, err
	}
	sourceConfigPath := filepath.Join(receivertrust.SourceRegistryPath, config.SourceID+".conf")
	sourceConfig, err := transporttrust.LoadSourceConfig(sourceConfigPath)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(sourceConfig.Authorization.SourceID, config.SourceID) {
		return nil, fmt.Errorf("FI source config identity %q does not match requested source %q", sourceConfig.Authorization.SourceID, config.SourceID)
	}

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
	keepStage := false
	defer func() {
		if !keepStage {
			_ = os.RemoveAll(stageDir)
		}
	}()

	artifactNames := make([]string, 0, receipt.Descriptor.ArtifactCount)
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
			_, copyErr := io.Copy(file, reader)
			syncErr := file.Sync()
			closeErr := file.Close()
			if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
				return err
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
				Source:            sourceConfig.Authorization,
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

	batches, dataBytes, recordCount, err := inspectStagedBatches(stageDir, artifactNames, config.MaxManifestBytes)
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
	}, nil
}

func inspectStagedBatches(stageDir string, names []string, maxManifestBytes uint64) ([]PreparedBatch, uint64, uint64, error) {
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
		dataFile, err := os.Open(dataPath)
		if err != nil {
			return nil, 0, 0, err
		}
		inspection, inspectErr := spool.InspectData(dataFile)
		closeErr := dataFile.Close()
		if err := errors.Join(inspectErr, closeErr); err != nil {
			return nil, 0, 0, fmt.Errorf("inspect FI Phase 3 batch %q data: %w", batchID, err)
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
