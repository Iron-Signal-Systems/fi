// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const generationReclaimingDirectoryPrefix = ".fi-generation-reclaiming-"
const generationRetirementMetadataMaxBytes = 512 << 10

type GenerationReclamationResult struct {
	Reclaimed          uint64
	ReclaimedDiskBytes uint64
	Resumed            uint64
}

type generationRetirementInspection struct {
	DiskBytes uint64
	Transfer  transportgeneration.TransferResult
}

func inspectGenerationRetirementTombstone(
	path string,
	sourceID string,
) (generationRetirementInspection, error) {
	if path == "" || !filepath.IsAbs(path) {
		return generationRetirementInspection{}, errors.New(
			"FI generation retirement tombstone path must be absolute",
		)
	}

	if strings.TrimSpace(sourceID) == "" {
		return generationRetirementInspection{}, errors.New(
			"FI generation source ID is required for retirement reclamation",
		)
	}

	name := filepath.Base(filepath.Clean(path))
	if err := validateGenerationRetirementObjectName(
		name,
		generationRetiredDirectoryPrefix,
	); err != nil {
		return generationRetirementInspection{}, err
	}

	if err := validateOutboundStageDirectoryPath(path); err != nil {
		return generationRetirementInspection{}, fmt.Errorf(
			"validate FI generation retirement tombstone path: %w",
			err,
		)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return generationRetirementInspection{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return generationRetirementInspection{}, errors.New(
			"FI generation retirement tombstone must name a real directory",
		)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return generationRetirementInspection{}, err
	}
	if len(entries) != 2 {
		return generationRetirementInspection{}, errors.New(
			"FI generation retirement tombstone must contain exactly two artifacts",
		)
	}

	foundMetadata := false
	foundPayload := false
	for _, entry := range entries {
		switch entry.Name() {
		case transportgeneration.SealedGenerationPayloadName:
			foundPayload = true
		case transportgeneration.SignedGenerationMetadataName:
			foundMetadata = true
		default:
			return generationRetirementInspection{}, fmt.Errorf(
				"FI generation retirement tombstone contains unexpected artifact %q",
				entry.Name(),
			)
		}
	}
	if !foundMetadata || !foundPayload {
		return generationRetirementInspection{}, errors.New(
			"FI generation retirement tombstone is incomplete",
		)
	}

	metadataPath := filepath.Join(
		path,
		transportgeneration.SignedGenerationMetadataName,
	)
	metadata, err := readGenerationRetirementMetadata(metadataPath)
	if err != nil {
		return generationRetirementInspection{}, fmt.Errorf(
			"read retired FI generation metadata: %w",
			err,
		)
	}

	signed, err := transportgeneration.UnmarshalSignedGeneration(metadata)
	if err != nil {
		return generationRetirementInspection{}, fmt.Errorf(
			"validate retired FI generation metadata: %w",
			err,
		)
	}
	if signed.Descriptor.SourceID != sourceID {
		return generationRetirementInspection{}, fmt.Errorf(
			"retired FI generation source ID %q does not match configured source %q",
			signed.Descriptor.SourceID,
			sourceID,
		)
	}

	payloadPath := filepath.Join(
		path,
		transportgeneration.SealedGenerationPayloadName,
	)
	transfer, err := verifyGenerationRetirementTransfer(
		metadata,
		payloadPath,
		signed.Descriptor,
	)
	if err != nil {
		return generationRetirementInspection{}, err
	}

	expectedName := generationRetirementObjectName(transfer)
	if name != expectedName {
		return generationRetirementInspection{}, fmt.Errorf(
			"FI generation retirement tombstone name %q does not match verified transfer identity %q",
			name,
			expectedName,
		)
	}

	if transfer.MetadataBytes > ^uint64(0)-transfer.PayloadBytes {
		return generationRetirementInspection{}, errors.New(
			"FI generation retirement disk byte count overflow",
		)
	}

	return generationRetirementInspection{
		DiskBytes: transfer.MetadataBytes + transfer.PayloadBytes,
		Transfer:  transfer,
	}, nil
}

func readGenerationRetirementMetadata(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New(
			"FI generation retirement metadata must be a real regular file",
		)
	}
	if info.Size() <= 0 || info.Size() > generationRetirementMetadataMaxBytes {
		return nil, errors.New(
			"FI generation retirement metadata size is outside bounds",
		)
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
	if !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New(
			"FI generation retirement metadata changed while opening",
		)
	}

	value, readErr := io.ReadAll(io.LimitReader(
		file,
		generationRetirementMetadataMaxBytes+1,
	))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(value) == 0 || len(value) > generationRetirementMetadataMaxBytes {
		return nil, errors.New(
			"FI generation retirement metadata size changed while reading",
		)
	}
	if int64(len(value)) != info.Size() {
		return nil, errors.New(
			"FI generation retirement metadata byte count changed while reading",
		)
	}

	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(opened, after) || after.Size() != info.Size() {
		return nil, errors.New(
			"FI generation retirement metadata changed during read",
		)
	}

	return value, nil
}

func recoverGenerationReclamation(
	stageRoot string,
) (uint64, error) {
	entries, err := os.ReadDir(stageRoot)
	if err != nil {
		return 0, err
	}

	names := make([]string, 0)
	for _, entry := range entries {
		if !strings.HasPrefix(
			entry.Name(),
			generationReclaimingDirectoryPrefix,
		) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	var resumed uint64
	for _, name := range names {
		if err := validateGenerationRetirementObjectName(
			name,
			generationReclaimingDirectoryPrefix,
		); err != nil {
			return resumed, err
		}

		path := filepath.Join(stageRoot, name)
		info, err := os.Lstat(path)
		if err != nil {
			return resumed, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return resumed, fmt.Errorf(
				"FI generation reclamation path %q must name a real directory",
				name,
			)
		}

		removed, err := removeGenerationReclamationPath(path)
		if err != nil {
			return resumed, fmt.Errorf(
				"resume FI generation byte reclamation for %q: %w",
				name,
				err,
			)
		}
		if removed {
			resumed++
		}
	}

	return resumed, nil
}

// ReclaimGenerationRetirementTombstones verifies and removes generation bytes
// that have already crossed the exact recorded/already_recorded retirement
// boundary.
//
// A verified retirement directory is first renamed into a dedicated reclaiming
// namespace. The rename is the crash-safe point: restart recovery may finish
// deletion from that namespace without ever making the generation active again.
func ReclaimGenerationRetirementTombstones(
	stageRoot string,
	sourceID string,
) (GenerationReclamationResult, error) {
	if err := validateGenerationStageRoot(stageRoot); err != nil {
		return GenerationReclamationResult{}, err
	}
	if strings.TrimSpace(sourceID) == "" {
		return GenerationReclamationResult{}, errors.New(
			"FI generation source ID is required for retirement reclamation",
		)
	}

	resumed, err := recoverGenerationReclamation(stageRoot)
	if err != nil {
		return GenerationReclamationResult{}, err
	}
	result := GenerationReclamationResult{Resumed: resumed}

	entries, err := os.ReadDir(stageRoot)
	if err != nil {
		return result, err
	}

	names := make([]string, 0)
	for _, entry := range entries {
		if strings.HasPrefix(
			entry.Name(),
			generationRetiredDirectoryPrefix,
		) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		retiredPath := filepath.Join(stageRoot, name)
		inspection, err := inspectGenerationRetirementTombstone(
			retiredPath,
			sourceID,
		)
		if err != nil {
			return result, fmt.Errorf(
				"verify FI generation retirement tombstone %q before reclamation: %w",
				name,
				err,
			)
		}

		suffix := strings.TrimPrefix(
			name,
			generationRetiredDirectoryPrefix,
		)
		reclaimingName := generationReclaimingDirectoryPrefix + suffix
		reclaimingPath := filepath.Join(stageRoot, reclaimingName)

		if _, err := os.Lstat(reclaimingPath); err == nil {
			return result, fmt.Errorf(
				"FI generation reclamation found both retired and reclaiming objects for %q",
				name,
			)
		} else if !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf(
				"inspect FI generation reclaiming namespace for %q: %w",
				name,
				err,
			)
		}

		if err := publishGenerationDirectory(
			retiredPath,
			reclaimingPath,
		); err != nil {
			return result, fmt.Errorf(
				"publish FI generation reclamation boundary for %q: %w",
				name,
				err,
			)
		}

		removed, err := removeGenerationReclamationPath(reclaimingPath)
		if err != nil {
			return result, fmt.Errorf(
				"reclaim FI generation retirement bytes for %q: %w",
				name,
				err,
			)
		}
		if !removed {
			return result, fmt.Errorf(
				"FI generation reclamation object %q disappeared before cleanup completed",
				reclaimingName,
			)
		}

		if inspection.DiskBytes > ^uint64(0)-result.ReclaimedDiskBytes {
			return result, errors.New(
				"FI generation reclaimed disk byte counter overflow",
			)
		}
		result.Reclaimed++
		result.ReclaimedDiskBytes += inspection.DiskBytes
	}

	return result, nil
}

func validateGenerationRetirementObjectName(
	name string,
	prefix string,
) error {
	if !strings.HasPrefix(name, prefix) {
		return fmt.Errorf(
			"FI generation retirement object %q does not use required prefix %q",
			name,
			prefix,
		)
	}

	digest := strings.TrimPrefix(name, prefix)
	if len(digest) != sha256.Size*2 {
		return fmt.Errorf(
			"FI generation retirement object %q has invalid digest length",
			name,
		)
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != sha256.Size || digest != hex.EncodeToString(raw) {
		return fmt.Errorf(
			"FI generation retirement object %q has invalid lowercase SHA-256 identity",
			name,
		)
	}

	return nil
}

func verifyGenerationRetirementTransfer(
	metadata []byte,
	payloadPath string,
	descriptor transportgeneration.Descriptor,
) (transportgeneration.TransferResult, error) {
	if err := descriptor.Validate(); err != nil {
		return transportgeneration.TransferResult{}, err
	}
	if len(metadata) == 0 || uint64(len(metadata)) > uint64(^uint32(0)) {
		return transportgeneration.TransferResult{}, errors.New(
			"FI generation retirement metadata exceeds transfer framing range",
		)
	}

	initial, err := os.Lstat(payloadPath)
	if err != nil {
		return transportgeneration.TransferResult{}, err
	}
	if initial.Mode()&os.ModeSymlink != 0 ||
		!initial.Mode().IsRegular() ||
		initial.Size() <= 0 ||
		uint64(initial.Size()) != descriptor.EncodedDataBytes {
		return transportgeneration.TransferResult{}, errors.New(
			"retired FI generation payload structure does not match signed descriptor",
		)
	}

	payload, err := os.Open(payloadPath)
	if err != nil {
		return transportgeneration.TransferResult{}, err
	}
	opened, err := payload.Stat()
	if err != nil {
		_ = payload.Close()
		return transportgeneration.TransferResult{}, err
	}
	if !os.SameFile(initial, opened) {
		_ = payload.Close()
		return transportgeneration.TransferResult{}, errors.New(
			"retired FI generation payload changed while opening",
		)
	}

	var header [20]byte
	copy(header[0:8], []byte(transportgeneration.TransferMagic))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(metadata)))
	binary.BigEndian.PutUint64(header[12:20], descriptor.EncodedDataBytes)

	transferHasher := sha256.New()
	_, _ = transferHasher.Write(header[:])
	_, _ = transferHasher.Write(metadata)

	payloadHasher := sha256.New()
	written, copyErr := io.CopyN(
		io.MultiWriter(transferHasher, payloadHasher),
		payload,
		int64(descriptor.EncodedDataBytes),
	)
	if copyErr != nil {
		_ = payload.Close()
		return transportgeneration.TransferResult{}, fmt.Errorf(
			"hash retired FI generation payload: %w",
			copyErr,
		)
	}
	if uint64(written) != descriptor.EncodedDataBytes {
		_ = payload.Close()
		return transportgeneration.TransferResult{}, errors.New(
			"retired FI generation payload was short",
		)
	}

	var trailing [1]byte
	n, trailingErr := payload.Read(trailing[:])
	closeErr := payload.Close()
	if n != 0 || !errors.Is(trailingErr, io.EOF) {
		return transportgeneration.TransferResult{}, errors.New(
			"retired FI generation payload contains unexpected trailing bytes",
		)
	}
	if closeErr != nil {
		return transportgeneration.TransferResult{}, closeErr
	}

	after, err := os.Lstat(payloadPath)
	if err != nil {
		return transportgeneration.TransferResult{}, err
	}
	if !os.SameFile(opened, after) || after.Size() != initial.Size() {
		return transportgeneration.TransferResult{}, errors.New(
			"retired FI generation payload changed during verification",
		)
	}

	payloadSHA256 := hex.EncodeToString(payloadHasher.Sum(nil))
	if payloadSHA256 != descriptor.EncodedDataSHA256 {
		return transportgeneration.TransferResult{}, errors.New(
			"retired FI generation payload SHA-256 does not match signed descriptor",
		)
	}

	metadataDigest := sha256.Sum256(metadata)
	if uint64(len(metadata)) > ^uint64(0)-20 ||
		descriptor.EncodedDataBytes > ^uint64(0)-(20+uint64(len(metadata))) {
		return transportgeneration.TransferResult{}, errors.New(
			"FI generation retirement transfer byte count overflow",
		)
	}

	result := transportgeneration.TransferResult{
		Descriptor:     descriptor,
		MetadataBytes:  uint64(len(metadata)),
		MetadataSHA256: hex.EncodeToString(metadataDigest[:]),
		PayloadBytes:   descriptor.EncodedDataBytes,
		PayloadSHA256:  payloadSHA256,
		TransferBytes:  20 + uint64(len(metadata)) + descriptor.EncodedDataBytes,
		TransferSHA256: hex.EncodeToString(transferHasher.Sum(nil)),
	}
	if err := validateGenerationTransferResult(result); err != nil {
		return transportgeneration.TransferResult{}, err
	}

	return result, nil
}
