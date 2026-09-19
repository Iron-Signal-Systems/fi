// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportgeneration

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	generationCustodyFinalPrefix       = "generation-"
	generationCustodyFinalSuffix       = ".figt"
	generationCustodyProvisionalPrefix = ".fi-generation-custody-"
	generationCustodyProvisionalSuffix = ".open"
)

// DiscoveredCustody identifies one already-published generation custody object
// found during receiver restart recovery.
//
// Discovery proves only root/name/type/mode/size structure. The exact FIGT
// transfer, signing trust, encoded/canonical hashes, and collector semantics are
// revalidated when the object is opened for recorder processing.
type DiscoveredCustody struct {
	Bytes uint64
	Path  string
}

// CustodyRecoveryResult describes one restart recovery pass over the durable
// generation custody root.
type CustodyRecoveryResult struct {
	Objects            []DiscoveredCustody
	RemovedProvisional uint64
}

// CanonicalArtifactHandlerFactory creates the semantic artifact consumer after
// restart discovery has recovered the signed generation descriptor from the
// exact custody object.
type CanonicalArtifactHandlerFactory func(
	descriptor Descriptor,
) (
	CanonicalArtifactHandler,
	error,
)

// RecoverDurableCustodyRoot removes abandoned provisional .open names and
// returns the deterministic set of already-published generation custody
// objects that remain.
//
// A regular provisional .open file is never an authoritative custody identity,
// including the crash state where it is a second hard link to an already-
// published final object. Unknown entries, directories, symlinks, writable
// final objects, and malformed final names fail closed.
func RecoverDurableCustodyRoot(
	config CustodyConfig,
) (
	CustodyRecoveryResult,
	error,
) {
	if err := validateGenerationCustodyConfig(config); err != nil {
		return CustodyRecoveryResult{}, err
	}

	entries, err := os.ReadDir(config.RootDir)
	if err != nil {
		return CustodyRecoveryResult{}, fmt.Errorf(
			"read FI generation durable custody root: %w",
			err,
		)
	}

	result := CustodyRecoveryResult{}
	var provisional []string

	// Validate the complete directory state before mutating any abandoned
	// provisional names. An unexpected or unsafe entry therefore fails the
	// recovery pass without first changing an otherwise useful custody root.
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(config.RootDir, name)

		info, err := os.Lstat(path)
		if err != nil {
			return CustodyRecoveryResult{}, fmt.Errorf(
				"inspect FI generation custody restart entry %q: %w",
				name,
				err,
			)
		}

		if isGenerationCustodyProvisionalName(name) {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return CustodyRecoveryResult{}, fmt.Errorf(
					"FI generation provisional custody restart entry %q must be a regular file",
					name,
				)
			}

			provisional = append(provisional, path)
			continue
		}

		if !isGenerationCustodyFinalName(name) {
			return CustodyRecoveryResult{}, fmt.Errorf(
				"unexpected FI generation custody restart entry %q",
				name,
			)
		}

		if info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() ||
			info.Mode().Perm() != 0o400 {
			return CustodyRecoveryResult{}, fmt.Errorf(
				"FI generation custody restart object %q must be a read-only regular file",
				name,
			)
		}

		if info.Size() <= transferHeaderBytes {
			return CustodyRecoveryResult{}, fmt.Errorf(
				"FI generation custody restart object %q is too small",
				name,
			)
		}

		result.Objects = append(
			result.Objects,
			DiscoveredCustody{
				Bytes: uint64(info.Size()),
				Path:  path,
			},
		)
	}

	for _, path := range provisional {
		if err := os.Remove(path); err != nil {
			return CustodyRecoveryResult{}, fmt.Errorf(
				"remove abandoned FI generation provisional custody entry %q: %w",
				filepath.Base(path),
				err,
			)
		}
		result.RemovedProvisional++
	}

	if result.RemovedProvisional != 0 {
		if err := syncGenerationCustodyDirectory(config.RootDir); err != nil {
			return CustodyRecoveryResult{}, fmt.Errorf(
				"sync FI generation custody root after restart cleanup: %w",
				err,
			)
		}
	}

	return result, nil
}

// ReadDiscoveredDurableCustodyArtifacts reopens one restart-discovered custody
// object and streams its canonical artifacts exactly once through a semantic
// handler while the complete FIGT transfer and current signing trust are
// revalidated.
//
// Only the small wire header and signed metadata are read before the full pass;
// the encoded payload itself is not prehashed or decompressed twice.
func ReadDiscoveredDurableCustodyArtifacts(
	discovered DiscoveredCustody,
	config CustodyConfig,
	factory CanonicalArtifactHandlerFactory,
) (
	CustodyResult,
	error,
) {
	if factory == nil {
		return CustodyResult{}, errors.New(
			"FI generation discovered custody artifact handler factory is required",
		)
	}

	if err := validateGenerationCustodyConfig(config); err != nil {
		return CustodyResult{}, err
	}

	if err := validateDiscoveredCustody(discovered, config.RootDir); err != nil {
		return CustodyResult{}, err
	}

	before, err := os.Lstat(discovered.Path)
	if err != nil {
		return CustodyResult{}, fmt.Errorf(
			"inspect discovered FI generation custody object: %w",
			err,
		)
	}

	if err := validateGenerationCustodyFileInfo(before, discovered.Bytes); err != nil {
		return CustodyResult{}, err
	}

	file, err := os.Open(discovered.Path)
	if err != nil {
		return CustodyResult{}, fmt.Errorf(
			"open discovered FI generation custody object: %w",
			err,
		)
	}

	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return CustodyResult{}, fmt.Errorf(
			"stat opened discovered FI generation custody object: %w",
			err,
		)
	}

	if !os.SameFile(before, opened) {
		_ = file.Close()
		return CustodyResult{}, errors.New(
			"discovered FI generation custody object changed while being opened",
		)
	}

	offer, err := readDiscoveredCustodyOffer(file, discovered)
	if err != nil {
		_ = file.Close()
		return CustodyResult{}, err
	}

	expectedName := generationCustodyObjectName(
		offer.Descriptor.SourceID,
		offer.Descriptor.GenerationID,
	)

	if filepath.Base(discovered.Path) != expectedName {
		_ = file.Close()
		return CustodyResult{}, errors.New(
			"discovered FI generation custody filename does not match signed generation identity",
		)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return CustodyResult{}, fmt.Errorf(
			"rewind discovered FI generation custody object: %w",
			err,
		)
	}

	handler, err := factory(offer.Descriptor)
	if err != nil {
		_ = file.Close()
		return CustodyResult{}, fmt.Errorf(
			"create FI generation discovered custody artifact handler: %w",
			err,
		)
	}

	if handler == nil {
		_ = file.Close()
		return CustodyResult{}, errors.New(
			"FI generation discovered custody artifact handler is required",
		)
	}

	transfer, readErr := readValidatedTransfer(
		file,
		offer,
		config.Receive,
		handler,
	)

	var extra [1]byte
	extraCount, extraErr := file.Read(extra[:])
	closeErr := file.Close()

	if readErr != nil {
		return CustodyResult{}, fmt.Errorf(
			"revalidate discovered FI generation custody transfer: %w",
			readErr,
		)
	}

	if extraCount != 0 || !errors.Is(extraErr, io.EOF) {
		return CustodyResult{}, errors.New(
			"discovered FI generation custody object contains trailing transfer bytes",
		)
	}

	if closeErr != nil {
		return CustodyResult{}, fmt.Errorf(
			"close discovered FI generation custody object: %w",
			closeErr,
		)
	}

	if transfer.TransferBytes != discovered.Bytes {
		return CustodyResult{}, errors.New(
			"discovered FI generation custody byte count changed during recorder read",
		)
	}

	after, err := os.Lstat(discovered.Path)
	if err != nil {
		return CustodyResult{}, fmt.Errorf(
			"reinspect discovered FI generation custody object: %w",
			err,
		)
	}

	if !os.SameFile(before, after) {
		return CustodyResult{}, errors.New(
			"discovered FI generation custody object changed during recorder read",
		)
	}

	if err := validateGenerationCustodyFileInfo(after, discovered.Bytes); err != nil {
		return CustodyResult{}, err
	}

	return newGenerationCustodyResult(
		transfer,
		discovered.Path,
		CustodyDispositionExisting,
	), nil
}

func isGenerationCustodyFinalName(
	name string,
) bool {
	if !strings.HasPrefix(name, generationCustodyFinalPrefix) ||
		!strings.HasSuffix(name, generationCustodyFinalSuffix) {
		return false
	}

	hexValue := strings.TrimSuffix(
		strings.TrimPrefix(name, generationCustodyFinalPrefix),
		generationCustodyFinalSuffix,
	)

	if len(hexValue) != sha256.Size*2 || strings.ToLower(hexValue) != hexValue {
		return false
	}

	decoded, err := hex.DecodeString(hexValue)
	return err == nil && len(decoded) == sha256.Size
}

func isGenerationCustodyProvisionalName(
	name string,
) bool {
	return strings.HasPrefix(name, generationCustodyProvisionalPrefix) &&
		strings.HasSuffix(name, generationCustodyProvisionalSuffix)
}

func readDiscoveredCustodyOffer(
	file *os.File,
	discovered DiscoveredCustody,
) (
	Offer,
	error,
) {
	if file == nil {
		return Offer{}, errors.New(
			"FI generation discovered custody file is required",
		)
	}

	var header [transferHeaderBytes]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return Offer{}, fmt.Errorf(
			"read discovered FI generation transfer header: %w",
			err,
		)
	}

	if string(header[0:8]) != TransferMagic {
		return Offer{}, errors.New(
			"unexpected discovered FI generation transfer magic",
		)
	}

	metadataBytes := uint64(binary.BigEndian.Uint32(header[8:12]))
	payloadBytes := binary.BigEndian.Uint64(header[12:20])

	if metadataBytes == 0 || metadataBytes > uint64(maxSignedGenerationMetadataBytes) {
		return Offer{}, errors.New(
			"discovered FI generation metadata byte count is outside bounds",
		)
	}

	expectedBytes := uint64(transferHeaderBytes)
	if metadataBytes > ^uint64(0)-expectedBytes {
		return Offer{}, errors.New(
			"discovered FI generation transfer byte count overflow",
		)
	}
	expectedBytes += metadataBytes

	if payloadBytes > ^uint64(0)-expectedBytes {
		return Offer{}, errors.New(
			"discovered FI generation transfer byte count overflow",
		)
	}
	expectedBytes += payloadBytes

	if expectedBytes != discovered.Bytes {
		return Offer{}, errors.New(
			"discovered FI generation custody size does not match wire framing",
		)
	}

	metadata := make([]byte, int(metadataBytes))
	if _, err := io.ReadFull(file, metadata); err != nil {
		return Offer{}, fmt.Errorf(
			"read discovered FI generation signed metadata: %w",
			err,
		)
	}

	digest := sha256.Sum256(metadata)
	signed, err := UnmarshalSignedGeneration(metadata)
	if err != nil {
		return Offer{}, fmt.Errorf(
			"validate discovered FI generation signed metadata: %w",
			err,
		)
	}

	if payloadBytes != signed.Descriptor.EncodedDataBytes {
		return Offer{}, errors.New(
			"discovered FI generation payload byte count does not match signed descriptor",
		)
	}

	offer := Offer{
		Version:        OfferVersion,
		Descriptor:     signed.Descriptor,
		MetadataBytes:  metadataBytes,
		MetadataSHA256: hex.EncodeToString(digest[:]),
	}

	if err := offer.Validate(); err != nil {
		return Offer{}, fmt.Errorf(
			"validate discovered FI generation offer identity: %w",
			err,
		)
	}

	return offer, nil
}

func validateDiscoveredCustody(
	discovered DiscoveredCustody,
	root string,
) error {
	if discovered.Path == "" {
		return errors.New(
			"FI generation discovered custody path is required",
		)
	}

	if discovered.Bytes <= transferHeaderBytes {
		return errors.New(
			"FI generation discovered custody byte count is outside bounds",
		)
	}

	if !filepath.IsAbs(discovered.Path) {
		return errors.New(
			"FI generation discovered custody path must be absolute",
		)
	}

	if filepath.Clean(filepath.Dir(discovered.Path)) != filepath.Clean(root) {
		return errors.New(
			"FI generation discovered custody path is outside configured custody root",
		)
	}

	if !isGenerationCustodyFinalName(filepath.Base(discovered.Path)) {
		return errors.New(
			"FI generation discovered custody filename is invalid",
		)
	}

	return nil
}
