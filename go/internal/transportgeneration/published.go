// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationsealer"
)

const (
	SealedGenerationPayloadName = "payload.figz"

	sealedGenerationDirectoryPrefix = "generation-"
)

var ErrEncodedLimitExceeded = errors.New(
	"FI generation encoded payload exceeds configured sender limit",
)

type CreateConfig struct {
	BatchSigner             crypto.Signer
	BatchSigningCertificate *x509.Certificate

	FrozenDir string

	GenerationID string

	MaxEncodedBytes       uint64
	MaxReadBytesPerSecond uint64

	SealedRoot string
	SourceID   string
}

type PublishedGeneration struct {
	DirectoryPath string
	MetadataPath  string
	PayloadPath   string

	Signed SignedGeneration
}

// CreateSealedGeneration creates one immutable transport-generation object.
//
// The frozen directory remains authoritative until the caller separately
// decides that the published generation has replaced it. This function never
// removes the frozen source.
func CreateSealedGeneration(
	ctx context.Context,
	config CreateConfig,
) (
	PublishedGeneration,
	error,
) {
	if ctx == nil {
		return PublishedGeneration{},
			errors.New(
				"generation creation context is required",
			)
	}

	if err :=
		validateCreateConfig(
			config,
		); err != nil {
		return PublishedGeneration{}, err
	}

	if err :=
		os.MkdirAll(
			config.SealedRoot,
			0o700,
		); err != nil {
		return PublishedGeneration{},
			fmt.Errorf(
				"create FI sealed-generation root: %w",
				err,
			)
	}

	if err :=
		validateSealedGenerationRoot(
			config.SealedRoot,
		); err != nil {
		return PublishedGeneration{}, err
	}

	if err :=
		cleanupProvisionalGenerationDirectories(
			config.SealedRoot,
			config.GenerationID,
		); err != nil {
		return PublishedGeneration{}, err
	}

	finalDir :=
		filepath.Join(
			config.SealedRoot,
			sealedGenerationDirectoryPrefix+
				config.GenerationID,
		)

	if _,
		err :=
		os.Lstat(
			finalDir,
		); err == nil {
		existing, loadErr :=
			LoadSealedGeneration(
				finalDir,
			)

		if loadErr != nil {
			return PublishedGeneration{},
				fmt.Errorf(
					"load existing durable FI sealed generation: %w",
					loadErr,
				)
		}

		if existing.Signed.Descriptor.SourceID !=
			config.SourceID ||
			existing.Signed.Descriptor.GenerationID !=
				config.GenerationID {
			return PublishedGeneration{},
				errors.New(
					"existing durable FI sealed generation identity conflicts with requested generation",
				)
		}

		if err :=
			validateEncodedGenerationLimit(
				existing.Signed.Descriptor.EncodedDataBytes,
				config.MaxEncodedBytes,
			); err != nil {
			return PublishedGeneration{}, err
		}

		if err :=
			VerifyPublishedGenerationPayload(
				existing,
			); err != nil {
			return PublishedGeneration{},
				fmt.Errorf(
					"verify existing durable FI sealed generation payload: %w",
					err,
				)
		}

		return existing, nil
	} else if !errors.Is(
		err,
		fs.ErrNotExist,
	) {
		return PublishedGeneration{},
			fmt.Errorf(
				"inspect durable FI sealed generation path: %w",
				err,
			)
	}

	provisionalDir, err :=
		os.MkdirTemp(
			config.SealedRoot,
			".generation-"+
				config.GenerationID+
				"-*.open",
		)
	if err != nil {
		return PublishedGeneration{},
			fmt.Errorf(
				"create provisional FI sealed-generation directory: %w",
				err,
			)
	}

	keepProvisional :=
		false

	defer func() {
		if !keepProvisional {
			_ =
				os.RemoveAll(
					provisionalDir,
				)
		}
	}()

	sealResult, err :=
		generationsealer.Seal(
			ctx,
			generationsealer.Config{
				FrozenDir: config.FrozenDir,

				GenerationID: config.GenerationID,

				MaxReadBytesPerSecond: config.MaxReadBytesPerSecond,

				SealedDir: provisionalDir,
			},
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	if err :=
		validateEncodedGenerationLimit(
			sealResult.EncodedBytes,
			config.MaxEncodedBytes,
		); err != nil {
		return PublishedGeneration{}, err
	}

	descriptor, err :=
		DescriptorFromSeal(
			config.SourceID,
			sealResult,
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	signed, err :=
		NewSignedGeneration(
			descriptor,
			config.BatchSigningCertificate,
			config.BatchSigner,
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	metadataBytes, err :=
		MarshalSignedGeneration(
			signed,
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	payloadPath :=
		filepath.Join(
			provisionalDir,
			SealedGenerationPayloadName,
		)

	if err :=
		publishGenerationPayload(
			sealResult.SealedPath,
			payloadPath,
		); err != nil {
		return PublishedGeneration{},
			fmt.Errorf(
				"rename provisional FI generation payload: %w",
				err,
			)
	}

	payloadInfo, err :=
		os.Lstat(
			payloadPath,
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	if !payloadInfo.Mode().IsRegular() ||
		uint64(payloadInfo.Size()) !=
			descriptor.EncodedDataBytes {
		return PublishedGeneration{},
			errors.New(
				"provisional FI generation payload does not match signed byte count",
			)
	}

	metadataPath :=
		filepath.Join(
			provisionalDir,
			SignedGenerationMetadataName,
		)

	if err :=
		writeSyncedGenerationFile(
			metadataPath,
			metadataBytes,
		); err != nil {
		return PublishedGeneration{}, err
	}

	if err :=
		validateProvisionalGenerationDirectory(
			provisionalDir,
		); err != nil {
		return PublishedGeneration{}, err
	}

	if err :=
		publishGenerationDirectory(
			provisionalDir,
			finalDir,
		); err != nil {
		return PublishedGeneration{},
			fmt.Errorf(
				"publish durable FI sealed-generation directory: %w",
				err,
			)
	}

	keepProvisional =
		true

	published, err :=
		LoadSealedGeneration(
			finalDir,
		)
	if err != nil {
		return PublishedGeneration{},
			fmt.Errorf(
				"reload published FI sealed generation: %w",
				err,
			)
	}

	if published.Signed.Descriptor !=
		descriptor {
		return PublishedGeneration{},
			errors.New(
				"published FI sealed-generation descriptor changed after publication",
			)
	}

	if err :=
		VerifyPublishedGenerationPayload(
			published,
		); err != nil {
		return PublishedGeneration{},
			fmt.Errorf(
				"verify newly published FI sealed-generation payload: %w",
				err,
			)
	}

	return published, nil
}

// LoadSealedGeneration validates the durable generation structure and signed
// metadata without rereading the entire compressed payload.
//
// Exact payload hashing is deliberately separate so normal queue discovery does
// not reread a potentially very large generation on every scan.
func LoadSealedGeneration(
	directoryPath string,
) (
	PublishedGeneration,
	error,
) {
	if directoryPath == "" ||
		!filepath.IsAbs(
			directoryPath,
		) {
		return PublishedGeneration{},
			errors.New(
				"FI sealed-generation directory must be absolute",
			)
	}

	info, err :=
		os.Lstat(
			directoryPath,
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return PublishedGeneration{},
			errors.New(
				"FI sealed-generation path must name a real directory",
			)
	}

	entries, err :=
		os.ReadDir(
			directoryPath,
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	if len(entries) != 2 {
		return PublishedGeneration{},
			fmt.Errorf(
				"FI sealed-generation directory contains %d entries; expected exactly 2",
				len(entries),
			)
	}

	foundPayload :=
		false

	foundMetadata :=
		false

	for _, entry := range entries {
		if entry.Type()&
			os.ModeSymlink != 0 {
			return PublishedGeneration{},
				fmt.Errorf(
					"FI sealed-generation directory contains symlink %q",
					entry.Name(),
				)
		}

		switch entry.Name() {
		case SealedGenerationPayloadName:
			foundPayload = true

		case SignedGenerationMetadataName:
			foundMetadata = true

		default:
			return PublishedGeneration{},
				fmt.Errorf(
					"FI sealed-generation directory contains unexpected artifact %q",
					entry.Name(),
				)
		}
	}

	if !foundPayload ||
		!foundMetadata {
		return PublishedGeneration{},
			errors.New(
				"FI sealed-generation directory is incomplete",
			)
	}

	metadataPath :=
		filepath.Join(
			directoryPath,
			SignedGenerationMetadataName,
		)

	metadataBytes, err :=
		readStableBoundedGenerationFile(
			metadataPath,
			maxSignedGenerationMetadataBytes,
		)
	if err != nil {
		return PublishedGeneration{},
			fmt.Errorf(
				"read signed FI generation metadata: %w",
				err,
			)
	}

	signed, err :=
		UnmarshalSignedGeneration(
			metadataBytes,
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	expectedDirectoryName :=
		sealedGenerationDirectoryPrefix +
			signed.Descriptor.GenerationID

	if filepath.Base(
		filepath.Clean(
			directoryPath,
		),
	) != expectedDirectoryName {
		return PublishedGeneration{},
			fmt.Errorf(
				"FI sealed-generation directory name must be %q",
				expectedDirectoryName,
			)
	}

	payloadPath :=
		filepath.Join(
			directoryPath,
			SealedGenerationPayloadName,
		)

	payloadInfo, err :=
		os.Lstat(
			payloadPath,
		)
	if err != nil {
		return PublishedGeneration{}, err
	}

	if payloadInfo.Mode()&
		os.ModeSymlink != 0 ||
		!payloadInfo.Mode().IsRegular() {
		return PublishedGeneration{},
			errors.New(
				"FI sealed-generation payload must be a real regular file",
			)
	}

	if payloadInfo.Size() <= 0 ||
		uint64(
			payloadInfo.Size(),
		) !=
			signed.Descriptor.EncodedDataBytes {
		return PublishedGeneration{},
			errors.New(
				"FI sealed-generation payload byte count does not match signed descriptor",
			)
	}

	return PublishedGeneration{
		DirectoryPath: directoryPath,

		MetadataPath: metadataPath,

		PayloadPath: payloadPath,

		Signed: signed,
	}, nil
}

// VerifyPublishedGenerationPayload performs the expensive full encoded-payload
// hash verification.
//
// Callers use this when reconciling durable state after restart or immediately
// before retiring another authoritative copy. Queue discovery itself does not
// need to perform this full reread.
func VerifyPublishedGenerationPayload(
	generation PublishedGeneration,
) error {
	current, err :=
		LoadSealedGeneration(
			generation.DirectoryPath,
		)
	if err != nil {
		return err
	}

	if current.Signed.Descriptor !=
		generation.Signed.Descriptor {
		return errors.New(
			"FI sealed-generation descriptor changed before payload verification",
		)
	}

	initial, err :=
		os.Lstat(
			current.PayloadPath,
		)
	if err != nil {
		return err
	}

	if !initial.Mode().IsRegular() ||
		initial.Size() <= 0 {
		return errors.New(
			"FI sealed-generation payload is not a regular file",
		)
	}

	file, err :=
		os.Open(
			current.PayloadPath,
		)
	if err != nil {
		return err
	}

	opened, err :=
		file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}

	if !os.SameFile(
		initial,
		opened,
	) {
		_ = file.Close()

		return errors.New(
			"FI sealed-generation payload changed while opening",
		)
	}

	hasher :=
		sha256.New()

	counter :=
		&generationCountWriter{}

	_,
		copyErr :=
		io.Copy(
			io.MultiWriter(
				hasher,
				counter,
			),
			file,
		)

	closeErr :=
		file.Close()

	if copyErr != nil {
		return copyErr
	}

	if closeErr != nil {
		return closeErr
	}

	after, err :=
		os.Lstat(
			current.PayloadPath,
		)
	if err != nil {
		return err
	}

	if !os.SameFile(
		opened,
		after,
	) ||
		after.Size() !=
			initial.Size() {
		return errors.New(
			"FI sealed-generation payload changed during verification",
		)
	}

	descriptor :=
		current.Signed.Descriptor

	if counter.bytes !=
		descriptor.EncodedDataBytes {
		return errors.New(
			"FI sealed-generation payload byte count changed",
		)
	}

	actualSHA :=
		hex.EncodeToString(
			hasher.Sum(
				nil,
			),
		)

	if actualSHA !=
		descriptor.EncodedDataSHA256 {
		return errors.New(
			"FI sealed-generation encoded SHA-256 does not match signed descriptor",
		)
	}

	return nil
}

func cleanupProvisionalGenerationDirectories(
	root string,
	generationID string,
) error {
	entries, err :=
		os.ReadDir(
			root,
		)
	if err != nil {
		return err
	}

	prefix :=
		".generation-" +
			generationID +
			"-"

	for _, entry := range entries {
		name :=
			entry.Name()

		if !strings.HasPrefix(
			name,
			prefix,
		) ||
			!strings.HasSuffix(
				name,
				".open",
			) {
			continue
		}

		path :=
			filepath.Join(
				root,
				name,
			)

		info, err :=
			os.Lstat(
				path,
			)
		if err != nil {
			return err
		}

		if info.Mode()&
			os.ModeSymlink != 0 ||
			!info.IsDir() {
			return fmt.Errorf(
				"FI provisional sealed-generation path %q is not a real directory",
				path,
			)
		}

		if err :=
			os.RemoveAll(
				path,
			); err != nil {
			return fmt.Errorf(
				"remove abandoned FI provisional sealed generation %q: %w",
				path,
				err,
			)
		}
	}

	return nil
}

func readStableBoundedGenerationFile(
	path string,
	maxBytes int,
) (
	[]byte,
	error,
) {
	initial, err :=
		os.Lstat(
			path,
		)
	if err != nil {
		return nil, err
	}

	if initial.Mode()&
		os.ModeSymlink != 0 ||
		!initial.Mode().IsRegular() ||
		initial.Size() <= 0 ||
		initial.Size() >
			int64(
				maxBytes,
			) {
		return nil,
			errors.New(
				"FI generation metadata is not a bounded regular file",
			)
	}

	file, err :=
		os.Open(
			path,
		)
	if err != nil {
		return nil, err
	}

	opened, err :=
		file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	if !os.SameFile(
		initial,
		opened,
	) {
		_ = file.Close()

		return nil,
			errors.New(
				"FI generation metadata changed while opening",
			)
	}

	reader :=
		io.LimitReader(
			file,
			int64(maxBytes)+1,
		)

	raw, readErr :=
		io.ReadAll(
			reader,
		)

	closeErr :=
		file.Close()

	if readErr != nil {
		return nil, readErr
	}

	if closeErr != nil {
		return nil, closeErr
	}

	if len(raw) == 0 ||
		len(raw) >
			maxBytes {
		return nil,
			errors.New(
				"FI generation metadata size changed while reading",
			)
	}

	after, err :=
		os.Lstat(
			path,
		)
	if err != nil {
		return nil, err
	}

	if !os.SameFile(
		opened,
		after,
	) ||
		after.Size() !=
			initial.Size() {
		return nil,
			errors.New(
				"FI generation metadata changed during reading",
			)
	}

	return raw, nil
}

func validateCreateConfig(
	config CreateConfig,
) error {
	if err :=
		validateTextIdentity(
			"source ID",
			config.SourceID,
		); err != nil {
		return err
	}

	if err :=
		validateTextIdentity(
			"generation ID",
			config.GenerationID,
		); err != nil {
		return err
	}

	if strings.ContainsAny(
		config.GenerationID,
		"/\\",
	) {
		return errors.New(
			"generation ID must not contain path separators",
		)
	}

	if config.BatchSigner == nil ||
		config.BatchSigningCertificate == nil {
		return errors.New(
			"FI generation batch-signing identity is required",
		)
	}

	if config.FrozenDir == "" ||
		!filepath.IsAbs(
			config.FrozenDir,
		) {
		return errors.New(
			"FI frozen generation directory must be absolute",
		)
	}

	if config.SealedRoot == "" ||
		!filepath.IsAbs(
			config.SealedRoot,
		) {
		return errors.New(
			"FI sealed-generation root must be absolute",
		)
	}

	return nil
}

func validateEncodedGenerationLimit(
	encodedBytes uint64,
	maxEncodedBytes uint64,
) error {
	if maxEncodedBytes == 0 ||
		encodedBytes <= maxEncodedBytes {
		return nil
	}

	return fmt.Errorf(
		"%w: encoded=%d max=%d",
		ErrEncodedLimitExceeded,
		encodedBytes,
		maxEncodedBytes,
	)
}

func validateProvisionalGenerationDirectory(
	path string,
) error {
	entries, err :=
		os.ReadDir(
			path,
		)
	if err != nil {
		return err
	}

	if len(entries) != 2 {
		return fmt.Errorf(
			"provisional FI sealed-generation directory contains %d entries; expected exactly 2",
			len(entries),
		)
	}

	for _, entry := range entries {
		if entry.Type()&
			os.ModeSymlink != 0 {
			return errors.New(
				"provisional FI sealed-generation directory contains a symlink",
			)
		}

		switch entry.Name() {
		case SealedGenerationPayloadName,
			SignedGenerationMetadataName:

		default:
			return fmt.Errorf(
				"provisional FI sealed-generation directory contains unexpected artifact %q",
				entry.Name(),
			)
		}
	}

	return nil
}

func validateSealedGenerationRoot(
	path string,
) error {
	info, err :=
		os.Lstat(
			path,
		)
	if err != nil {
		return err
	}

	if info.Mode()&
		os.ModeSymlink != 0 ||
		!info.IsDir() {
		return errors.New(
			"FI sealed-generation root must name a real directory",
		)
	}

	return nil
}

func writeSyncedGenerationFile(
	path string,
	value []byte,
) error {
	file, err :=
		os.OpenFile(
			path,
			os.O_WRONLY|
				os.O_CREATE|
				os.O_EXCL,
			0o600,
		)
	if err != nil {
		return err
	}

	_, writeErr :=
		file.Write(
			value,
		)

	if writeErr != nil {
		_ = file.Close()
		return writeErr
	}

	if err :=
		file.Sync(); err != nil {
		_ = file.Close()
		return err
	}

	return file.Close()
}

type generationCountWriter struct {
	bytes uint64
}

func (
	writer *generationCountWriter,
) Write(
	value []byte,
) (
	int,
	error,
) {
	if uint64(
		len(value),
	) >
		^uint64(0)-
			writer.bytes {
		return 0,
			errors.New(
				"FI generation payload byte counter overflow",
			)
	}

	writer.bytes +=
		uint64(
			len(value),
		)

	return len(value), nil
}
