// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const generationTransportBuildRootDirectoryName = ".fi-generation-build"

// TransportGeneration is one semantic-free durable transport object.
type TransportGeneration struct {
	GenerationDir string
	GenerationID  string

	Published transportgeneration.PublishedGeneration
}

// BuildRawTransportGeneration converts one already-frozen raw spool generation
// into the semantic-free transportgeneration representation.
//
// The complete signed generation is first built below a private build root that
// is invisible to NextTransportGeneration. Only after the exact durable payload
// verifies is the frozen raw generation retired. The complete built directory is
// then atomically promoted into the active generation queue. A crash after raw
// retirement but before promotion is recovered by RecoverTransportGenerationBuilds.
func BuildRawTransportGeneration(
	ctx context.Context,
	config GenerationSealConfig,
	raw RawGeneration,
) (
	TransportGeneration,
	error,
) {
	if ctx == nil {
		return TransportGeneration{}, errors.New(
			"FI transport generation build context is required",
		)
	}

	if err := validateGenerationSealConfig(config); err != nil {
		return TransportGeneration{}, err
	}

	physicalSpoolPath, err := spool.PhysicalSpoolPath(config.SpoolDir)
	if err != nil {
		return TransportGeneration{}, fmt.Errorf(
			"resolve physical FI spool path for transport-generation validation: %w",
			err,
		)
	}

	rawRoot := filepath.Join(
		filepath.Dir(physicalSpoolPath),
		generationRawRootDirectoryName,
	)

	if err := validateRawGeneration(raw, rawRoot); err != nil {
		return TransportGeneration{}, err
	}

	buildRoot, err := ensureTransportGenerationBuildRoot(config.StageRoot)
	if err != nil {
		return TransportGeneration{}, err
	}

	finalDir := filepath.Join(
		config.StageRoot,
		generationDirectoryPrefix+raw.GenerationID,
	)
	builtDir := filepath.Join(
		buildRoot,
		generationDirectoryPrefix+raw.GenerationID,
	)

	if _, err := os.Lstat(finalDir); err == nil {
		if _, builtErr := os.Lstat(builtDir); builtErr == nil {
			return TransportGeneration{}, errors.New(
				"FI transport generation exists in both private and active namespaces",
			)
		} else if !errors.Is(builtErr, os.ErrNotExist) {
			return TransportGeneration{}, fmt.Errorf(
				"inspect private FI transport generation during reconciliation: %w",
				builtErr,
			)
		}

		generation, loadErr := loadTransportGenerationAt(
			finalDir,
			config.SourceID,
			raw.GenerationID,
			config.MaxEncodedBytes,
		)
		if loadErr != nil {
			return TransportGeneration{}, fmt.Errorf(
				"load already-promoted FI transport generation: %w",
				loadErr,
			)
		}

		if err := removeRawGenerationDirectory(raw); err != nil {
			return TransportGeneration{}, fmt.Errorf(
				"retire reconciled frozen FI generation: %w",
				err,
			)
		}

		return generation, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return TransportGeneration{}, fmt.Errorf(
			"inspect promoted FI transport generation: %w",
			err,
		)
	}

	published, err := transportgeneration.CreateSealedGeneration(
		ctx,
		transportgeneration.CreateConfig{
			BatchSigner:             config.BatchSigner,
			BatchSigningCertificate: config.BatchSigningCertificate,
			FrozenDir:               raw.GenerationDir,
			GenerationID:            raw.GenerationID,
			MaxEncodedBytes:         config.MaxEncodedBytes,
			SealedRoot:              buildRoot,
			SourceID:                config.SourceID,
		},
	)
	if err != nil {
		return TransportGeneration{}, fmt.Errorf(
			"build semantic-free FI transport generation: %w",
			err,
		)
	}

	if err := validateTransportGenerationIdentity(
		published,
		config.SourceID,
		raw.GenerationID,
		config.MaxEncodedBytes,
	); err != nil {
		return TransportGeneration{}, err
	}

	if err := removeRawGenerationDirectory(raw); err != nil {
		return TransportGeneration{}, fmt.Errorf(
			"retire frozen FI generation after durable semantic-free build: %w",
			err,
		)
	}

	if err := publishGenerationDirectory(published.DirectoryPath, finalDir); err != nil {
		return TransportGeneration{}, fmt.Errorf(
			"promote built FI transport generation into active queue: %w",
			err,
		)
	}

	generation, err := loadTransportGenerationAt(
		finalDir,
		config.SourceID,
		raw.GenerationID,
		0,
	)
	if err != nil {
		return TransportGeneration{}, fmt.Errorf(
			"reload promoted FI transport generation: %w",
			err,
		)
	}

	return generation, nil
}

// NextTransportGeneration returns the oldest complete durable generation.
//
// Discovery validates signed metadata and structural payload facts but does not
// reread or hash the entire payload merely to select the oldest object.
func NextTransportGeneration(
	stageRoot string,
	sourceID string,
) (
	TransportGeneration,
	bool,
	error,
) {
	if err := validateGenerationStageRoot(stageRoot); err != nil {
		return TransportGeneration{}, false, err
	}

	if strings.TrimSpace(sourceID) == "" {
		return TransportGeneration{}, false, errors.New(
			"FI generation source ID is required",
		)
	}

	entries, err := os.ReadDir(stageRoot)
	if err != nil {
		return TransportGeneration{}, false, err
	}

	names := make([]string, 0)

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), generationDirectoryPrefix) {
			continue
		}

		if entry.Type()&os.ModeSymlink != 0 {
			return TransportGeneration{}, false, fmt.Errorf(
				"FI generation queue contains symlink %q",
				entry.Name(),
			)
		}

		if !entry.IsDir() {
			return TransportGeneration{}, false, fmt.Errorf(
				"FI generation queue entry %q is not a directory",
				entry.Name(),
			)
		}

		names = append(names, entry.Name())
	}

	if len(names) == 0 {
		return TransportGeneration{}, false, nil
	}

	sort.Strings(names)

	name := names[0]
	generationDir := filepath.Join(stageRoot, name)
	generationID := strings.TrimPrefix(name, generationDirectoryPrefix)

	generation, err := loadTransportGenerationAt(
		generationDir,
		sourceID,
		generationID,
		0,
	)
	if err != nil {
		return TransportGeneration{}, false, fmt.Errorf(
			"load oldest FI transport generation: %w",
			err,
		)
	}

	return generation, true, nil
}

// RecoverTransportGenerationBuilds completes crash-safe local generation
// publication before the network queue is allowed to send anything.
//
// A complete object under the private build root is authoritative enough to
// retire its matching raw generation only after full payload verification. It
// is then atomically promoted into the active queue. Already-promoted objects
// are also reconciled against any matching raw directory left by an interrupted
// earlier transition.
func RecoverTransportGenerationBuilds(
	rawRoot string,
	stageRoot string,
	sourceID string,
	maxEncodedBytes uint64,
) error {
	if err := validateRawGenerationRoot(rawRoot); err != nil {
		return err
	}

	if err := validateGenerationStageRoot(stageRoot); err != nil {
		return err
	}

	if strings.TrimSpace(sourceID) == "" {
		return errors.New("FI generation source ID is required")
	}

	if maxEncodedBytes == 0 {
		return errors.New("FI generation encoded byte ceiling must be greater than zero")
	}

	buildRoot, err := ensureTransportGenerationBuildRoot(stageRoot)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(buildRoot)
	if err != nil {
		return err
	}

	names := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()

		if strings.HasPrefix(name, ".generation-") &&
			strings.HasSuffix(name, ".open") {
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				return fmt.Errorf(
					"FI transport-generation provisional build %q is not a real directory",
					name,
				)
			}
			continue
		}

		if !strings.HasPrefix(name, generationDirectoryPrefix) {
			return fmt.Errorf(
				"FI transport-generation build root contains unexpected entry %q",
				name,
			)
		}

		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return fmt.Errorf(
				"FI transport-generation build %q is not a real directory",
				name,
			)
		}

		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		generationID := strings.TrimPrefix(name, generationDirectoryPrefix)
		builtDir := filepath.Join(buildRoot, name)
		finalDir := filepath.Join(stageRoot, name)

		if _, err := os.Lstat(finalDir); err == nil {
			return fmt.Errorf(
				"FI transport-generation recovery found both private and active generation %q",
				generationID,
			)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf(
				"inspect active FI transport generation during build recovery: %w",
				err,
			)
		}

		if _, err := loadTransportGenerationAt(
			builtDir,
			sourceID,
			generationID,
			maxEncodedBytes,
		); err != nil {
			return fmt.Errorf(
				"verify private FI transport generation during recovery: %w",
				err,
			)
		}

		raw := RawGeneration{
			GenerationDir: filepath.Join(rawRoot, name),
			GenerationID:  generationID,
		}

		if _, err := os.Lstat(raw.GenerationDir); err == nil {
			if err := validateRawGeneration(raw, rawRoot); err != nil {
				return err
			}

			if err := removeRawGenerationDirectory(raw); err != nil {
				return fmt.Errorf(
					"retire frozen FI generation during transport-build recovery: %w",
					err,
				)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf(
				"inspect frozen FI generation during transport-build recovery: %w",
				err,
			)
		}

		if err := publishGenerationDirectory(builtDir, finalDir); err != nil {
			return fmt.Errorf(
				"promote recovered FI transport generation: %w",
				err,
			)
		}
	}

	rawEntries, err := os.ReadDir(rawRoot)
	if err != nil {
		return err
	}

	for _, entry := range rawEntries {
		name := entry.Name()
		if !strings.HasPrefix(name, generationDirectoryPrefix) {
			continue
		}

		generationID := strings.TrimPrefix(name, generationDirectoryPrefix)
		finalDir := filepath.Join(stageRoot, name)
		if _, err := os.Lstat(finalDir); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf(
				"inspect active FI transport generation during raw reconciliation: %w",
				err,
			)
		}

		if _, err := loadTransportGenerationAt(
			finalDir,
			sourceID,
			generationID,
			maxEncodedBytes,
		); err != nil {
			return fmt.Errorf(
				"verify active FI transport generation during raw reconciliation: %w",
				err,
			)
		}

		raw := RawGeneration{
			GenerationDir: filepath.Join(rawRoot, name),
			GenerationID:  generationID,
		}

		if err := validateRawGeneration(raw, rawRoot); err != nil {
			return err
		}

		if err := removeRawGenerationDirectory(raw); err != nil {
			return fmt.Errorf(
				"retire reconciled frozen FI generation: %w",
				err,
			)
		}
	}

	return nil
}

// SendTransportGeneration streams the exact already-published generation.
//
// It does not interpret collector batches, rebuild the generation, recompress
// the payload or re-marshal the signed metadata.
func SendTransportGeneration(
	writer io.Writer,
	generation TransportGeneration,
) (
	transportgeneration.TransferResult,
	error,
) {
	if generation.GenerationDir == "" ||
		generation.GenerationID == "" {
		return transportgeneration.TransferResult{}, errors.New(
			"FI transport generation identity is required",
		)
	}

	if generation.Published.DirectoryPath != generation.GenerationDir ||
		generation.Published.Signed.Descriptor.GenerationID != generation.GenerationID {
		return transportgeneration.TransferResult{}, errors.New(
			"FI transport generation in-memory identity is inconsistent",
		)
	}

	result, err := transportgeneration.WritePublishedGeneration(
		writer,
		generation.Published,
	)
	if err != nil {
		return transportgeneration.TransferResult{}, err
	}

	return result, nil
}

func ensureTransportGenerationBuildRoot(
	stageRoot string,
) (string, error) {
	if err := validateGenerationStageRoot(stageRoot); err != nil {
		return "", err
	}

	buildRoot := filepath.Join(
		stageRoot,
		generationTransportBuildRootDirectoryName,
	)

	if err := os.MkdirAll(buildRoot, 0o700); err != nil {
		return "", fmt.Errorf(
			"create FI transport-generation private build root: %w",
			err,
		)
	}

	info, err := os.Lstat(buildRoot)
	if err != nil {
		return "", fmt.Errorf(
			"inspect FI transport-generation private build root: %w",
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New(
			"FI transport-generation private build root must name a real directory",
		)
	}

	return buildRoot, nil
}

func loadTransportGenerationAt(
	generationDir string,
	sourceID string,
	generationID string,
	maxEncodedBytes uint64,
) (TransportGeneration, error) {
	published, err := transportgeneration.LoadSealedGeneration(generationDir)
	if err != nil {
		return TransportGeneration{}, err
	}

	if err := validateTransportGenerationIdentity(
		published,
		sourceID,
		generationID,
		maxEncodedBytes,
	); err != nil {
		return TransportGeneration{}, err
	}

	if maxEncodedBytes > 0 {
		if err := transportgeneration.VerifyPublishedGenerationPayload(published); err != nil {
			return TransportGeneration{}, err
		}
	}

	return TransportGeneration{
		GenerationDir: generationDir,
		GenerationID:  generationID,
		Published:     published,
	}, nil
}

func validateTransportGenerationIdentity(
	published transportgeneration.PublishedGeneration,
	sourceID string,
	generationID string,
	maxEncodedBytes uint64,
) error {
	descriptor := published.Signed.Descriptor

	if descriptor.SourceID != sourceID {
		return fmt.Errorf(
			"FI transport generation source ID %q does not match configured source %q",
			descriptor.SourceID,
			sourceID,
		)
	}

	if descriptor.GenerationID != generationID {
		return errors.New(
			"FI transport generation directory identity does not match signed descriptor",
		)
	}

	if maxEncodedBytes > 0 &&
		descriptor.EncodedDataBytes > maxEncodedBytes {
		return fmt.Errorf(
			"%w: encoded=%d max=%d",
			transportgeneration.ErrEncodedLimitExceeded,
			descriptor.EncodedDataBytes,
			maxEncodedBytes,
		)
	}

	return nil
}
