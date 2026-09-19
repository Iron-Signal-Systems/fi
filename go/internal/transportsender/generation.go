// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"crypto"
	"crypto/x509"
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

const generationDirectoryPrefix = "generation-"
const generationRawRootDirectoryName = "generation-raw"
const generationRolloverNextPrefix = ".fi-spool-next-"

type GenerationSealConfig struct {
	BatchSigner             crypto.Signer
	BatchSigningCertificate *x509.Certificate
	MaxEncodedBytes         uint64
	SourceID                string
	SpoolDir                string
	StageRoot               string
}

type RawGeneration struct {
	GenerationDir string
	GenerationID  string
}

// EnsureGenerationRawRoot creates and validates the sibling directory that
// holds immutable raw spool generations. It must be on the same filesystem as
// the active spool so rollover is a directory rename rather than a data copy.
func EnsureGenerationRawRoot(
	spoolDir string,
) (
	string,
	error,
) {
	physicalSpoolPath, err :=
		spool.PhysicalSpoolPath(
			spoolDir,
		)
	if err != nil {
		return "", fmt.Errorf(
			"resolve physical FI generation spool path: %w",
			err,
		)
	}

	parent :=
		filepath.Dir(
			physicalSpoolPath,
		)

	parentInfo, err :=
		os.Lstat(
			parent,
		)
	if err != nil {
		return "", fmt.Errorf(
			"inspect FI generation spool parent: %w",
			err,
		)
	}

	if parentInfo.Mode()&os.ModeSymlink != 0 ||
		!parentInfo.IsDir() {
		return "", errors.New(
			"FI generation spool parent must be a real directory",
		)
	}

	rawRoot :=
		filepath.Join(
			parent,
			generationRawRootDirectoryName,
		)

	if err :=
		os.MkdirAll(
			rawRoot,
			0o700,
		); err != nil {
		return "", fmt.Errorf(
			"create FI raw-generation root: %w",
			err,
		)
	}

	if err :=
		validateRawGenerationRoot(
			rawRoot,
		); err != nil {
		return "", err
	}

	return rawRoot, nil
}

// NextRawGeneration returns the oldest frozen raw generation without opening
// or hashing its member payloads. Compression/building is a separate operation.
func NextRawGeneration(rawRoot string) (RawGeneration, bool, error) {
	if err := validateRawGenerationRoot(rawRoot); err != nil {
		return RawGeneration{}, false, err
	}
	entries, err := os.ReadDir(rawRoot)
	if err != nil {
		return RawGeneration{}, false, err
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), generationDirectoryPrefix) {
			continue
		}
		names = append(names, entry.Name())
	}
	if len(names) == 0 {
		return RawGeneration{}, false, nil
	}
	sort.Strings(names)
	name := names[0]
	generationID := strings.TrimPrefix(name, generationDirectoryPrefix)
	if generationID == "" {
		return RawGeneration{}, false, errors.New("FI raw generation has empty identity")
	}
	raw := RawGeneration{
		GenerationDir: filepath.Join(rawRoot, name),
		GenerationID:  generationID,
	}
	if err := validateRawGeneration(raw, rawRoot); err != nil {
		return RawGeneration{}, false, err
	}
	return raw, true, nil
}

// RolloverPublishedSpool freezes the entire active spool with one directory
// rename while holding the same publication guard used by collector writers.
// A new empty directory is immediately promoted back to the original spool path
// before the guard is released. Compression and transport happen later and are
// not part of this critical section.
func RolloverPublishedSpool(
	spoolDir string,
) (raw RawGeneration, found bool, returnErr error) {
	physicalSpoolDir, err :=
		spool.PhysicalSpoolPath(
			spoolDir,
		)
	if err != nil {
		return RawGeneration{}, false, fmt.Errorf(
			"resolve physical FI active spool path for rollover: %w",
			err,
		)
	}

	guard, err :=
		spool.AcquirePublishBoundary()
	if err != nil {
		return RawGeneration{}, false, fmt.Errorf(
			"acquire FI spool rollover boundary: %w",
			err,
		)
	}

	defer func() {
		returnErr =
			errors.Join(
				returnErr,
				guard.Close(),
			)
	}()

	if err :=
		recoverInterruptedRolloverLocked(
			physicalSpoolDir,
		); err != nil {
		return RawGeneration{}, false, fmt.Errorf(
			"recover interrupted FI spool rollover: %w",
			err,
		)
	}

	if err :=
		validateRecoverySpoolDir(
			physicalSpoolDir,
		); err != nil {
		return RawGeneration{}, false, err
	}

	rawRoot, err :=
		EnsureGenerationRawRoot(
			physicalSpoolDir,
		)
	if err != nil {
		return RawGeneration{}, false, err
	}

	if err :=
		cleanupRolloverNextDirectories(
			physicalSpoolDir,
		); err != nil {
		return RawGeneration{}, false, err
	}

	if _, err :=
		spool.RecoverInterruptedPublicationsLocked(
			physicalSpoolDir,
		); err != nil {
		return RawGeneration{}, false, fmt.Errorf(
			"recover interrupted FI spool publication before rollover: %w",
			err,
		)
	}

	pairs, err :=
		spool.ValidatePublishedSpoolStructureLocked(
			physicalSpoolDir,
		)
	if err != nil {
		return RawGeneration{}, false, fmt.Errorf(
			"validate FI active spool structure before rollover: %w",
			err,
		)
	}

	if pairs == 0 {
		return RawGeneration{}, false, nil
	}

	generationID, err :=
		transportgeneration.NewGenerationID()
	if err != nil {
		return RawGeneration{}, false, fmt.Errorf(
			"create FI generation ID: %w",
			err,
		)
	}

	parent :=
		filepath.Dir(
			physicalSpoolDir,
		)

	nextDir :=
		filepath.Join(
			parent,
			generationRolloverNextPrefix+
				generationID,
		)

	if err :=
		os.Mkdir(
			nextDir,
			0o700,
		); err != nil {
		return RawGeneration{}, false, fmt.Errorf(
			"create next FI active-spool directory: %w",
			err,
		)
	}

	keepNext :=
		true

	defer func() {
		if keepNext {
			_ =
				os.Remove(
					nextDir,
				)
		}
	}()

	rawDir :=
		filepath.Join(
			rawRoot,
			generationDirectoryPrefix+
				generationID,
		)

	if err :=
		publishGenerationDirectory(
			physicalSpoolDir,
			rawDir,
		); err != nil {
		return RawGeneration{}, false, fmt.Errorf(
			"freeze FI active spool generation: %w",
			err,
		)
	}

	if err :=
		publishGenerationDirectory(
			nextDir,
			physicalSpoolDir,
		); err != nil {

		rollbackErr :=
			publishGenerationDirectory(
				rawDir,
				physicalSpoolDir,
			)

		if rollbackErr == nil {
			return RawGeneration{}, false, fmt.Errorf(
				"promote replacement FI active spool: %w",
				err,
			)
		}

		return RawGeneration{}, false, errors.Join(
			fmt.Errorf(
				"promote replacement FI active spool: %w",
				err,
			),
			fmt.Errorf(
				"rollback frozen FI active spool: %w",
				rollbackErr,
			),
		)
	}

	keepNext =
		false

	return RawGeneration{
		GenerationDir: rawDir,
		GenerationID:  generationID,
	}, true, nil
}

// recoverInterruptedRolloverLocked repairs the namespace state created by a
// crash after the active spool was frozen but before the empty replacement
// directory was promoted.
//
// The caller MUST hold the FI publication boundary.
//
// Recovery never moves the frozen generation back into service. The already
// frozen generation remains immutable under generation-raw, while its matching
// empty rollover-next directory becomes the new active spool.
func recoverInterruptedRolloverLocked(
	physicalSpoolDir string,
) error {
	activeInfo, err :=
		os.Lstat(
			physicalSpoolDir,
		)

	if err == nil {
		if activeInfo.Mode()&os.ModeSymlink != 0 ||
			!activeInfo.IsDir() {
			return errors.New(
				"FI physical active spool must name a real directory",
			)
		}

		return nil
	}

	if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		return fmt.Errorf(
			"inspect FI physical active spool during rollover recovery: %w",
			err,
		)
	}

	parent :=
		filepath.Dir(
			filepath.Clean(
				physicalSpoolDir,
			),
		)

	entries, err :=
		os.ReadDir(
			parent,
		)
	if err != nil {
		return fmt.Errorf(
			"scan FI spool parent for interrupted rollover: %w",
			err,
		)
	}

	var nextNames []string

	for _, entry := range entries {

		if !strings.HasPrefix(
			entry.Name(),
			generationRolloverNextPrefix,
		) {
			continue
		}

		info, err :=
			entry.Info()
		if err != nil {
			return fmt.Errorf(
				"inspect FI rollover-next recovery directory: %w",
				err,
			)
		}

		if info.Mode()&os.ModeSymlink != 0 ||
			!info.IsDir() {
			return fmt.Errorf(
				"FI rollover-next recovery path %q is not a real directory",
				entry.Name(),
			)
		}

		nextNames =
			append(
				nextNames,
				entry.Name(),
			)
	}

	if len(nextNames) != 1 {
		return fmt.Errorf(
			"FI active spool is missing with %d rollover-next recovery directories; expected exactly 1",
			len(nextNames),
		)
	}

	nextName :=
		nextNames[0]

	generationID :=
		strings.TrimPrefix(
			nextName,
			generationRolloverNextPrefix,
		)

	if generationID == "" {
		return errors.New(
			"FI interrupted rollover next-directory has empty generation ID",
		)
	}

	nextDir :=
		filepath.Join(
			parent,
			nextName,
		)

	hasEntries, err :=
		directoryHasEntries(
			nextDir,
		)
	if err != nil {
		return fmt.Errorf(
			"inspect interrupted FI rollover replacement directory: %w",
			err,
		)
	}

	if hasEntries {
		return errors.New(
			"interrupted FI rollover replacement directory is not empty",
		)
	}

	rawRoot :=
		filepath.Join(
			parent,
			generationRawRootDirectoryName,
		)

	if err :=
		validateRawGenerationRoot(
			rawRoot,
		); err != nil {
		return fmt.Errorf(
			"validate interrupted FI rollover raw root: %w",
			err,
		)
	}

	rawDir :=
		filepath.Join(
			rawRoot,
			generationDirectoryPrefix+
				generationID,
		)

	rawInfo, err :=
		os.Lstat(
			rawDir,
		)
	if err != nil {
		return fmt.Errorf(
			"inspect interrupted FI frozen generation: %w",
			err,
		)
	}

	if rawInfo.Mode()&os.ModeSymlink != 0 ||
		!rawInfo.IsDir() {
		return errors.New(
			"interrupted FI frozen generation is not a real directory",
		)
	}

	pairs, err :=
		spool.ValidatePublishedSpoolStructureLocked(
			rawDir,
		)
	if err != nil {
		return fmt.Errorf(
			"validate interrupted FI frozen generation structure: %w",
			err,
		)
	}

	if pairs == 0 {
		return errors.New(
			"interrupted FI frozen generation contains no published batches",
		)
	}

	if err :=
		publishGenerationDirectory(
			nextDir,
			physicalSpoolDir,
		); err != nil {
		return fmt.Errorf(
			"restore FI active spool after interrupted rollover: %w",
			err,
		)
	}

	return nil
}
func cleanupRolloverNextDirectories(spoolDir string) error {
	parent := filepath.Dir(filepath.Clean(spoolDir))
	entries, err := os.ReadDir(parent)
	if err != nil {
		return fmt.Errorf("scan FI active-spool parent for rollover remnants: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), generationRolloverNextPrefix) {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		hasEntries, err := directoryHasEntries(path)
		if err != nil {
			return err
		}
		if hasEntries {
			return fmt.Errorf("FI rollover next-directory %q is unexpectedly non-empty", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove abandoned FI rollover next-directory: %w", err)
		}
	}
	return nil
}

func directoryHasEntries(path string) (bool, error) {
	directory, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer directory.Close()
	_, err = directory.Readdirnames(1)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, io.EOF):
		return false, nil
	default:
		return false, err
	}
}

func removeRawGenerationDirectory(raw RawGeneration) error {
	info, err := os.Lstat(raw.GenerationDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI raw generation path is not a real directory")
	}
	return os.RemoveAll(raw.GenerationDir)
}

func validateGenerationSealConfig(config GenerationSealConfig) error {
	if config.BatchSigner == nil || config.BatchSigningCertificate == nil {
		return errors.New("FI generation batch-signing identity is required")
	}
	if strings.TrimSpace(config.SourceID) == "" {
		return errors.New("FI generation source ID is required")
	}
	if config.MaxEncodedBytes == 0 {
		return errors.New("FI generation encoded byte ceiling must be greater than zero")
	}
	if _, err :=
		spool.PhysicalSpoolPath(
			config.SpoolDir,
		); err != nil {
		return fmt.Errorf(
			"resolve physical FI spool path for generation sealing: %w",
			err,
		)
	}

	return validateGenerationStageRoot(
		config.StageRoot,
	)
}

func validateGenerationStageRoot(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("FI generation stage root must be absolute")
	}
	clean := filepath.Clean(path)
	if err := validateOutboundStageDirectoryPath(clean); err != nil {
		return fmt.Errorf("validate FI generation stage root path: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("inspect FI generation stage root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI generation stage root must name a real directory")
	}
	return nil
}

func validateRawGeneration(raw RawGeneration, rawRoot string) error {
	if raw.GenerationDir == "" || raw.GenerationID == "" {
		return errors.New("FI raw generation identity is required")
	}
	if filepath.Base(raw.GenerationDir) != generationDirectoryPrefix+raw.GenerationID {
		return errors.New("FI raw generation directory identity is inconsistent")
	}
	if !filepath.IsAbs(raw.GenerationDir) {
		return errors.New("FI raw generation directory must be absolute")
	}
	if rawRoot != "" && filepath.Clean(filepath.Dir(raw.GenerationDir)) != filepath.Clean(rawRoot) {
		return errors.New("FI raw generation is outside the configured raw-generation root")
	}
	info, err := os.Lstat(raw.GenerationDir)
	if err != nil {
		return fmt.Errorf("inspect FI raw generation directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI raw generation path must name a real directory")
	}
	return nil
}

func validateRawGenerationRoot(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("FI raw-generation root must be absolute")
	}
	clean := filepath.Clean(path)
	if err := validateOutboundStageDirectoryPath(clean); err != nil {
		return fmt.Errorf("validate FI raw-generation root path: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("inspect FI raw-generation root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI raw-generation root must name a real directory")
	}
	return nil
}
