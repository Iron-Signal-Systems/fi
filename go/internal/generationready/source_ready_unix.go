// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux || freebsd

package generationready

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const sourceReadyDirectoryMode = 0o700

// PublishForSource publishes one READY marker beneath the source-specific
// READY queue.
func PublishForSource(
	readyRoot string,
	sourceID string,
	receiptName string,
) (
	PublishResult,
	error,
) {
	sourceRoot, err := ensureSourceReadyRoot(
		readyRoot,
		sourceID,
	)
	if err != nil {
		return PublishResult{}, err
	}

	return Publish(
		sourceRoot,
		receiptName,
	)
}

// ReadReceiptNamesForSource returns at most limit READY marker names from one
// source-specific queue. A source with no queue yet is an empty queue.
func ReadReceiptNamesForSource(
	readyRoot string,
	sourceID string,
	limit uint64,
) (
	[]string,
	error,
) {
	sourceRoot, exists, err := inspectSourceReadyRoot(
		readyRoot,
		sourceID,
	)
	if err != nil {
		return nil, err
	}

	if !exists {
		return []string{}, nil
	}

	return ReadReceiptNames(
		sourceRoot,
		limit,
	)
}

// ReceiptNamePresentForSource checks one exact READY marker within one
// source-specific queue.
func ReceiptNamePresentForSource(
	readyRoot string,
	sourceID string,
	receiptName string,
) (
	bool,
	error,
) {
	sourceRoot, exists, err := inspectSourceReadyRoot(
		readyRoot,
		sourceID,
	)
	if err != nil {
		return false, err
	}

	if !exists {
		return false, nil
	}

	return ReceiptNamePresent(
		sourceRoot,
		receiptName,
	)
}

// RemoveReceiptNamesForSource retires READY markers only from the requested
// source-specific queue.
func RemoveReceiptNamesForSource(
	readyRoot string,
	sourceID string,
	names []string,
) error {
	sourceRoot, exists, err := inspectSourceReadyRoot(
		readyRoot,
		sourceID,
	)
	if err != nil {
		return err
	}

	if !exists {
		if len(names) == 0 {
			return nil
		}

		return fmt.Errorf(
			"FI generation READY source queue %q does not exist",
			sourceID,
		)
	}

	return RemoveReceiptNames(
		sourceRoot,
		names,
	)
}

func ensureSourceReadyRoot(
	readyRoot string,
	sourceID string,
) (
	string,
	error,
) {
	sourceRoot, exists, err := inspectSourceReadyRoot(
		readyRoot,
		sourceID,
	)
	if err != nil {
		return "", err
	}

	if exists {
		return sourceRoot, nil
	}

	if err := os.Mkdir(
		sourceRoot,
		sourceReadyDirectoryMode,
	); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf(
				"create FI generation READY source queue %q: %w",
				sourceID,
				err,
			)
		}
	}

	if err := validateSourceReadyRoot(sourceRoot); err != nil {
		return "", err
	}

	if err := syncDirectory(readyRoot); err != nil {
		return "", err
	}

	return sourceRoot, nil
}

func inspectSourceReadyRoot(
	readyRoot string,
	sourceID string,
) (
	string,
	bool,
	error,
) {
	if err := validateRoot(readyRoot); err != nil {
		return "", false, err
	}

	if err := validateReadySourceID(sourceID); err != nil {
		return "", false, err
	}

	sourceRoot := filepath.Join(
		readyRoot,
		sourceID,
	)

	_, err := os.Lstat(sourceRoot)

	switch {
	case err == nil:
		if err := validateSourceReadyRoot(
			sourceRoot,
		); err != nil {
			return "", false, err
		}

		return sourceRoot, true, nil

	case errors.Is(err, os.ErrNotExist):
		return sourceRoot, false, nil

	default:
		return "", false, fmt.Errorf(
			"inspect FI generation READY source queue %q: %w",
			sourceID,
			err,
		)
	}
}

func validateReadySourceID(
	sourceID string,
) error {
	if strings.TrimSpace(sourceID) == "" {
		return errors.New(
			"FI generation READY source ID is required",
		)
	}

	if len(sourceID) > 253 {
		return errors.New(
			"FI generation READY source ID exceeds 253 characters",
		)
	}

	if sourceID == "." ||
		sourceID == ".." ||
		filepath.Base(sourceID) != sourceID ||
		strings.Contains(sourceID, "..") {
		return fmt.Errorf(
			"FI generation READY source ID %q is unsafe",
			sourceID,
		)
	}

	for _, value := range sourceID {
		switch {
		case value >= 'a' && value <= 'z':
		case value >= 'A' && value <= 'Z':
		case value >= '0' && value <= '9':
		case value == '.':
		case value == '-':
		case value == '_':
		default:
			return fmt.Errorf(
				"FI generation READY source ID %q contains unsupported characters",
				sourceID,
			)
		}
	}

	return nil
}

func validateSourceReadyRoot(
	sourceRoot string,
) error {
	info, err := os.Lstat(sourceRoot)
	if err != nil {
		return fmt.Errorf(
			"inspect FI generation READY source queue %q: %w",
			sourceRoot,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm() != sourceReadyDirectoryMode {
		return fmt.Errorf(
			"FI generation READY source queue %q must be a %04o real directory",
			sourceRoot,
			sourceReadyDirectoryMode,
		)
	}

	return nil
}
