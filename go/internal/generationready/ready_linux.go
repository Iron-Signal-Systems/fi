// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package generationready

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const markerMode = 0o600

type PublishDisposition string

const (
	PublishDispositionAlreadyPresent PublishDisposition = "ALREADY_PRESENT"
	PublishDispositionNew            PublishDisposition = "NEW"
)

type PublishResult struct {
	Disposition PublishDisposition
	Path        string
}

// Publish creates one durable, zero-byte, non-authoritative ingest-ready marker.
// The marker name is the exact immutable recorder receipt basename. Receipt
// contents and the recorded receipt itself remain authoritative.
func Publish(
	readyRoot string,
	receiptName string,
) (PublishResult, error) {
	if err := validateRoot(readyRoot); err != nil {
		return PublishResult{}, err
	}
	if err := validateReceiptName(receiptName); err != nil {
		return PublishResult{}, err
	}

	path := filepath.Join(readyRoot, receiptName)
	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		markerMode,
	)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if err := validateMarker(path); err != nil {
				return PublishResult{}, err
			}
			if err := syncDirectory(readyRoot); err != nil {
				return PublishResult{}, err
			}

			return PublishResult{
				Disposition: PublishDispositionAlreadyPresent,
				Path:        path,
			}, nil
		}

		return PublishResult{}, fmt.Errorf(
			"publish FI generation ingest-ready marker %q: %w",
			path,
			err,
		)
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return PublishResult{}, fmt.Errorf(
			"sync FI generation ingest-ready marker %q: %w",
			path,
			err,
		)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return PublishResult{}, fmt.Errorf(
			"close FI generation ingest-ready marker %q: %w",
			path,
			err,
		)
	}

	if err := validateMarker(path); err != nil {
		_ = os.Remove(path)
		return PublishResult{}, err
	}

	if err := syncDirectory(readyRoot); err != nil {
		return PublishResult{}, err
	}

	return PublishResult{
		Disposition: PublishDispositionNew,
		Path:        path,
	}, nil
}

// ReadReceiptNames returns at most limit exact ready-marker names without
// enumerating the complete directory. Directory order is not authoritative;
// returned names are sorted only for deterministic processing of this bounded
// batch.
func ReadReceiptNames(
	readyRoot string,
	limit uint64,
) ([]string, error) {
	if err := validateRoot(readyRoot); err != nil {
		return nil, err
	}
	if limit == 0 {
		return nil, errors.New(
			"FI generation ingest-ready read limit must be greater than zero",
		)
	}
	if limit > uint64(^uint(0)>>1) {
		return nil, errors.New(
			"FI generation ingest-ready read limit exceeds platform bounds",
		)
	}

	directory, err := os.Open(readyRoot)
	if err != nil {
		return nil, fmt.Errorf(
			"open FI generation ingest-ready root %q: %w",
			readyRoot,
			err,
		)
	}
	defer directory.Close()

	entries, err := directory.ReadDir(int(limit))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf(
			"read FI generation ingest-ready root %q: %w",
			readyRoot,
			err,
		)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if err := validateReceiptName(name); err != nil {
			return nil, err
		}

		path := filepath.Join(readyRoot, name)
		if err := validateMarker(path); err != nil {
			return nil, err
		}

		names = append(names, name)
	}

	sort.Strings(names)
	return names, nil
}

// RemoveReceiptNames retires successfully consumed ready markers. The marker
// queue is operational state only; immutable recorder receipts are untouched.
func RemoveReceiptNames(
	readyRoot string,
	names []string,
) error {
	if err := validateRoot(readyRoot); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if err := validateReceiptName(name); err != nil {
			return err
		}
		if _, found := seen[name]; found {
			return fmt.Errorf(
				"FI generation ingest-ready marker %q was supplied more than once for removal",
				name,
			)
		}
		seen[name] = struct{}{}

		path := filepath.Join(readyRoot, name)
		if err := validateMarker(path); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf(
				"remove FI generation ingest-ready marker %q: %w",
				path,
				err,
			)
		}
	}

	if len(names) == 0 {
		return nil
	}

	return syncDirectory(readyRoot)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf(
			"open FI generation ingest-ready directory for sync %q: %w",
			path,
			err,
		)
	}
	defer directory.Close()

	if err := directory.Sync(); err != nil {
		return fmt.Errorf(
			"sync FI generation ingest-ready directory %q: %w",
			path,
			err,
		)
	}

	return nil
}

func validateMarker(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf(
			"inspect FI generation ingest-ready marker %q: %w",
			path,
			err,
		)
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != markerMode {
		return fmt.Errorf(
			"FI generation ingest-ready marker %q must be a %04o regular file",
			path,
			markerMode,
		)
	}
	if info.Size() != 0 {
		return fmt.Errorf(
			"FI generation ingest-ready marker %q must be empty",
			path,
		)
	}

	return nil
}

func validateReceiptName(name string) error {
	if strings.TrimSpace(name) == "" ||
		filepath.Base(name) != name ||
		!strings.HasPrefix(name, "generation-") ||
		!strings.HasSuffix(name, ".record.json") {
		return fmt.Errorf(
			"FI generation ingest-ready name %q is not an exact recorder receipt basename",
			name,
		)
	}

	return nil
}

func validateRoot(readyRoot string) error {
	if strings.TrimSpace(readyRoot) == "" {
		return errors.New(
			"FI generation ingest-ready root is required",
		)
	}
	if !filepath.IsAbs(readyRoot) {
		return errors.New(
			"FI generation ingest-ready root must be absolute",
		)
	}

	resolvedRoot, err := filepath.EvalSymlinks(readyRoot)
	if err != nil {
		return fmt.Errorf(
			"resolve FI generation ingest-ready root: %w",
			err,
		)
	}
	if filepath.Clean(resolvedRoot) != filepath.Clean(readyRoot) {
		return errors.New(
			"FI generation ingest-ready root must not traverse symlinks",
		)
	}

	rootInfo, err := os.Lstat(readyRoot)
	if err != nil {
		return fmt.Errorf(
			"inspect FI generation ingest-ready root: %w",
			err,
		)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New(
			"FI generation ingest-ready root must be a real directory",
		)
	}
	if rootInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf(
			"FI generation ingest-ready root must not be group- or other-writable: mode=%04o",
			rootInfo.Mode().Perm(),
		)
	}

	return nil
}
