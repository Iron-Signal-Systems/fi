// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RetirementDisposition describes how local source custody reached its final
// retired state after durable downstream custody had already been authorized.
type RetirementDisposition string

const (
	RetirementDispositionAlreadyComplete RetirementDisposition = "ALREADY_RETIRED"
	RetirementDispositionComplete        RetirementDisposition = "RETIRED"
	RetirementDispositionResumed         RetirementDisposition = "RESUMED_RETIREMENT"
)

// RetirementResult describes the local Phase 1 spool artifacts affected by one
// authorized retirement operation.
//
// ManifestRemoved and DataRemoved describe work performed by this call. A
// resumed retirement can therefore complete safely after an earlier interruption
// removed only one of the two local artifacts.
type RetirementResult struct {
	BatchID         string
	DataPath        string
	DataRemoved     bool
	Disposition     RetirementDisposition
	ManifestPath    string
	ManifestRemoved bool
	SourceID        string
}

type retirementFileState struct {
	exists bool
	info   os.FileInfo
}

// RetirePublishedBatch removes one published Phase 1 spool batch only after the
// caller presents RetirementAuthorization produced by exact durable receiver
// acknowledgement verification.
//
// Before any local file is removed, every still-present artifact is matched
// against the acknowledged batch. The published manifest is removed before the
// data file so an interrupted retirement cannot leave a published manifest that
// points at data already removed locally. If an earlier retirement was
// interrupted after removing one artifact, the remaining artifact is verified
// against the same authorization and retirement resumes safely.
func RetirePublishedBatch(
	manifestPath string,
	authorization RetirementAuthorization,
) (RetirementResult, error) {
	acknowledgement, err := authorization.Acknowledgement()
	if err != nil {
		return RetirementResult{}, fmt.Errorf(
			"validate FI retirement authorization: %w",
			err,
		)
	}

	dataPath, err := validateRetirementManifestPath(
		manifestPath,
		acknowledgement.BatchID,
	)
	if err != nil {
		return RetirementResult{}, err
	}

	manifestState, err := inspectRetirementFile(manifestPath, "published FI batch manifest")
	if err != nil {
		return RetirementResult{}, err
	}
	dataState, err := inspectRetirementFile(dataPath, "published FI batch data")
	if err != nil {
		return RetirementResult{}, err
	}

	result := RetirementResult{
		BatchID:      acknowledgement.BatchID,
		DataPath:     dataPath,
		ManifestPath: manifestPath,
		SourceID:     acknowledgement.SourceID,
	}

	if !manifestState.exists && !dataState.exists {
		result.Disposition = RetirementDispositionAlreadyComplete
		return result, nil
	}

	// Verify all remaining local custody before removing either artifact. A
	// mismatch therefore leaves every still-present local file untouched.
	if manifestState.exists {
		if err := verifyRetirementManifest(
			manifestPath,
			manifestState.info,
			acknowledgement.ManifestSHA256,
		); err != nil {
			return RetirementResult{}, err
		}
	}
	if dataState.exists {
		if err := verifyRetirementData(
			dataPath,
			dataState.info,
			acknowledgement.DataBytes,
			acknowledgement.DataSHA256,
		); err != nil {
			return RetirementResult{}, err
		}
	}

	if manifestState.exists && dataState.exists {
		result.Disposition = RetirementDispositionComplete
	} else {
		result.Disposition = RetirementDispositionResumed
	}

	if manifestState.exists {
		if err := os.Remove(manifestPath); err != nil {
			return result, fmt.Errorf("remove published FI batch manifest: %w", err)
		}
		result.ManifestRemoved = true
	}

	if dataState.exists {
		if err := os.Remove(dataPath); err != nil {
			return result, fmt.Errorf("remove published FI batch data: %w", err)
		}
		result.DataRemoved = true
	}

	return result, nil
}

func hashRetirementFile(
	path string,
	initial os.FileInfo,
) (string, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !os.SameFile(initial, opened) {
		return "", 0, errors.New("FI retirement file changed while being opened")
	}
	if !opened.Mode().IsRegular() {
		return "", 0, errors.New("FI retirement file must remain a regular file")
	}

	hasher := sha256.New()
	written, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	if written < 0 {
		return "", 0, errors.New("FI retirement file reported a negative byte count")
	}

	afterOpen, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !os.SameFile(opened, afterOpen) || afterOpen.Size() != written {
		return "", 0, errors.New("FI retirement file changed during verification")
	}

	afterPath, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !os.SameFile(afterOpen, afterPath) {
		return "", 0, errors.New("FI retirement file path changed during verification")
	}
	if !afterPath.Mode().IsRegular() {
		return "", 0, errors.New("FI retirement file path no longer names a regular file")
	}

	return hex.EncodeToString(hasher.Sum(nil)), uint64(written), nil
}

func inspectRetirementFile(path string, name string) (retirementFileState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return retirementFileState{}, nil
		}
		return retirementFileState{}, fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return retirementFileState{}, fmt.Errorf("%s must be a regular file", name)
	}
	return retirementFileState{exists: true, info: info}, nil
}

func validateRetirementManifestPath(manifestPath string, batchID string) (string, error) {
	if manifestPath == "" {
		return "", errors.New("published FI batch manifest path is required")
	}
	if batchID == "" {
		return "", errors.New("authorized FI batch ID is required")
	}

	expectedManifest := "batch-" + batchID + ".manifest.json"
	expectedData := "batch-" + batchID + ".jsonl"
	if filepath.Base(expectedManifest) != expectedManifest ||
		filepath.Base(expectedData) != expectedData ||
		strings.ContainsAny(expectedManifest, `/\\`) ||
		strings.ContainsAny(expectedData, `/\\`) {
		return "", errors.New("authorized FI batch ID cannot map to a local spool filename")
	}
	if filepath.Base(filepath.Clean(manifestPath)) != expectedManifest {
		return "", fmt.Errorf(
			"published FI batch manifest filename must be %q",
			expectedManifest,
		)
	}

	return filepath.Join(filepath.Dir(manifestPath), expectedData), nil
}

func verifyRetirementData(
	path string,
	info os.FileInfo,
	wantBytes uint64,
	wantSHA256 string,
) error {
	digest, bytes, err := hashRetirementFile(path, info)
	if err != nil {
		return fmt.Errorf("verify published FI batch data before retirement: %w", err)
	}
	if bytes != wantBytes {
		return fmt.Errorf(
			"published FI batch data byte count %d does not match authorized byte count %d",
			bytes,
			wantBytes,
		)
	}
	if digest != wantSHA256 {
		return errors.New(
			"published FI batch data SHA-256 does not match retirement authorization",
		)
	}
	return nil
}

func verifyRetirementManifest(
	path string,
	info os.FileInfo,
	wantSHA256 string,
) error {
	digest, bytes, err := hashRetirementFile(path, info)
	if err != nil {
		return fmt.Errorf("verify published FI batch manifest before retirement: %w", err)
	}
	if bytes == 0 {
		return errors.New("published FI batch manifest is empty")
	}
	if digest != wantSHA256 {
		return errors.New(
			"published FI batch manifest SHA-256 does not match retirement authorization",
		)
	}
	return nil
}
