// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// OutboundCleanupDisposition describes whether this call removed the exact
// staged retry frame or found that a prior cleanup had already removed it.
type OutboundCleanupDisposition string

const (
	OutboundCleanupDispositionAlreadyRemoved OutboundCleanupDisposition = "ALREADY_REMOVED"
	OutboundCleanupDispositionRemoved        OutboundCleanupDisposition = "REMOVED"
)

// OutboundCleanupResult describes the completed cleanup state for one durable
// outbound retry frame after downstream custody and local spool retirement.
type OutboundCleanupResult struct {
	BatchID     string
	Disposition OutboundCleanupDisposition
	FramePath   string
	SourceID    string
}

// CleanupRetiredOutboundFrame removes one durable source-side retry frame only
// after the caller presents the exact RetirementAuthorization for that frame and
// both corresponding Phase 1 spool artifacts are already absent.
//
// This is intentionally separate from source-spool retirement. A send failure,
// acknowledgement failure, acknowledgement mismatch, or incomplete local spool
// retirement must leave the staged frame available for exact retry.
func CleanupRetiredOutboundFrame(
	outbound OutboundFrame,
	manifestPath string,
	authorization RetirementAuthorization,
) (OutboundCleanupResult, error) {
	if err := outbound.Sent.Validate(); err != nil {
		return OutboundCleanupResult{}, fmt.Errorf(
			"validate FI outbound cleanup frame facts: %w",
			err,
		)
	}

	acknowledgement, err := authorization.Acknowledgement()
	if err != nil {
		return OutboundCleanupResult{}, fmt.Errorf(
			"validate FI outbound cleanup authorization: %w",
			err,
		)
	}
	if err := acknowledgementMatchesSentFrame(
		acknowledgement,
		outbound.Sent,
	); err != nil {
		return OutboundCleanupResult{}, fmt.Errorf(
			"match FI outbound cleanup authorization to staged frame: %w",
			err,
		)
	}

	dataPath, err := validateOutboundCleanupPaths(outbound, manifestPath)
	if err != nil {
		return OutboundCleanupResult{}, err
	}
	if err := requireRetiredSourceArtifacts(manifestPath, dataPath); err != nil {
		return OutboundCleanupResult{}, err
	}

	result := OutboundCleanupResult{
		BatchID:   outbound.Sent.Descriptor.BatchID,
		FramePath: outbound.FramePath,
		SourceID:  outbound.Sent.Descriptor.SourceID,
	}

	exists, initialInfo, err := inspectOutboundCleanupFrame(outbound.FramePath)
	if err != nil {
		return OutboundCleanupResult{}, err
	}
	if !exists {
		result.Disposition = OutboundCleanupDispositionAlreadyRemoved
		return result, nil
	}

	current, err := validateStagedOutboundFrame(
		outbound.FramePath,
		outbound.Sent.Descriptor,
	)
	if err != nil {
		return OutboundCleanupResult{}, fmt.Errorf(
			"validate exact FI outbound frame before cleanup: %w",
			err,
		)
	}
	if current != outbound.Sent {
		return OutboundCleanupResult{}, errors.New(
			"staged FI outbound frame facts changed before cleanup",
		)
	}

	afterValidation, err := os.Lstat(outbound.FramePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			result.Disposition = OutboundCleanupDispositionAlreadyRemoved
			return result, nil
		}
		return OutboundCleanupResult{}, fmt.Errorf(
			"re-inspect staged FI outbound frame before cleanup: %w",
			err,
		)
	}
	if !os.SameFile(initialInfo, afterValidation) {
		return OutboundCleanupResult{}, errors.New(
			"staged FI outbound frame path changed before cleanup",
		)
	}
	if !afterValidation.Mode().IsRegular() || afterValidation.Mode().Perm()&0o222 != 0 {
		return OutboundCleanupResult{}, errors.New(
			"staged FI outbound frame must remain a read-only regular file before cleanup",
		)
	}

	// Re-check source retirement immediately before deleting the retry object.
	// The retry frame is the last local transport representation of this batch.
	if err := requireRetiredSourceArtifacts(manifestPath, dataPath); err != nil {
		return OutboundCleanupResult{}, err
	}

	removed, err := removeOutboundFrame(outbound.FramePath)
	if removed {
		result.Disposition = OutboundCleanupDispositionRemoved
	} else {
		result.Disposition = OutboundCleanupDispositionAlreadyRemoved
	}
	if err != nil {
		return result, fmt.Errorf("remove retired FI outbound frame: %w", err)
	}

	return result, nil
}

func inspectOutboundCleanupFrame(path string) (bool, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("inspect staged FI outbound frame for cleanup: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, nil, errors.New(
			"staged FI outbound cleanup path must name a regular file",
		)
	}
	if info.Mode().Perm()&0o222 != 0 {
		return false, nil, errors.New(
			"staged FI outbound frame must remain read-only before cleanup",
		)
	}
	return true, info, nil
}

func requireRetiredSourceArtifacts(manifestPath string, dataPath string) error {
	for _, artifact := range []struct {
		name string
		path string
	}{
		{name: "published FI batch manifest", path: manifestPath},
		{name: "published FI batch data", path: dataPath},
	} {
		_, err := os.Lstat(artifact.path)
		switch {
		case err == nil:
			return fmt.Errorf(
				"%s still exists; staged FI outbound frame must be retained",
				artifact.name,
			)
		case errors.Is(err, fs.ErrNotExist):
			continue
		default:
			return fmt.Errorf("inspect %s before outbound cleanup: %w", artifact.name, err)
		}
	}
	return nil
}

func validateOutboundCleanupPaths(
	outbound OutboundFrame,
	manifestPath string,
) (string, error) {
	if outbound.FramePath == "" {
		return "", errors.New("staged FI outbound frame path is required")
	}
	if !filepath.IsAbs(outbound.FramePath) {
		return "", errors.New("staged FI outbound frame path must be absolute")
	}

	switch outbound.Disposition {
	case OutboundFrameDispositionExisting:
	case OutboundFrameDispositionNew:
	default:
		return "", fmt.Errorf(
			"unsupported FI outbound frame disposition %q",
			outbound.Disposition,
		)
	}

	expectedName := outboundFrameObjectName(
		outbound.Sent.Descriptor.SourceID,
		outbound.Sent.Descriptor.BatchID,
	)
	if filepath.Base(filepath.Clean(outbound.FramePath)) != expectedName {
		return "", fmt.Errorf(
			"staged FI outbound frame filename must be %q",
			expectedName,
		)
	}

	frameDir := filepath.Dir(outbound.FramePath)
	resolvedFrameDir, err := filepath.EvalSymlinks(frameDir)
	if err != nil {
		return "", fmt.Errorf("resolve FI outbound cleanup directory: %w", err)
	}
	if filepath.Clean(resolvedFrameDir) != filepath.Clean(frameDir) {
		return "", errors.New(
			"FI outbound cleanup directory path must not traverse symlinks",
		)
	}

	dataPath, err := validateRetirementManifestPath(
		manifestPath,
		outbound.Sent.Descriptor.BatchID,
	)
	if err != nil {
		return "", fmt.Errorf("validate FI retired source paths for outbound cleanup: %w", err)
	}
	return dataPath, nil
}
