// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const walkDirectoryBatchSize = 128

var (
	ErrWalkVisitorRequired = errors.New("walk visitor is required")
)

// WalkVisitFunc receives one walk event.
//
// objectErr is nil when observation contains a successful FI observation.
// When traversal of an already-observed directory later fails, FI can emit a
// second event for the same path containing the traversal error and an empty
// observation. Returning an error stops the walk.
type WalkVisitFunc func(
	path string,
	observation Observation,
	objectErr error,
) error

// WalkGovernedRoot recursively walks one governed local NTFS directory tree.
//
// The governed root itself is collected first. CollectPath owns the definition
// of a valid governed root, including the requirement that it be a non-reparse
// NTFS directory.
//
// Directory entries are read in bounded batches. FI does not sort traversal
// order because traversal order is not authoritative record content.
//
// Every discovered object is passed through CollectPath. Reparse objects are
// observed but never recursively followed. Before ReadDir begins, the opened
// directory handle must still match the exact directory observation that
// authorized traversal.
func WalkGovernedRoot(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	visit WalkVisitFunc,
) error {
	if visit == nil {
		return ErrWalkVisitorRequired
	}
	if err := validateContext(ctx); err != nil {
		return err
	}

	rootObservation, err := CollectPath(ctx, scopeID, governedRoot, governedRoot)
	if err != nil {
		return err
	}
	if err := visit(governedRoot, rootObservation, nil); err != nil {
		return err
	}

	return walkDirectory(ctx, scopeID, governedRoot, governedRoot, rootObservation, true, visit)
}

func walkDirectory(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	directoryPath string,
	expected Observation,
	root bool,
	visit WalkVisitFunc,
) error {
	directory, err := os.Open(directoryPath)
	if err != nil {
		if root {
			return err
		}
		return visit(directoryPath, Observation{}, err)
	}
	defer directory.Close()

	if err := verifyWalkDirectoryIdentity(directory, expected); err != nil {
		if root {
			return err
		}
		return visit(directoryPath, Observation{}, err)
	}

	for {
		if err := validateContext(ctx); err != nil {
			return err
		}

		entries, readErr := directory.ReadDir(walkDirectoryBatchSize)
		for _, entry := range entries {
			childPath := filepath.Join(directoryPath, entry.Name())
			if err := walkObject(ctx, scopeID, governedRoot, childPath, visit); err != nil {
				return err
			}
		}

		switch readErr {
		case nil:
			continue
		case io.EOF:
			return nil
		default:
			if root {
				return readErr
			}
			if err := visit(directoryPath, Observation{}, readErr); err != nil {
				return err
			}
			return nil
		}
	}
}

func walkObject(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	path string,
	visit WalkVisitFunc,
) error {
	if err := validateContext(ctx); err != nil {
		return err
	}

	observation, collectErr := CollectPath(ctx, scopeID, governedRoot, path)
	if collectErr != nil {
		return visit(path, Observation{}, collectErr)
	}
	if err := visit(path, observation, nil); err != nil {
		return err
	}
	if observation.SubjectKind != records.SubjectDirectory ||
		observation.Reparse.State == records.ReparseStatePresent {
		return nil
	}

	return walkDirectory(ctx, scopeID, governedRoot, path, observation, false, visit)
}
