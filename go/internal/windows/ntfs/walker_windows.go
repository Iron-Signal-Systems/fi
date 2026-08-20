// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

var (
	ErrWalkRootNotDirectory = errors.New("governed root is not a directory")
	ErrWalkVisitorRequired  = errors.New("walk visitor is required")
)

// WalkVisitFunc receives the result of collecting one object discovered during
// a governed-root walk.
//
// collectErr is nil when observation contains a successful FI observation.
// Returning an error stops the walk.
type WalkVisitFunc func(
	path string,
	observation Observation,
	collectErr error,
) error

// WalkGovernedRoot recursively walks one governed local NTFS directory tree.
//
// The governed root itself is collected first. Every discovered object is
// passed through CollectPath so the existing NTFS collector remains responsible
// for containment, identity, metadata, reparse state, streams, consistency, and
// validation.
//
// Reparse objects are collected but are not recursively followed.
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

	rootObservation, err := CollectPath(
		ctx,
		scopeID,
		governedRoot,
		governedRoot,
	)
	if err != nil {
		return err
	}

	if rootObservation.SubjectKind != records.SubjectDirectory {
		return ErrWalkRootNotDirectory
	}

	if err := visit(governedRoot, rootObservation, nil); err != nil {
		return err
	}

	first := true

	return filepath.WalkDir(
		governedRoot,
		func(path string, entry fs.DirEntry, walkErr error) error {
			if first {
				first = false

				if walkErr != nil {
					return walkErr
				}

				return nil
			}

			if err := validateContext(ctx); err != nil {
				return err
			}

			if walkErr != nil {
				if err := visit(path, Observation{}, walkErr); err != nil {
					return err
				}

				return nil
			}

			observation, collectErr := CollectPath(
				ctx,
				scopeID,
				governedRoot,
				path,
			)

			if err := visit(path, observation, collectErr); err != nil {
				return err
			}

			// Do not descend through a directory FI could not safely collect.
			if collectErr != nil {
				if entry.IsDir() {
					return filepath.SkipDir
				}

				return nil
			}

			// Record reparse objects, but do not recursively follow them.
			if observation.Reparse.State == records.ReparseStatePresent && entry.IsDir() {
				return filepath.SkipDir
			}

			return nil
		},
	)
}
