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
	"syscall"

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
// The governed root is established once and its proven context remains open for
// the walk. Every discovered object still goes through the normal opened-target
// collector, including per-object final root/target/scope revalidation. Reparse
// objects are observed but never recursively followed.
//
// Directory entries are read in bounded batches. FI does not sort traversal
// order because traversal order is not authoritative record content.
// Before ReadDir begins, the opened directory handle must still match the exact
// directory observation that authorized traversal.
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

	rootUnits, err := syscall.UTF16FromString(governedRoot)
	if err != nil {
		return &Error{Stage: StageValidatePath, Op: "UTF16FromString(GovernedRoot)", Err: err}
	}
	rootPath := rootUnits[:len(rootUnits)-1]
	if scopeID == "" {
		return &Error{Stage: StageGovernedRoot, Op: "ValidateScope", Err: ErrScopeRequired}
	}
	if err := validateLocalAbsolutePath(rootPath); err != nil {
		return &Error{Stage: StageGovernedRoot, Op: "ValidatePath", Err: err}
	}

	root, err := openGovernedRoot(scopeID, rootPath)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(root.handle)

	rootObservation, err := collectWalkPath(ctx, root, governedRoot)
	if err != nil {
		return err
	}
	if err := visit(governedRoot, rootObservation, nil); err != nil {
		return err
	}

	return walkDirectory(ctx, root, governedRoot, rootObservation, true, visit)
}

func collectWalkPath(ctx context.Context, root governedRootContext, path string) (Observation, error) {
	if err := validateContext(ctx); err != nil {
		return Observation{}, err
	}
	targetUnits, err := syscall.UTF16FromString(path)
	if err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "UTF16FromString(Target)", Err: err}
	}
	targetPath := targetUnits[:len(targetUnits)-1]
	if err := validateLocalAbsolutePath(targetPath); err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "ValidatePath", Err: err}
	}

	targetHandle, err := openPath(nulTerminate(targetPath))
	if err != nil {
		return Observation{}, &Error{Stage: StageOpen, Op: "CreateFileW", Err: err}
	}
	defer syscall.CloseHandle(targetHandle)

	return collectOpenedTargetWithContentHashes(
		ctx,
		root,
		CollectionEntryPath,
		targetPath,
		targetHandle,
		nil,
	)
}

func walkDirectory(
	ctx context.Context,
	rootContext governedRootContext,
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
			if err := walkObject(ctx, rootContext, childPath, visit); err != nil {
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
	root governedRootContext,
	path string,
	visit WalkVisitFunc,
) error {
	if err := validateContext(ctx); err != nil {
		return err
	}

	observation, collectErr := collectWalkPath(ctx, root, path)
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

	return walkDirectory(ctx, root, path, observation, false, visit)
}
