// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"errors"
	"fmt"
)

// These errors describe failures specific to direct Windows NTFS collection.
// Callers can use errors.Is on the stable errors below and still receive the
// collection Stage and Windows operation through Error.

var (
	ErrGovernedRootNotDirectory       = errors.New("governed root must be a directory")
	ErrGovernedRootReparse            = errors.New("governed root cannot be a reparse object")
	ErrIdentityChanged                = errors.New("object identity changed during collection")
	ErrInvalidPath                    = errors.New("path is invalid")
	ErrMalformedReparseData           = errors.New("Windows returned malformed reparse data")
	ErrMalformedStreamInfo            = errors.New("Windows returned malformed FILE_STREAM_INFO data")
	ErrNotLocalVolume                 = errors.New("path is not on a local volume")
	ErrNotNTFS                        = errors.New("path is not on an NTFS volume")
	ErrOutsideGovernedRoot            = errors.New("path is outside the governed root")
	ErrReparseChangedDuringCollection = errors.New("reparse state changed during collection")
	ErrScopeRequired                  = errors.New("scope ID is required")
	ErrStreamBufferLimit              = errors.New("NTFS stream inventory exceeded bounded buffer limit")
	ErrStreamQualifiedPath            = errors.New("path must identify the base NTFS object, not a named stream")
	ErrUnsafePathForm                 = errors.New("path form is not authorized for direct NTFS collection")
)

// Stage identifies the part of NTFS collection that failed.
type Stage string

const (
	StageConsistency  Stage = "Consistency"
	StageContainment  Stage = "Containment"
	StageGovernedRoot Stage = "GovernedRoot"
	StageIdentity     Stage = "Identity"
	StageMetadata     Stage = "Metadata"
	StageOpen         Stage = "Open"
	StageReparse      Stage = "Reparse"
	StageStreams      Stage = "Streams"
	StageValidatePath Stage = "ValidatePath"
	StageVolume       Stage = "Volume"
)

// Error keeps the collection stage and Windows operation with the underlying
// error. This is diagnostic context; it does not convert a failed collection
// into a successful FI observation.
type Error struct {
	Stage Stage
	Op    string
	Err   error
}

func (e *Error) Error() string {
	return fmt.Sprintf("ntfs %s/%s: %v", e.Stage, e.Op, e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}
