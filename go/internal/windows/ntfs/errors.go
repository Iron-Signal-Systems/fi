// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"errors"
	"fmt"
)

var (
	// TODO: change how the errors display.
	ErrUnsupportedPlatform  = errors.New("NTFS collection requires Windows")
	ErrNotLocalVolume       = errors.New("path is not on a local volume")
	ErrNotNTFS              = errors.New("path is not on an NTFS volume")
	ErrIdentityChanged      = errors.New("object identity changed during collection")
	ErrInvalidPath          = errors.New("path is invalid")
	ErrUnsafePathForm       = errors.New("path form is not authorized for direct NTFS collection")
	ErrOutsideGovernedRoot  = errors.New("path is outside the governed root")
	ErrGovernedRootReparse  = errors.New("governed root cannot be a reparse object")
	ErrGovernedRootRequired = errors.New("governed root scope is required")
	ErrStreamBufferLimit    = errors.New("NTFS stream inventory exceeded bounded buffer limit")
	ErrMalformedStreamInfo  = errors.New("Windows returned malformed FILE_STREAM_INFO data")
)

type Stage string

const (
	StageValidatePath Stage = "ValidatePath"
	StageGovernedRoot Stage = "GovernedRoot"
	StageContainment  Stage = "Containment"
	StageOpen         Stage = "Open"
	StageVolume       Stage = "Volume"
	StageIdentity     Stage = "Identity"
	StageMetadata     Stage = "Metadata"
	StageStreams      Stage = "Streams"
	StageConsistency  Stage = "Consistency"
)

// Error binds an operating-system failure to a stable source-collection stage.
type Error struct {
	Stage Stage
	Op    string
	Err   error
}

func (e *Error) Error() string { return fmt.Sprintf("ntfs %s/%s: %v", e.Stage, e.Op, e.Err) }
func (e *Error) Unwrap() error { return e.Err }
