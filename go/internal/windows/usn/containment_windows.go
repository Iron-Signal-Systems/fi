// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"errors"
	"strconv"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnbroker"
)

type ContainmentResult = usnbroker.ContainmentResult

const (
	ContainmentContained   = usnbroker.ContainmentContained
	ContainmentOutside     = usnbroker.ContainmentOutside
	ContainmentUnavailable = usnbroker.ContainmentUnavailable
)

// CheckObjectContainment asks the privileged FIUSNReader only for the current
// governed-root containment of one exact NTFS object identity. The helper does
// not return the resolved path or any object metadata.
func CheckObjectContainment(
	ctx context.Context,
	governedRoot string,
	identity records.NTFSObjectIdentity,
) (ContainmentResult, error) {
	if identity.MethodVersion != ntfs.IdentityMethodVersion {
		return 0, ntfs.ErrUnsupportedIdentityMethod
	}
	if err := records.ValidateNTFSObjectIdentity(identity); err != nil {
		return 0, err
	}

	fileReferenceNumber, err := strconv.ParseUint(identity.FileReferenceNumber, 10, 48)
	if err != nil {
		return 0, err
	}
	sequenceNumber, err := strconv.ParseUint(identity.SequenceNumber, 10, 16)
	if err != nil {
		return 0, err
	}
	return usnbroker.CheckContainment(
		ctx,
		governedRoot,
		fileReferenceNumber,
		uint16(sequenceNumber),
	)
}

// IsOpenFileByIDAccessDenied reports only the narrow collector failure that the
// helper containment operation is allowed to resolve. Access-denied errors from
// later metadata, security, hashing, or path operations are not redirected to
// the privileged helper.
func IsOpenFileByIDAccessDenied(err error) bool {
	var ntfsErr *ntfs.Error
	return errors.As(err, &ntfsErr) &&
		ntfsErr.Stage == ntfs.StageOpen &&
		ntfsErr.Op == "OpenFileById" &&
		errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}
