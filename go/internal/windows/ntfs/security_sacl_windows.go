// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnbroker"
)

const (
	saclPrivilegeUnavailable = "SACLPrivilegeUnavailable"
	saclDescriptorReadFailed = "SACLDescriptorReadFailed"
)

type saclDescriptorReader func(
	context.Context,
	string,
	uint64,
	uint16,
) ([]byte, error)

type saclQueryError struct {
	ReasonCode string
	Err        error
}

func (e *saclQueryError) Error() string {
	return e.Err.Error()
}

func (e *saclQueryError) Unwrap() error {
	return e.Err
}

// querySACLDescriptor asks the privileged FIUSNReader boundary to retrieve the
// raw SACL for the exact object identity derived from the already-proven FI
// handle. FICollector remains responsible for parsing and recording the returned
// descriptor and never receives SeSecurityPrivilege itself.
func querySACLDescriptor(
	ctx context.Context,
	root governedRootContext,
	handle syscall.Handle,
) ([]byte, error) {
	return querySACLDescriptorWithReader(ctx, root, handle, usnbroker.ReadSACL)
}

func querySACLDescriptorWithReader(
	ctx context.Context,
	root governedRootContext,
	handle syscall.Handle,
	readSACL saclDescriptorReader,
) ([]byte, error) {
	if readSACL == nil {
		return nil, &saclQueryError{
			ReasonCode: saclDescriptorReadFailed,
			Err:        errors.New("SACL broker reader is required"),
		}
	}

	identity, err := securityObjectIdentity(handle)
	if err != nil {
		return nil, &saclQueryError{ReasonCode: saclDescriptorReadFailed, Err: err}
	}

	fileReferenceNumber, err := strconv.ParseUint(identity.FileReferenceNumber, 10, 64)
	if err != nil {
		return nil, &saclQueryError{
			ReasonCode: saclDescriptorReadFailed,
			Err:        fmt.Errorf("parse NTFS file reference number: %w", err),
		}
	}
	sequenceNumber, err := strconv.ParseUint(identity.SequenceNumber, 10, 16)
	if err != nil {
		return nil, &saclQueryError{
			ReasonCode: saclDescriptorReadFailed,
			Err:        fmt.Errorf("parse NTFS sequence number: %w", err),
		}
	}

	governedRoot := syscall.UTF16ToString(root.requestedPath)
	raw, err := readSACL(
		ctx,
		governedRoot,
		fileReferenceNumber,
		uint16(sequenceNumber),
	)
	if err != nil {
		return nil, &saclQueryError{ReasonCode: saclBrokerReasonCode(err), Err: err}
	}
	return raw, nil
}

func saclBrokerReasonCode(err error) string {
	if errors.Is(err, usnbroker.ErrSACLPrivilegeUnavailable) {
		return saclPrivilegeUnavailable
	}
	return saclDescriptorReadFailed
}

func saclQueryReasonCode(err error) string {
	var queryErr *saclQueryError
	if errors.As(err, &queryErr) && queryErr.ReasonCode != "" {
		return queryErr.ReasonCode
	}
	return saclDescriptorReadFailed
}
