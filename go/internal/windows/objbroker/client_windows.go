// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package objbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/scopeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"golang.org/x/sys/windows"
)

const (
	PipePath = `\\.\pipe\FI-OBJ`

	connectAttempts = 20
	connectDelay    = 50 * time.Millisecond
)

var ErrPrivilegeUnavailable = errors.New("FIObjReader required Windows privilege unavailable")

// ObserveObject asks the local FIObjReader service for one bounded observation
// of the exact NTFS object identity inside governedRoot.
func ObserveObject(
	ctx context.Context,
	governedRoot string,
	objectIdentity records.NTFSObjectIdentity,
) (ntfs.Observation, error) {
	if objectIdentity.MethodVersion != ntfs.IdentityMethodVersion {
		return ntfs.Observation{}, errors.New("FIObjReader object identity method is unsupported")
	}
	if err := records.ValidateNTFSObjectIdentity(objectIdentity); err != nil {
		return ntfs.Observation{}, err
	}

	fileReferenceNumber, err := strconv.ParseUint(
		objectIdentity.FileReferenceNumber,
		10,
		64,
	)
	if err != nil {
		return ntfs.Observation{}, fmt.Errorf("parse FIObjReader file reference number: %w", err)
	}
	sequenceNumber, err := strconv.ParseUint(
		objectIdentity.SequenceNumber,
		10,
		16,
	)
	if err != nil {
		return ntfs.Observation{}, fmt.Errorf("parse FIObjReader sequence number: %w", err)
	}

	result, err := roundTrip(ctx, request{
		Operation:           operationObserveObject,
		GovernedRoot:        governedRoot,
		FileReferenceNumber: fileReferenceNumber,
		SequenceNumber:      uint16(sequenceNumber),
	})
	if err != nil {
		var remote *remoteError
		if errors.As(err, &remote) && (remote.Code == 1300 || remote.Code == 1314) {
			return ntfs.Observation{}, fmt.Errorf("%w: %v", ErrPrivilegeUnavailable, err)
		}
		return ntfs.Observation{}, err
	}

	if len(result.Data) == 0 || len(result.Data) > MaxObservationBytes {
		return ntfs.Observation{}, errors.New("FIObjReader returned an invalid observation length")
	}

	var observation ntfs.Observation
	if err := json.Unmarshal(result.Data, &observation); err != nil {
		return ntfs.Observation{}, fmt.Errorf("decode FIObjReader observation: %w", err)
	}
	if err := ntfs.ValidateObservation(observation); err != nil {
		return ntfs.Observation{}, fmt.Errorf("validate FIObjReader observation: %w", err)
	}
	if observation.CollectionMethod != records.CollectionBackupAuthorityWindowsNTFS {
		return ntfs.Observation{}, errors.New("FIObjReader returned an unexpected collection method")
	}
	if observation.ObjectIdentity != objectIdentity {
		return ntfs.Observation{}, errors.New("FIObjReader returned a different NTFS object identity")
	}

	expectedScopeID := scopeidentity.GovernedRootScopeID(governedRoot)
	if observation.GovernedRoot.ScopeID != expectedScopeID {
		return ntfs.Observation{}, errors.New("FIObjReader returned a different governed-root scope id")
	}

	return observation, nil
}

func connect(ctx context.Context) (windows.Handle, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	pipeUnits, err := windows.UTF16PtrFromString(PipePath)
	if err != nil {
		return windows.InvalidHandle, err
	}

	var lastErr error
	for attempt := 0; attempt < connectAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return windows.InvalidHandle, err
		}

		handle, openErr := windows.CreateFile(
			pipeUnits,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if openErr == nil {
			return handle, nil
		}

		lastErr = openErr
		if openErr != windows.ERROR_PIPE_BUSY && openErr != windows.ERROR_FILE_NOT_FOUND {
			return windows.InvalidHandle, fmt.Errorf("connect FIObjReader pipe: %w", openErr)
		}

		timer := time.NewTimer(connectDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return windows.InvalidHandle, ctx.Err()

		case <-timer.C:
		}
	}

	return windows.InvalidHandle, fmt.Errorf("FIObjReader pipe unavailable: %w", lastErr)
}

func roundTrip(ctx context.Context, value request) (response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return response{}, err
	}

	handle, err := connect(ctx)
	if err != nil {
		return response{}, err
	}
	defer windows.CloseHandle(handle)

	stream := handleIO{handle: handle}
	if err := writeRequest(stream, value); err != nil {
		return response{}, fmt.Errorf("write FIObjReader request: %w", err)
	}

	result, err := readResponse(stream)
	if err != nil {
		return response{}, fmt.Errorf("read FIObjReader response: %w", err)
	}
	if result.Error != "" {
		return response{}, &remoteError{
			Code:    result.ErrorCode,
			Message: result.Error,
		}
	}
	if err := ctx.Err(); err != nil {
		return response{}, err
	}

	return result, nil
}
