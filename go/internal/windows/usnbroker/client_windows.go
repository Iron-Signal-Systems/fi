// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnbroker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

const (
	PipePath = `\\.\pipe\FI-USN`

	connectAttempts = 20
	connectDelay    = 50 * time.Millisecond
)

// Query asks the local FIUSNReader service for the current USN journal state
// of the volume containing governedRoot.
func Query(ctx context.Context, governedRoot string) (Journal, error) {
	result, err := roundTrip(ctx, request{
		Operation:    operationQuery,
		GovernedRoot: governedRoot,
	})
	if err != nil {
		return Journal{}, err
	}
	if len(result.Data) != 0 {
		return Journal{}, errors.New("FIUSNReader query unexpectedly returned raw USN data")
	}
	if err := validateJournal(result.Journal); err != nil {
		return Journal{}, err
	}
	return result.Journal, nil
}

// Read asks the local FIUSNReader service for one bounded raw USN buffer. The
// caller remains responsible for parsing the returned data.
func Read(ctx context.Context, governedRoot string, startUSN int64) (Journal, []byte, error) {
	result, err := roundTrip(ctx, request{
		Operation:    operationRead,
		GovernedRoot: governedRoot,
		StartUSN:     startUSN,
	})
	if err != nil {
		return Journal{}, nil, err
	}
	if err := validateJournal(result.Journal); err != nil {
		return Journal{}, nil, err
	}
	if len(result.Data) < 8 || len(result.Data) > MaxUSNDataBytes {
		return Journal{}, nil, errors.New("FIUSNReader returned an invalid USN buffer length")
	}
	return result.Journal, result.Data, nil
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
			return windows.InvalidHandle, fmt.Errorf("connect FIUSNReader pipe: %w", openErr)
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
	return windows.InvalidHandle, fmt.Errorf("FIUSNReader pipe unavailable: %w", lastErr)
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
		return response{}, fmt.Errorf("write FIUSNReader request: %w", err)
	}
	result, err := readResponse(stream)
	if err != nil {
		return response{}, fmt.Errorf("read FIUSNReader response: %w", err)
	}
	if result.Error != "" {
		return response{}, &remoteError{Code: result.ErrorCode, Message: result.Error}
	}
	if err := ctx.Err(); err != nil {
		return response{}, err
	}
	return result, nil
}

func validateJournal(value Journal) error {
	if value.FirstUSN < 0 || value.NextUSN < 0 || value.LowestValidUSN < 0 || value.MaxUSN < 0 {
		return errors.New("FIUSNReader returned invalid journal state")
	}
	return nil
}
