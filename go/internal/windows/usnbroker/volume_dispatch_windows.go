// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnbroker

import (
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnraw"
)

// ErrVolumeAccessDenied means the requested enrollment has no broker authority.
// Callers map this to ERROR_ACCESS_DENIED without revealing any native path.
var ErrVolumeAccessDenied = errors.New("FIUSNReader enrolled-volume access denied")

// volumeUSNSource allows native handler dispatch to be tested without granting
// privileged filesystem access to the test runner. The real implementation
// uses only the existing bounded query/read native USN operations.
type volumeUSNSource interface {
	Query(guid, serial64 string) (usnraw.Journal, error)
	Read(guid, serial64 string, startUSN int64) (usnraw.Journal, []byte, error)
}

type nativeVolumeUSNSource struct{}

func (nativeVolumeUSNSource) Query(guid, serial64 string) (usnraw.Journal, error) {
	return usnraw.QueryEnrolledVolume(guid, serial64)
}

func (nativeVolumeUSNSource) Read(guid, serial64 string, startUSN int64) (usnraw.Journal, []byte, error) {
	return usnraw.ReadEnrolledVolume(guid, serial64, startUSN)
}

// dispatchEnrolledUSN never receives a native path from the local pipe client.
// Only a trusted snapshot of installed scope can select the raw target. One
// denied/offline enrollment does not impact the others. The caller must already
// have authenticated the actual FICollector service SID before invocation.
func dispatchEnrolledUSN(
	value request,
	authority *volumeAuthoritySnapshot,
	source volumeUSNSource,
) (response, error) {
	if authority == nil || source == nil {
		return response{}, ErrVolumeAccessDenied
	}
	if !validVolumeEnrollmentID(value.EnrollmentID) || value.GovernedRoot != "" {
		return response{}, ErrVolumeAccessDenied
	}
	if value.Operation != operationQueryVolume && value.Operation != operationReadVolume {
		return response{}, ErrVolumeAccessDenied
	}
	target, err := authority.resolve(value.EnrollmentID)
	if err != nil {
		return response{}, fmt.Errorf("%w: %v", ErrVolumeAccessDenied, err)
	}
	switch value.Operation {
	case operationQueryVolume:
		if value.StartUSN != 0 || value.FileReferenceNumber != 0 || value.SequenceNumber != 0 {
			return response{}, ErrVolumeAccessDenied
		}
		journal, err := source.Query(target.VolumeGUID, target.Serial64)
		if err != nil {
			return response{}, err
		}
		return response{Journal: brokerJournal(journal)}, nil

	case operationReadVolume:
		if value.StartUSN < 0 || value.FileReferenceNumber != 0 || value.SequenceNumber != 0 {
			return response{}, ErrVolumeAccessDenied
		}
		journal, raw, err := source.Read(target.VolumeGUID, target.Serial64, value.StartUSN)
		if err != nil {
			return response{}, err
		}
		if len(raw) < 8 || len(raw) > MaxUSNDataBytes {
			return response{}, errors.New("FIUSNReader volume source returned invalid bounded USN data")
		}
		return response{Journal: brokerJournal(journal), Data: raw}, nil
	}
	return response{}, ErrVolumeAccessDenied
}
