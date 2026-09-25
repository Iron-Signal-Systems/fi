// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func TestReobserveBatchUsesBackupAuthorityOnlyForInitialOpenAccessDenied(t *testing.T) {
	identity := fallbackTestIdentity()
	batch := fallbackTestBatch(identity)

	backupCalls := 0
	containmentCalls := 0

	backupObservation := ntfs.Observation{
		ObjectIdentity:   identity,
		CollectionMethod: records.CollectionBackupAuthorityWindowsNTFS,
	}

	result := reobserveBatchWithDependencies(
		context.Background(),
		`C:\FI-Lab`,
		batch,
		func(
			context.Context,
			string,
			string,
			records.NTFSObjectIdentity,
		) (ntfs.Observation, error) {
			return ntfs.Observation{}, openFileByIDAccessDenied()
		},
		func(
			context.Context,
			string,
			records.NTFSObjectIdentity,
		) (ntfs.Observation, error) {
			backupCalls++
			return backupObservation, nil
		},
		func(
			context.Context,
			string,
			records.NTFSObjectIdentity,
		) (ContainmentResult, error) {
			containmentCalls++
			return ContainmentUnavailable, errors.New("containment must not run after successful FIObjReader observation")
		},
	)

	if backupCalls != 1 {
		t.Fatalf("FIObjReader calls = %d, want 1", backupCalls)
	}
	if containmentCalls != 0 {
		t.Fatalf("containment calls = %d, want 0", containmentCalls)
	}
	if len(result.Reobservations) != 1 {
		t.Fatalf("reobservations = %d, want 1", len(result.Reobservations))
	}

	got := result.Reobservations[0]
	if got.Status != ReobservationObserved {
		t.Fatalf("status = %q, error = %q", got.Status, got.Error)
	}
	if got.Observation == nil {
		t.Fatal("backup-authority observation is nil")
	}
	if got.Observation.CollectionMethod != records.CollectionBackupAuthorityWindowsNTFS {
		t.Fatalf("collection method = %q", got.Observation.CollectionMethod)
	}
}

func TestReobserveBatchDoesNotEscalateLaterAccessDenied(t *testing.T) {
	identity := fallbackTestIdentity()
	batch := fallbackTestBatch(identity)

	backupCalls := 0
	containmentCalls := 0

	result := reobserveBatchWithDependencies(
		context.Background(),
		`C:\FI-Lab`,
		batch,
		func(
			context.Context,
			string,
			string,
			records.NTFSObjectIdentity,
		) (ntfs.Observation, error) {
			return ntfs.Observation{}, &ntfs.Error{
				Stage: ntfs.StageMetadata,
				Op:    "GetFileInformationByHandleEx",
				Err:   syscall.ERROR_ACCESS_DENIED,
			}
		},
		func(
			context.Context,
			string,
			records.NTFSObjectIdentity,
		) (ntfs.Observation, error) {
			backupCalls++
			return ntfs.Observation{}, errors.New("unexpected FIObjReader call")
		},
		func(
			context.Context,
			string,
			records.NTFSObjectIdentity,
		) (ContainmentResult, error) {
			containmentCalls++
			return ContainmentContained, nil
		},
	)

	if backupCalls != 0 {
		t.Fatalf("FIObjReader calls = %d, want 0", backupCalls)
	}
	if containmentCalls != 0 {
		t.Fatalf("containment calls = %d, want 0", containmentCalls)
	}

	got := result.Reobservations[0]
	if got.Status != ReobservationError || got.ReasonCode != "ReobservationFailed" {
		t.Fatalf("result = %+v", got)
	}
}

func TestReobserveBatchClassifiesContainedBackupAuthorityFailure(t *testing.T) {
	identity := fallbackTestIdentity()
	batch := fallbackTestBatch(identity)

	backupErr := errors.New("backup authority failed")

	result := reobserveBatchWithDependencies(
		context.Background(),
		`C:\FI-Lab`,
		batch,
		func(
			context.Context,
			string,
			string,
			records.NTFSObjectIdentity,
		) (ntfs.Observation, error) {
			return ntfs.Observation{}, openFileByIDAccessDenied()
		},
		func(
			context.Context,
			string,
			records.NTFSObjectIdentity,
		) (ntfs.Observation, error) {
			return ntfs.Observation{}, backupErr
		},
		func(
			context.Context,
			string,
			records.NTFSObjectIdentity,
		) (ContainmentResult, error) {
			return ContainmentContained, nil
		},
	)

	got := result.Reobservations[0]
	if got.Status != ReobservationError {
		t.Fatalf("status = %q, want Error", got.Status)
	}
	if got.ReasonCode != ReobservationReasonBackupAuthorityObservationFailed {
		t.Fatalf("reason = %q", got.ReasonCode)
	}
	if !strings.Contains(got.Error, "Access is denied") {
		t.Fatalf("error does not contain ordinary access denial: %q", got.Error)
	}
	if !strings.Contains(got.Error, backupErr.Error()) {
		t.Fatalf("error does not contain FIObjReader failure: %q", got.Error)
	}
}

func TestReobserveBatchPreservesScopeClassificationAfterBackupFailure(t *testing.T) {
	for _, test := range []struct {
		name        string
		containment ContainmentResult
		status      ReobservationStatus
		reason      string
	}{
		{
			name:        "outside",
			containment: ContainmentOutside,
			status:      ReobservationOutsideGovernedRoot,
			reason:      "OutsideGovernedRoot",
		},
		{
			name:        "unavailable",
			containment: ContainmentUnavailable,
			status:      ReobservationUnavailable,
			reason:      "ObjectUnavailableAfterUSN",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := fallbackTestIdentity()

			result := reobserveBatchWithDependencies(
				context.Background(),
				`C:\FI-Lab`,
				fallbackTestBatch(identity),
				func(
					context.Context,
					string,
					string,
					records.NTFSObjectIdentity,
				) (ntfs.Observation, error) {
					return ntfs.Observation{}, openFileByIDAccessDenied()
				},
				func(
					context.Context,
					string,
					records.NTFSObjectIdentity,
				) (ntfs.Observation, error) {
					return ntfs.Observation{}, errors.New("FIObjReader failed")
				},
				func(
					context.Context,
					string,
					records.NTFSObjectIdentity,
				) (ContainmentResult, error) {
					return test.containment, nil
				},
			)

			got := result.Reobservations[0]
			if got.Status != test.status || got.ReasonCode != test.reason {
				t.Fatalf("result = %+v", got)
			}
			if got.Error != "" {
				t.Fatalf("classified result retained error text %q", got.Error)
			}
		})
	}
}

func TestReobserveBatchDoesNotCallBackupAfterNormalSuccess(t *testing.T) {
	identity := fallbackTestIdentity()
	batch := fallbackTestBatch(identity)

	backupCalls := 0
	observation := ntfs.Observation{
		ObjectIdentity:   identity,
		CollectionMethod: records.CollectionDirectWindowsNTFS,
	}

	result := reobserveBatchWithDependencies(
		context.Background(),
		`C:\FI-Lab`,
		batch,
		func(
			context.Context,
			string,
			string,
			records.NTFSObjectIdentity,
		) (ntfs.Observation, error) {
			return observation, nil
		},
		func(
			context.Context,
			string,
			records.NTFSObjectIdentity,
		) (ntfs.Observation, error) {
			backupCalls++
			return ntfs.Observation{}, errors.New("unexpected FIObjReader call")
		},
		func(
			context.Context,
			string,
			records.NTFSObjectIdentity,
		) (ContainmentResult, error) {
			return ContainmentContained, errors.New("unexpected containment call")
		},
	)

	if backupCalls != 0 {
		t.Fatalf("FIObjReader calls = %d, want 0", backupCalls)
	}
	got := result.Reobservations[0]
	if got.Status != ReobservationObserved || got.Observation == nil {
		t.Fatalf("result = %+v", got)
	}
	if got.Observation.CollectionMethod != records.CollectionDirectWindowsNTFS {
		t.Fatalf("collection method = %q", got.Observation.CollectionMethod)
	}
}

func fallbackTestBatch(identity records.NTFSObjectIdentity) records.USNReadBatch {
	return records.USNReadBatch{
		ScopeID: "root-fallback-test",
		Records: []records.USNChangeObservation{
			{
				FileIdentity: identity,
				USN:          "100",
			},
		},
	}
}

func fallbackTestIdentity() records.NTFSObjectIdentity {
	return records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: "270203",
		SequenceNumber:      "1070",
	}
}

func openFileByIDAccessDenied() error {
	return &ntfs.Error{
		Stage: ntfs.StageOpen,
		Op:    "OpenFileById",
		Err:   syscall.ERROR_ACCESS_DENIED,
	}
}
