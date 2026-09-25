// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectFileReferenceWithSACLReaderUsesInjectedReader(t *testing.T) {
	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "injected-sacl-reader.txt")

	if err := os.WriteFile(
		targetPath,
		[]byte("FI injected SACL reader test"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	rootUnitsWithNUL, err := syscall.UTF16FromString(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	rootUnits := rootUnitsWithNUL[:len(rootUnitsWithNUL)-1]

	root, err := openGovernedRoot(
		"injected-sacl-reader-test",
		rootUnits,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	targetUnitsWithNUL, err := syscall.UTF16FromString(targetPath)
	if err != nil {
		t.Fatal(err)
	}

	targetHandle, err := openPath(targetUnitsWithNUL)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(targetHandle)

	state, err := queryNativeState(targetHandle)
	if err != nil {
		t.Fatal(err)
	}

	_, objectIdentity, err := buildObjectIdentity(
		state.ID.VolumeSerialNumber,
		state.ID.FileID,
	)
	if err != nil {
		t.Fatal(err)
	}

	expectedFileReferenceNumber, err := strconv.ParseUint(
		objectIdentity.FileReferenceNumber,
		10,
		64,
	)
	if err != nil {
		t.Fatal(err)
	}

	expectedSequenceNumber, err := strconv.ParseUint(
		objectIdentity.SequenceNumber,
		10,
		16,
	)
	if err != nil {
		t.Fatal(err)
	}

	injectedErr := errors.New("injected SACL reader failure")
	calls := 0

	reader := func(
		ctx context.Context,
		governedRoot string,
		fileReferenceNumber uint64,
		sequenceNumber uint16,
	) ([]byte, error) {
		calls++

		if ctx == nil {
			t.Fatal("SACL reader received nil context")
		}
		if governedRoot != rootPath {
			t.Fatalf(
				"governed root = %q, want %q",
				governedRoot,
				rootPath,
			)
		}
		if fileReferenceNumber != expectedFileReferenceNumber {
			t.Fatalf(
				"file reference number = %d, want %d",
				fileReferenceNumber,
				expectedFileReferenceNumber,
			)
		}
		if sequenceNumber != uint16(expectedSequenceNumber) {
			t.Fatalf(
				"sequence number = %d, want %d",
				sequenceNumber,
				uint16(expectedSequenceNumber),
			)
		}

		return nil, injectedErr
	}

	observation, err := CollectFileReferenceWithSACLReader(
		context.Background(),
		"injected-sacl-reader-test",
		rootPath,
		objectIdentity,
		reader,
	)
	if err != nil {
		t.Fatal(err)
	}

	if calls != 1 {
		t.Fatalf("SACL reader calls = %d, want 1", calls)
	}

	if observation.SACL.State != records.ObservationStateError {
		t.Fatalf(
			"SACL state = %q, want %q",
			observation.SACL.State,
			records.ObservationStateError,
		)
	}

	if observation.SACL.ReasonCode != saclDescriptorReadFailed {
		t.Fatalf(
			"SACL reason = %q, want %q",
			observation.SACL.ReasonCode,
			saclDescriptorReadFailed,
		)
	}

	if observation.ObservationStatus != records.ObservationPartial {
		t.Fatalf(
			"observation status = %q, want %q",
			observation.ObservationStatus,
			records.ObservationPartial,
		)
	}

	foundWarning := false
	for _, warning := range observation.Warnings {
		if warning.Code != saclDescriptorReadFailed {
			continue
		}
		if !strings.Contains(warning.Detail, injectedErr.Error()) {
			t.Fatalf(
				"SACL warning detail = %q, want injected error",
				warning.Detail,
			)
		}
		foundWarning = true
		break
	}

	if !foundWarning {
		t.Fatalf(
			"missing %q observation warning",
			saclDescriptorReadFailed,
		)
	}
}
