// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package checkpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

const (
	moveFileReplaceExisting = 0x00000001
	moveFileWriteThrough    = 0x00000008
)

var procMoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

type Initialization struct {
	StatePath    string                  `json:"state_path"`
	Checkpoint   USNCheckpoint           `json:"checkpoint"`
	JournalState records.USNJournalState `json:"journal_state"`
	Semantics    string                  `json:"semantics"`
}

func DefaultPath(scopeID string) (string, error) {
	if !safeScopeID(scopeID) {
		return "", fmt.Errorf("invalid scope id for state filename")
	}
	base := os.Getenv("FI_STATE_DIR")
	if base == "" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return "", errors.New("ProgramData is not set")
		}
		base = filepath.Join(programData, "FI", "state")
	}
	return filepath.Join(base, scopeID+"-usn.json"), nil
}

func Initialize(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	statePath string,
) (Initialization, error) {
	root, err := currentGovernedRoot(ctx, scopeID, governedRoot)
	if err != nil {
		return Initialization{}, err
	}
	journal, err := usn.QueryJournal(ctx, scopeID, governedRoot)
	if err != nil {
		return Initialization{}, err
	}
	if !sameVolume(root.VolumeIdentity, journal.VolumeIdentity) {
		return Initialization{}, errors.New("governed root and USN journal volume identities do not match")
	}

	value := USNCheckpoint{
		Version:      SchemaVersion,
		ScopeID:      scopeID,
		GovernedRoot: root,
		JournalID:    journal.JournalID,
		NextUSN:      journal.NextUSN,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := Save(statePath, value); err != nil {
		return Initialization{}, err
	}
	return Initialization{
		StatePath:    statePath,
		Checkpoint:   value,
		JournalState: journal,
		Semantics:    "Checkpoint begins at the current journal NextUSN after a known baseline; earlier journal history is not claimed as processed by this checkpoint.",
	}, nil
}

func Check(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	statePath string,
) (ContinuityAssessment, error) {
	value, err := Load(statePath)
	if err != nil {
		return ContinuityAssessment{}, err
	}
	root, err := currentGovernedRoot(ctx, scopeID, governedRoot)
	if err != nil {
		return ContinuityAssessment{}, err
	}
	journal, err := usn.QueryJournal(ctx, scopeID, governedRoot)
	if err != nil {
		return ContinuityAssessment{}, err
	}
	return Assess(value, root, journal)
}

// Advance persists a new checkpoint after its caller has independently
// established that the bounded source range through newNextUSN is safe to
// retire. Advance validates the requested movement and rechecks the persisted
// checkpoint for conflicts, but it does not itself verify spool custody,
// supporting state, or source continuity.
//
// The current FI USN spool path owns that commit boundary: selected records are
// finalized and manifest-verified before supporting SID state is updated, then
// continuity is rechecked immediately before Advance. A range with no selected
// governed-root-relevant objects is advanced only after its scope decision and
// the same continuity recheck.
func Advance(
	statePath string,
	assessment ContinuityAssessment,
	expectedCurrentUSN string,
	newNextUSN string,
) (USNCheckpoint, error) {
	if err := ValidateAdvance(assessment, expectedCurrentUSN, newNextUSN); err != nil {
		return USNCheckpoint{}, err
	}

	current, err := Load(statePath)
	if err != nil {
		return USNCheckpoint{}, err
	}
	if current.NextUSN != expectedCurrentUSN ||
		current.JournalID != assessment.Checkpoint.JournalID ||
		!sameVolume(current.GovernedRoot.VolumeIdentity, assessment.Checkpoint.GovernedRoot.VolumeIdentity) ||
		!sameObject(current.GovernedRoot.ObjectIdentity, assessment.Checkpoint.GovernedRoot.ObjectIdentity) {
		return USNCheckpoint{}, ErrCheckpointConflict
	}

	current.NextUSN = newNextUSN
	current.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := Save(statePath, current); err != nil {
		return USNCheckpoint{}, err
	}
	return current, nil
}

func Load(path string) (USNCheckpoint, error) {
	file, err := os.Open(path)
	if err != nil {
		return USNCheckpoint{}, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var value USNCheckpoint
	if err := decoder.Decode(&value); err != nil {
		return USNCheckpoint{}, fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return USNCheckpoint{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidCheckpoint)
		}
		return USNCheckpoint{}, fmt.Errorf("%w: trailing data: %v", ErrInvalidCheckpoint, err)
	}
	if err := Validate(value); err != nil {
		return USNCheckpoint{}, err
	}
	return value, nil
}

// Save writes the complete checkpoint to a new file in the same directory,
// flushes it, and replaces the old file with MoveFileExW WRITE_THROUGH.
func Save(path string, value USNCheckpoint) error {
	if err := Validate(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	temp, err := os.CreateTemp(filepath.Dir(path), ".fi-usn-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = os.Remove(tempName)
		}
	}()

	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tempName, path); err != nil {
		return err
	}
	keepTemp = false
	return nil
}

func replaceFile(source string, destination string) error {
	sourcePtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPtr, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(destinationPtr)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if result == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("MoveFileExW failed")
	}
	return nil
}

func currentGovernedRoot(
	ctx context.Context,
	scopeID string,
	governedRoot string,
) (records.GovernedRootIdentity, error) {
	observation, err := ntfs.CollectPath(ctx, scopeID, governedRoot, governedRoot)
	if err != nil {
		return records.GovernedRootIdentity{}, err
	}
	return observation.GovernedRoot, nil
}

func safeScopeID(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return !strings.HasPrefix(value, ".")
}
