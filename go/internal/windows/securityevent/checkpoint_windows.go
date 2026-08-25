// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const securityCheckpointVersion = "fi-windows-security-checkpoint/0.1"

var procMoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

type Checkpoint struct {
	Version           string `json:"version"`
	Channel           string `json:"channel"`
	LastEventRecordID string `json:"last_event_record_id"`
	UpdatedAt         string `json:"updated_at"`
}

type Continuity string

const (
	ContinuityContinuous Continuity = "Continuous"
	ContinuityGap        Continuity = "Gap"
)

type ContinuityAssessment struct {
	Status     Continuity `json:"status"`
	ReasonCode string     `json:"reason_code,omitempty"`
	Checkpoint Checkpoint `json:"checkpoint"`
	LogState   LogState   `json:"log_state"`
}

func DefaultCheckpointPath() (string, error) {
	base := os.Getenv("FI_STATE_DIR")
	if base == "" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return "", errors.New("ProgramData is not set")
		}
		base = filepath.Join(programData, "FI", "state")
	}
	return filepath.Join(base, "windows-security.json"), nil
}

func InitializeCheckpoint(path string, state LogState) (Checkpoint, error) {
	value := Checkpoint{
		Version:           securityCheckpointVersion,
		Channel:           securityChannel,
		LastEventRecordID: state.NewestEventRecordID,
		UpdatedAt:         formatCanonicalTime(time.Now()),
	}
	if err := SaveCheckpoint(path, value); err != nil {
		return Checkpoint{}, err
	}
	return value, nil
}

func AssessCheckpoint(value Checkpoint, state LogState) (ContinuityAssessment, error) {
	if err := validateCheckpoint(value); err != nil {
		return ContinuityAssessment{}, err
	}
	checkpointID, _ := strconv.ParseUint(value.LastEventRecordID, 10, 64)
	oldest, err := strconv.ParseUint(state.OldestEventRecordID, 10, 64)
	if err != nil {
		return ContinuityAssessment{}, err
	}
	newest, err := strconv.ParseUint(state.NewestEventRecordID, 10, 64)
	if err != nil {
		return ContinuityAssessment{}, err
	}

	result := ContinuityAssessment{Status: ContinuityContinuous, Checkpoint: value, LogState: state}
	if newest == 0 {
		if checkpointID > 0 {
			result.Status = ContinuityGap
			result.ReasonCode = "SecurityLogResetOrCleared"
		}
		return result, nil
	}
	if checkpointID > newest {
		result.Status = ContinuityGap
		result.ReasonCode = "SecurityLogResetOrCleared"
		return result, nil
	}
	if oldest > 0 && checkpointID+1 < oldest {
		result.Status = ContinuityGap
		result.ReasonCode = "SecurityLogRecordsOverwritten"
	}
	return result, nil
}

func AdvanceCheckpoint(path string, expectedCurrent, newRecordID string) (Checkpoint, error) {
	current, err := LoadCheckpoint(path)
	if err != nil {
		return Checkpoint{}, err
	}
	if current.LastEventRecordID != expectedCurrent {
		return Checkpoint{}, errors.New("Windows Security checkpoint conflict")
	}
	oldValue, err := strconv.ParseUint(expectedCurrent, 10, 64)
	if err != nil {
		return Checkpoint{}, err
	}
	newValue, err := strconv.ParseUint(newRecordID, 10, 64)
	if err != nil {
		return Checkpoint{}, err
	}
	if newValue < oldValue {
		return Checkpoint{}, errors.New("Windows Security checkpoint cannot move backward")
	}
	current.LastEventRecordID = newRecordID
	current.UpdatedAt = formatCanonicalTime(time.Now())
	if err := SaveCheckpoint(path, current); err != nil {
		return Checkpoint{}, err
	}
	return current, nil
}

func LoadCheckpoint(path string) (Checkpoint, error) {
	file, err := os.Open(path)
	if err != nil {
		return Checkpoint{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var value Checkpoint
	if err := decoder.Decode(&value); err != nil {
		return Checkpoint{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Checkpoint{}, errors.New("trailing Windows Security checkpoint JSON")
		}
		return Checkpoint{}, err
	}
	if err := validateCheckpoint(value); err != nil {
		return Checkpoint{}, err
	}
	return value, nil
}

func SaveCheckpoint(path string, value Checkpoint) error {
	if err := validateCheckpoint(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".fi-security-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	keep := true
	defer func() {
		if keep {
			_ = os.Remove(name)
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
	if err := replaceCheckpoint(name, path); err != nil {
		return err
	}
	keep = false
	return nil
}

func validateCheckpoint(value Checkpoint) error {
	if value.Version != securityCheckpointVersion || value.Channel != securityChannel || value.LastEventRecordID == "" || value.UpdatedAt == "" {
		return errors.New("invalid Windows Security checkpoint")
	}
	if _, err := strconv.ParseUint(value.LastEventRecordID, 10, 64); err != nil {
		return fmt.Errorf("invalid Windows Security event record ID: %w", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, value.UpdatedAt); err != nil {
		return err
	}
	return nil
}

func replaceCheckpoint(source, destination string) error {
	sourcePtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPtr, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	r1, _, callErr := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(destinationPtr)),
		0x00000001|0x00000008,
	)
	if r1 == 0 {
		return windowsCallError("MoveFileExW(SecurityCheckpoint)", callErr)
	}
	return nil
}
