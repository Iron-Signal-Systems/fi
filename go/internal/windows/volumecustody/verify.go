// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package volumecustody checks a bounded FI v2 USN window against a published
// spool manifest before proposing a volume-owned checkpoint cursor. This is a
// source-boundary verifier, NOT native acquisition, protected installed-grant
// authentication, checkpoint persistence or permission to read NTFS objects.
package volumecustody

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeepoch"
)

const (
	BoundaryVersion = "fi-volume-usn-boundary/1"
	MinimalFactVersion = "fi-volume-usn-minimal-fact/1"
	BoundaryRecordKind = "VolumeUSNReadBoundaryV2"
	MinimalFactRecordKind = "VolumeUSNMinimalChangeV2"
	maxWindowChanges = 4096
)

var (
	ErrUnsafeWindow = errors.New("FI volume-first USN window is invalid or discontinuous")
	ErrUnverifiedCustody = errors.New("FI volume-first window is not in complete verified spool custody")
)

// MinimalChange is raw, bounded USN change evidence. This is NOT a path,
// actor, security descriptor or authorization to re-observe a file.
// File/parent references remain in their native USN record width: 64-bit
// references are 16 hex digits, 128-bit references are 32 hex digits. No
// equivalence to FILE_ID_INFO's 128-bit identity is inferred.
type MinimalChange struct {
	Version             string `json:"version"`
	USN                 string `json:"usn"`
	NTFSRecordVersion   uint16 `json:"ntfs_record_version"`
	FileReferenceHex    string `json:"file_reference_hex"`
	ParentReferenceHex  string `json:"parent_reference_hex"`
	ReasonFlags         uint32 `json:"reason_flags"`
}

// ReadBoundary must be published after every MinimalChange in the exact
// bounded capture. A zero-change read STILL requires an explicit boundary;
// otherwise no source window may be retired without durable evidence.
type ReadBoundary struct {
	Version           string               `json:"version"`
	EnrollmentID      string               `json:"enrollment_id"`
	Epoch             uint64               `json:"epoch"`
	Identity          volumeepoch.Identity `json:"identity"`
	StartUSN          string               `json:"start_usn"`
	NextUSN           string               `json:"next_usn"`
	SourceRecordCount uint32               `json:"source_record_count"`
}

// Window contains the expected facts returned by a future trusted native
// enrolled-volume reader. The verifier checks them against ACTUAL published
// bytes but cannot itself prove the reader did not omit source events.
type Window struct {
	Boundary ReadBoundary
	Changes  []MinimalChange
}

// ProposeAfterPublishedWindow verifies one fully published bounded window
// against the specified spool manifest and returns an IN-MEMORY candidate.
// It never writes a checkpoint, adjusts a journal, or enables a service.
//
// The future runtime must hold the per-volume exclusive writer/retirement lock,
// authenticate the installed scope, independently verify the native reader,
// and recheck the live checkpoint+journal at a guarded persistence boundary.
// A forged caller-supplied Window is NOT proof that NTFS was read.
func ProposeAfterPublishedWindow(
	saved volumeepoch.Checkpoint,
	current volumeepoch.Journal,
	expected Window,
	spoolDirectory string,
	manifestPath string,
) (volumeepoch.Checkpoint, error) {
	if err := validateWindow(saved, current, expected); err != nil {
		return volumeepoch.Checkpoint{}, err
	}
	if !filepath.IsAbs(spoolDirectory) || !filepath.IsAbs(manifestPath) ||
		filepath.Clean(filepath.Dir(manifestPath)) != filepath.Clean(spoolDirectory) {
		return volumeepoch.Checkpoint{}, fmt.Errorf("%w: manifest is not a direct file in the selected spool directory", ErrUnverifiedCustody)
	}
	if err := requirePlainFile(manifestPath); err != nil {
		return volumeepoch.Checkpoint{}, err
	}
	verification, err := spool.VerifyManifest(manifestPath)
	if err != nil || !verification.Verified {
		return volumeepoch.Checkpoint{}, fmt.Errorf("%w: manifest/data verification failed: %v", ErrUnverifiedCustody, err)
	}
	if verification.Manifest.RecordCount != len(expected.Changes)+1 ||
		filepath.Clean(filepath.Dir(verification.DataPath)) != filepath.Clean(spoolDirectory) ||
		filepath.Base(manifestPath) != "batch-"+verification.Manifest.BatchID+".manifest.json" {
		return volumeepoch.Checkpoint{}, fmt.Errorf("%w: published file/count identity mismatch", ErrUnverifiedCustody)
	}
	if err := requirePlainFile(verification.DataPath); err != nil {
		return volumeepoch.Checkpoint{}, err
	}
	data, err := os.Open(verification.DataPath)
	if err != nil {
		return volumeepoch.Checkpoint{}, fmt.Errorf("%w: open bounded data: %v", ErrUnverifiedCustody, err)
	}
	defer data.Close()
	decoder := json.NewDecoder(io.LimitReader(data, verification.Manifest.DataBytes+1))
	decoder.DisallowUnknownFields()
	for i := range expected.Changes {
		var record spool.Record
		if err := decoder.Decode(&record); err != nil {
			return volumeepoch.Checkpoint{}, fmt.Errorf("%w: missing or invalid source fact %d: %v", ErrUnverifiedCustody, i, err)
		}
		if err := checkRecord(record, MinimalFactRecordKind, saved.EnrollmentID); err != nil {
			return volumeepoch.Checkpoint{}, err
		}
		var actual MinimalChange
		if err := strictPayload(record.Payload, &actual); err != nil ||
			actual != expected.Changes[i] {
			return volumeepoch.Checkpoint{}, fmt.Errorf("%w: spooled minimal source fact %d does not match acquisition", ErrUnverifiedCustody, i)
		}
	}
	var final spool.Record
	if err := decoder.Decode(&final); err != nil {
		return volumeepoch.Checkpoint{}, fmt.Errorf("%w: missing terminal source boundary: %v", ErrUnverifiedCustody, err)
	}
	if err := checkRecord(final, BoundaryRecordKind, saved.EnrollmentID); err != nil {
		return volumeepoch.Checkpoint{}, err
	}
	var actualBoundary ReadBoundary
	if err := strictPayload(final.Payload, &actualBoundary); err != nil ||
		!reflect.DeepEqual(actualBoundary, expected.Boundary) {
		return volumeepoch.Checkpoint{}, fmt.Errorf("%w: terminal source boundary differs from expected read", ErrUnverifiedCustody)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return volumeepoch.Checkpoint{}, fmt.Errorf("%w: unexpected spooled records after terminal boundary: %v", ErrUnverifiedCustody, err)
	}
	// A second digest verification detects ordinary concurrent corruption
	// during semantic inspection. It cannot substitute for protected spool ACLs
	// and native lifetime/retirement locks in the eventual service runtime.
	again, err := spool.VerifyManifest(manifestPath)
	if err != nil || !again.Verified ||
		!reflect.DeepEqual(again.Manifest, verification.Manifest) ||
		again.DataPath != verification.DataPath {
		return volumeepoch.Checkpoint{}, fmt.Errorf("%w: published bytes changed during inspection: %v", ErrUnverifiedCustody, err)
	}
	next := saved
	next.NextUSN = expected.Boundary.NextUSN
	return next, nil
}

func requirePlainFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: inspect published file: %v", ErrUnverifiedCustody, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: published artifact is not a plain regular file", ErrUnverifiedCustody)
	}
	return nil
}

func checkRecord(record spool.Record, kind, enrollmentID string) error {
	if record.Version != spool.RecordVersion || record.RecordKind != kind ||
		record.ScopeID != "volume:"+enrollmentID || len(record.Payload) == 0 {
		return fmt.Errorf("%w: wrong spool record family, scope or version", ErrUnverifiedCustody)
	}
	return nil
}

func strictPayload(data []byte, output any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(output); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("record payload has trailing data")
	}
	return nil
}

func validateWindow(saved volumeepoch.Checkpoint, current volumeepoch.Journal, window Window) error {
	assessment, err := volumeepoch.Assess(saved.EnrollmentID, &saved, current)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeWindow, err)
	}
	if assessment.State != volumeepoch.Continuous {
		return fmt.Errorf("%w: source history is %s/%s", ErrUnsafeWindow, assessment.State, assessment.Reason)
	}
	b := window.Boundary
	if b.Version != BoundaryVersion || b.EnrollmentID != saved.EnrollmentID ||
		b.Epoch != saved.Epoch || !equalIdentity(b.Identity, saved.Identity) ||
		!equalIdentity(b.Identity, current.Identity) || b.StartUSN != saved.NextUSN ||
		len(window.Changes) > maxWindowChanges || b.SourceRecordCount != uint32(len(window.Changes)) {
		return fmt.Errorf("%w: boundary version, identity, epoch, cursor or bounded count mismatch", ErrUnsafeWindow)
	}
	start, err1 := canonicalUint(b.StartUSN)
	end, err2 := canonicalUint(b.NextUSN)
	journalEnd, err3 := canonicalUint(current.NextUSN)
	if err1 != nil || err2 != nil || err3 != nil || end <= start || end > journalEnd {
		return fmt.Errorf("%w: invalid bounded cursor progression", ErrUnsafeWindow)
	}
	for i, change := range window.Changes {
		cursor, err := canonicalUint(change.USN)
		wantLen := 0
		switch change.NTFSRecordVersion {
		case 2:
			wantLen = 16
		case 3:
			wantLen = 32
		}
		if change.Version != MinimalFactVersion || err != nil ||
			cursor < start || cursor >= end || wantLen == 0 ||
			!canonicalHex(change.FileReferenceHex, wantLen, true) ||
			!canonicalHex(change.ParentReferenceHex, wantLen, false) {
			return fmt.Errorf("%w: malformed minimal NTFS fact %d", ErrUnsafeWindow, i)
		}
		if i > 0 {
			previous, _ := canonicalUint(window.Changes[i-1].USN)
			if cursor < previous {
				return fmt.Errorf("%w: source facts not in journal cursor order", ErrUnsafeWindow)
			}
		}
	}
	return nil
}

func equalIdentity(left, right volumeepoch.Identity) bool {
	return strings.EqualFold(left.VolumeGUID, right.VolumeGUID) &&
		left.VolumeSerial == right.VolumeSerial && left.JournalID == right.JournalID
}

func canonicalUint(value string) (uint64, error) {
	if value != "0" && (len(value) == 0 || value[0] < '1' || value[0] > '9') {
		return 0, errors.New("invalid unsigned decimal")
	}
	if len(value) == 0 {
		return 0, errors.New("empty unsigned decimal")
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, errors.New("noncanonical unsigned decimal")
		}
	}
	return strconv.ParseUint(value, 10, 64)
}

func canonicalHex(value string, wantLen int, nonzero bool) bool {
	if len(value) != wantLen || strings.ToLower(value) != value {
		return false
	}
	bytes, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	if nonzero {
		for _, b := range bytes {
			if b != 0 {
				return true
			}
		}
		return false
	}
	return true
}
