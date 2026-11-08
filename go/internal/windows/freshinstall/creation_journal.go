// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package freshinstall also specifies the crash-evidence protocol for the
// planned version-2 creation-only Windows installer. This journal is evidence,
// NOT an approval signature, trusted storage, or permission to run a service.
package freshinstall

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	CreationJournalVersion = "fi-windows-v2-create-journal/1"
	maxCreationRecordBytes = 2048
	maxCreationRecords = 2 + len(creationSteps)*2
	maxCreationJournalBytes = maxCreationRecordBytes * maxCreationRecords
)

type CreationStep string

const (
	CreateProgramRoot       CreationStep = "CreateProgramRoot"
	CreateDataRoot          CreationStep = "CreateDataRoot"
	ProtectNewRoots         CreationStep = "ProtectNewRoots"
	CreateSignedBinaries    CreationStep = "CreateSignedBinaries"
	CreateOperationalConfig CreationStep = "CreateOperationalConfig"
	CreateSignedScopeGrant  CreationStep = "CreateSignedScopeGrant"
	CreateDisabledServices  CreationStep = "CreateDisabledServices"
	CommitProtectedState    CreationStep = "CommitProtectedState"
)

// This is a protocol order, not an executable installer plan. A future
// backend must prove every step is create-only, its outputs are durable,
// any ACL/SCM changes affect ONLY transaction-created objects, and service
// activation is separately gated on an authenticated installed authority.
// No upgrade, replace, reconfigure, removal or service start is represented.
var creationSteps = [...]CreationStep{
	CreateProgramRoot,
	CreateDataRoot,
	ProtectNewRoots,
	CreateSignedBinaries,
	CreateOperationalConfig,
	CreateSignedScopeGrant,
	CreateDisabledServices,
	CommitProtectedState,
}

type CreationEvent string

const (
	CreationBegin    CreationEvent = "Begin"
	CreationIntent   CreationEvent = "CreateIntent"
	CreationObserved CreationEvent = "CreatedAndSynced"
	CreationComplete CreationEvent = "CreationComplete"
)

// CreationRecord is a bounded, canonical, append-only record. Hashing detects
// accidental modifications and gaps; because there is no secret this does
// NOT authenticate the writer or prevent malicious record replacement.
// A future installer must establish ACL/protected-storage provenance separately.
type CreationRecord struct {
	Version        string        `json:"version"`
	Sequence       uint64        `json:"sequence"`
	Event          CreationEvent `json:"event"`
	InstallationID string        `json:"installation_id"`
	ScopeSHA256    string        `json:"scope_sha256"`
	Step           CreationStep  `json:"step,omitempty"`
	PreviousSHA256 string        `json:"previous_sha256,omitempty"`
	RecordSHA256   string        `json:"record_sha256"`
}

type CreationStatus struct {
	InstallationID string
	ScopeSHA256    string
	LastSHA256     string
	Records        uint64
	CreatedSteps   int
	NextStep       CreationStep
	// InDoubt is true for an intent without a durable matching Created event,
	// including the unavoidable crash window between native creation and
	// successful journal acknowledgement. NEVER auto-delete or auto-resume.
	InDoubt  bool
	Complete bool
}

var (
	ErrInvalidCreationJournal = errors.New("FI v2 creation journal is invalid")
	ErrCreationInDoubt        = errors.New("FI v2 creation intent requires manual recovery")
)

// CreationSink must durably append exactly one complete record (including
// newline) and sync it BEFORE reporting success. An error can mean a partial
// write, and that outcome always requires manual recovery: it must NEVER
// cause a silent new-install retry. This package provides no native sink yet.
type CreationSink interface {
	AppendAndSync(record []byte) error
}

// CreationBackend is deliberately unimplemented by any native code. Create
// MUST be create-only and return success only when the exact step's effects
// are fully durable and verified. On an error, effects MAY have occurred;
// callers MUST NOT delete or repeat them without separate ownership evidence.
type CreationBackend interface {
	Create(step CreationStep) error
}

// executeCreation is deliberately package-private and NOT wired to fi-install.
// Installing services must remain impossible until real operator consent,
// native protected state, and atomic create-only backend are implemented.
func executeCreation(
	sink CreationSink,
	backend CreationBackend,
	installationID, scopeSHA256 string,
) error {
	if sink == nil || backend == nil {
		return fmt.Errorf("%w: sink and backend are required", ErrInvalidCreationJournal)
	}
	if !validInstallHex128(installationID) || !validLowerSHA256(scopeSHA256) {
		return fmt.Errorf("%w: invalid first-install identity or canonical scope", ErrInvalidCreationJournal)
	}
	var previous string
	var sequence uint64
	appendRecord := func(event CreationEvent, step CreationStep) error {
		sequence++
		record := CreationRecord{
			Version: CreationJournalVersion,
			Sequence: sequence,
			Event: event,
			InstallationID: installationID,
			ScopeSHA256: scopeSHA256,
			Step: step,
			PreviousSHA256: previous,
		}
		data, hash, err := encodeCreationRecord(record)
		if err != nil {
			return err
		}
		if err := sink.AppendAndSync(data); err != nil {
			return fmt.Errorf("%w: durable %s record for %s: %v", ErrCreationInDoubt, event, step, err)
		}
		previous = hash
		return nil
	}
	if err := appendRecord(CreationBegin, ""); err != nil {
		return err
	}
	for _, step := range creationSteps {
		// The write-ahead intent MUST be durable before a native mutation.
		if err := appendRecord(CreationIntent, step); err != nil {
			return err
		}
		if err := backend.Create(step); err != nil {
			// Failure may have occurred after partial native creation. Preserve
			// the pending intent and refuse automatic deletion or retry.
			return fmt.Errorf("%w: create-only step %s: %v", ErrCreationInDoubt, step, err)
		}
		if err := appendRecord(CreationObserved, step); err != nil {
			return err
		}
	}
	if err := appendRecord(CreationComplete, ""); err != nil {
		return err
	}
	return nil
}

func encodeCreationRecord(record CreationRecord) ([]byte, string, error) {
	record.RecordSHA256 = ""
	withoutHash, err := json.Marshal(record)
	if err != nil {
		return nil, "", fmt.Errorf("%w: encode: %v", ErrInvalidCreationJournal, err)
	}
	digest := sha256.Sum256(withoutHash)
	record.RecordSHA256 = hex.EncodeToString(digest[:])
	withHash, err := json.Marshal(record)
	if err != nil {
		return nil, "", fmt.Errorf("%w: encode: %v", ErrInvalidCreationJournal, err)
	}
	if len(withHash)+1 > maxCreationRecordBytes {
		return nil, "", fmt.Errorf("%w: record too large", ErrInvalidCreationJournal)
	}
	return append(withHash, '\n'), record.RecordSHA256, nil
}

// InspectCreationJournal reconstructs only the *recorded* state. The physical
// host must be rediscovered and authenticated separately. Any incomplete
// journal always blocks an automatic retry, including a crash after the last
// CreatedAndSynced but before CreationComplete.
func InspectCreationJournal(reader io.Reader) (CreationStatus, error) {
	if reader == nil {
		return CreationStatus{}, fmt.Errorf("%w: reader is required", ErrInvalidCreationJournal)
	}
	// Unlike bufio.Scanner, this refuses a truncated final record with no
	// newline. The bound prevents an untrusted journal from allocating
	// arbitrary memory during crash inspection.
	data, err := io.ReadAll(io.LimitReader(reader, maxCreationJournalBytes+1))
	if err != nil {
		return CreationStatus{}, fmt.Errorf("%w: read: %v", ErrInvalidCreationJournal, err)
	}
	if len(data) == 0 || len(data) > maxCreationJournalBytes || data[len(data)-1] != '\n' {
		return CreationStatus{}, fmt.Errorf("%w: empty, oversized or unterminated journal", ErrInvalidCreationJournal)
	}
	records := bytes.Split(data[:len(data)-1], []byte{'\n'})
	var state CreationStatus
	var expectedStep int
	var pending bool
	for _, raw := range records {
		if len(raw) == 0 || len(raw)+1 > maxCreationRecordBytes {
			return CreationStatus{}, ErrInvalidCreationJournal
		}
		if state.Records >= maxCreationRecords {
			return CreationStatus{}, fmt.Errorf("%w: excessive record count", ErrInvalidCreationJournal)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var event CreationRecord
		if err := dec.Decode(&event); err != nil {
			return CreationStatus{}, fmt.Errorf("%w: decode: %v", ErrInvalidCreationJournal, err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return CreationStatus{}, fmt.Errorf("%w: trailing data", ErrInvalidCreationJournal)
		}
		canonical, hash, err := encodeCreationRecord(event)
		if err != nil || !bytes.Equal(canonical[:len(canonical)-1], raw) ||
			!validLowerSHA256(event.RecordSHA256) ||
			subtle.ConstantTimeCompare([]byte(event.RecordSHA256), []byte(hash)) != 1 {
			return CreationStatus{}, fmt.Errorf("%w: noncanonical or altered record", ErrInvalidCreationJournal)
		}
		if event.Version != CreationJournalVersion ||
			!validInstallHex128(event.InstallationID) || !validLowerSHA256(event.ScopeSHA256) ||
			event.Sequence != state.Records+1 || event.PreviousSHA256 != state.LastSHA256 ||
			state.Complete {
			return CreationStatus{}, fmt.Errorf("%w: invalid journal identity or sequence", ErrInvalidCreationJournal)
		}
		if state.Records == 0 {
			if event.Event != CreationBegin || event.Step != "" || event.PreviousSHA256 != "" {
				return CreationStatus{}, fmt.Errorf("%w: first record must begin new installation", ErrInvalidCreationJournal)
			}
			state.InstallationID = event.InstallationID
			state.ScopeSHA256 = event.ScopeSHA256
		} else if event.InstallationID != state.InstallationID || event.ScopeSHA256 != state.ScopeSHA256 {
			return CreationStatus{}, fmt.Errorf("%w: cross-installation record substitution", ErrInvalidCreationJournal)
		} else {
			switch event.Event {
			case CreationIntent:
				if pending || expectedStep >= len(creationSteps) ||
					event.Step != creationSteps[expectedStep] {
					return CreationStatus{}, fmt.Errorf("%w: duplicate or out-of-order create intent", ErrInvalidCreationJournal)
				}
				pending = true
			case CreationObserved:
				if !pending || expectedStep >= len(creationSteps) ||
					event.Step != creationSteps[expectedStep] {
					return CreationStatus{}, fmt.Errorf("%w: created event without matching intent", ErrInvalidCreationJournal)
				}
				expectedStep++
				pending = false
			case CreationComplete:
				if pending || expectedStep != len(creationSteps) || event.Step != "" {
					return CreationStatus{}, fmt.Errorf("%w: completion before durable full creation", ErrInvalidCreationJournal)
				}
				state.Complete = true
			default:
				return CreationStatus{}, fmt.Errorf("%w: unknown or repeated begin event", ErrInvalidCreationJournal)
			}
		}
		state.Records++
		state.LastSHA256 = hash
	}
	if state.Records == 0 {
		return CreationStatus{}, fmt.Errorf("%w: empty journal", ErrInvalidCreationJournal)
	}
	state.CreatedSteps = expectedStep
	state.InDoubt = !state.Complete
	if expectedStep < len(creationSteps) {
		state.NextStep = creationSteps[expectedStep]
	}
	if state.InDoubt {
		return state, ErrCreationInDoubt
	}
	return state, nil
}

func validInstallHex128(value string) bool {
	if len(value) != 32 || value == strings.Repeat("0", 32) {
		return false
	}
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == value
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == value
}
