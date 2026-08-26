// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package supportingstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	SchemaVersion           = "fi-supporting-sid-state/0.1"
	DefaultStateFileName    = "windows-supporting-sids.json"
	maxRelevantSIDs         = 262144
	moveFileReplaceExisting = 0x00000001
	moveFileWriteThrough    = 0x00000008
	timestampLayout         = "2006-01-02T15:04:05.000000000Z"
)

var procMoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

// State is FI-owned operational state identifying current-domain SIDs that have
// become relevant to governed history on this collector host.
//
// It is not an authoritative customer-source record. The source facts that made
// a SID relevant remain in FI spool/history. This state only bounds which AD
// principals a later supporting-source refresh should ask the directory source
// to refresh.
type State struct {
	Version             string   `json:"version"`
	ComputerNetBIOSName string   `json:"computer_netbios_name"`
	ComputerDNSFQDN     string   `json:"computer_dns_fqdn,omitempty"`
	DomainDNSName       string   `json:"domain_dns_name"`
	DomainSIDPrefix     string   `json:"domain_sid_prefix"`
	RelevantSIDs        []string `json:"relevant_sids"`
	UpdatedAt           string   `json:"updated_at"`
}

func DefaultPath() (string, error) {
	base := os.Getenv("FI_STATE_DIR")
	if base == "" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return "", errors.New("ProgramData is not set")
		}
		base = filepath.Join(programData, "FI", "state")
	}
	return filepath.Join(base, DefaultStateFileName), nil
}

func Load(path string) (State, error) {
	file, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var value State
	if err := decoder.Decode(&value); err != nil {
		return State{}, fmt.Errorf("invalid supporting SID state: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return State{}, errors.New("invalid supporting SID state: trailing JSON value")
		}
		return State{}, fmt.Errorf("invalid supporting SID state: trailing data: %w", err)
	}

	if err := Validate(value); err != nil {
		return State{}, err
	}
	return value, nil
}

// Merge adds newly relevant current-domain SIDs without deleting SIDs that were
// relevant to earlier governed history.
//
// Keeping this set monotonic is intentional. A SID that disappears from a
// current ACL, share, local group, or directory result may still be required to
// explain historical FI records.
func Merge(path string, current State, newSIDs []string) (State, error) {
	if current.Version == "" {
		current.Version = SchemaVersion
	}
	if current.UpdatedAt == "" {
		current.UpdatedAt = canonicalNow()
	}

	set := make(map[string]struct{}, len(current.RelevantSIDs)+len(newSIDs))
	for _, sid := range current.RelevantSIDs {
		set[sid] = struct{}{}
	}
	for _, sid := range newSIDs {
		if strings.TrimSpace(sid) == "" {
			return State{}, errors.New("invalid supporting SID state: empty SID")
		}
		set[sid] = struct{}{}
	}
	if len(set) > maxRelevantSIDs {
		return State{}, fmt.Errorf(
			"supporting SID state exceeds limit: %d > %d",
			len(set),
			maxRelevantSIDs,
		)
	}

	current.RelevantSIDs = current.RelevantSIDs[:0]
	for sid := range set {
		current.RelevantSIDs = append(current.RelevantSIDs, sid)
	}
	sort.Strings(current.RelevantSIDs)
	current.UpdatedAt = canonicalNow()

	if err := Save(path, current); err != nil {
		return State{}, err
	}
	return current, nil
}

func Save(path string, value State) error {
	if err := Validate(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	temp, err := os.CreateTemp(filepath.Dir(path), ".fi-supporting-sids-*.tmp")
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

func Validate(value State) error {
	if value.Version != SchemaVersion {
		return errors.New("invalid supporting SID state: version")
	}
	if strings.TrimSpace(value.ComputerNetBIOSName) == "" {
		return errors.New("invalid supporting SID state: computer_netbios_name")
	}
	if strings.TrimSpace(value.DomainDNSName) == "" {
		return errors.New("invalid supporting SID state: domain_dns_name")
	}
	if !validAccountDomainSIDPrefix(value.DomainSIDPrefix) {
		return errors.New("invalid supporting SID state: domain_sid_prefix")
	}
	if len(value.RelevantSIDs) > maxRelevantSIDs {
		return errors.New("invalid supporting SID state: relevant_sids limit")
	}
	if !sort.StringsAreSorted(value.RelevantSIDs) {
		return errors.New("invalid supporting SID state: relevant_sids unsorted")
	}
	for index, sid := range value.RelevantSIDs {
		if !sidInDomain(sid, value.DomainSIDPrefix) {
			return fmt.Errorf(
				"invalid supporting SID state: relevant_sids[%d] outside domain",
				index,
			)
		}
		if index > 0 && sid == value.RelevantSIDs[index-1] {
			return fmt.Errorf(
				"invalid supporting SID state: relevant_sids[%d] duplicate",
				index,
			)
		}
	}

	parsed, err := time.Parse(timestampLayout, value.UpdatedAt)
	if err != nil || parsed.Format(timestampLayout) != value.UpdatedAt {
		return errors.New("invalid supporting SID state: updated_at")
	}
	return nil
}

func New(
	computerNetBIOSName string,
	computerDNSFQDN string,
	domainDNSName string,
	domainSIDPrefix string,
	relevantSIDs []string,
) (State, error) {
	value := State{
		Version:             SchemaVersion,
		ComputerNetBIOSName: computerNetBIOSName,
		ComputerDNSFQDN:     computerDNSFQDN,
		DomainDNSName:       domainDNSName,
		DomainSIDPrefix:     domainSIDPrefix,
		RelevantSIDs:        append([]string(nil), relevantSIDs...),
		UpdatedAt:           canonicalNow(),
	}
	sort.Strings(value.RelevantSIDs)

	unique := value.RelevantSIDs[:0]
	for _, sid := range value.RelevantSIDs {
		if len(unique) == 0 || unique[len(unique)-1] != sid {
			unique = append(unique, sid)
		}
	}
	value.RelevantSIDs = unique

	if err := Validate(value); err != nil {
		return State{}, err
	}
	return value, nil
}

func canonicalNow() string {
	return time.Now().UTC().Format(timestampLayout)
}

func validAccountDomainSIDPrefix(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 7 {
		return false
	}
	return parts[0] == "S" &&
		parts[1] == "1" &&
		parts[2] == "5" &&
		parts[3] == "21" &&
		parts[4] != "" &&
		parts[5] != "" &&
		parts[6] != ""
}

func sidInDomain(sid string, prefix string) bool {
	return sid == prefix || strings.HasPrefix(sid, prefix+"-")
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
