// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/svc"
)

const (
	serviceName = "FIUSNProbe"

	fsctlQueryUSNJournal = 0x000900F4
	fsctlReadUSNJournal  = 0x000900BB

	fileReadData       = 0x00000001
	fileReadEA         = 0x00000008
	fileReadAttributes = 0x00000080
	readControl        = 0x00020000
	synchronize        = 0x00100000
	genericRead        = 0x80000000

	readBufferSize  = 1024 * 1024
	usnV2HeaderSize = 60
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procDeviceIoControl = kernel32.NewProc("DeviceIoControl")
)

type checkpoint struct {
	JournalID string `json:"journal_id"`
	NextUSN   string `json:"next_usn"`
}

type journalDataV0 struct {
	JournalID       uint64
	FirstUSN        int64
	NextUSN         int64
	LowestValidUSN  int64
	MaxUSN          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type readJournalDataV0 struct {
	StartUSN          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	JournalID         uint64
}

type accessCase struct {
	Name string
	Mask uint32
}

type accessResult struct {
	Name       string `json:"name"`
	AccessMask string `json:"access_mask"`

	OpenSucceeded bool   `json:"open_succeeded"`
	OpenError     string `json:"open_error,omitempty"`
	OpenErrorCode uint32 `json:"open_error_code,omitempty"`

	QueryAttempted bool   `json:"query_attempted"`
	QuerySucceeded bool   `json:"query_succeeded"`
	QueryError     string `json:"query_error,omitempty"`
	QueryErrorCode uint32 `json:"query_error_code,omitempty"`

	QueryJournalID string `json:"query_journal_id,omitempty"`
	QueryFirstUSN  string `json:"query_first_usn,omitempty"`
	QueryNextUSN   string `json:"query_next_usn,omitempty"`

	ReadAttempted bool   `json:"read_attempted"`
	ReadSucceeded bool   `json:"read_succeeded"`
	ReadError     string `json:"read_error,omitempty"`
	ReadErrorCode uint32 `json:"read_error_code,omitempty"`

	BytesReturned   uint32 `json:"bytes_returned,omitempty"`
	ContinuationUSN string `json:"continuation_usn,omitempty"`
	RecordCount     int    `json:"record_count"`
}

type probeResult struct {
	ObservedAt string `json:"observed_at"`

	Volume string `json:"volume"`

	CheckpointPath   string `json:"checkpoint_path,omitempty"`
	CheckpointLoaded bool   `json:"checkpoint_loaded"`
	CheckpointError  string `json:"checkpoint_error,omitempty"`

	JournalID string `json:"journal_id,omitempty"`
	StartUSN  string `json:"start_usn,omitempty"`

	Results []accessResult `json:"results"`
}

type serviceHandler struct{}

func main() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	if !isService {
		result := runProbe()

		if err := writeJSON(os.Stdout, result); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}

		if err := writeProbeResult(result); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}

		return
	}

	if err := svc.Run(serviceName, &serviceHandler{}); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func (h *serviceHandler) Execute(
	args []string,
	requests <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (bool, uint32) {
	status <- svc.Status{
		State: svc.StartPending,
	}

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		result := runProbe()

		if err := writeProbeResult(result); err != nil {
			_ = writeProbeFailure(err)
		}
	}()

	for {
		select {
		case <-done:
			return false, 0

		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus

			case svc.Stop, svc.Shutdown:
				status <- svc.Status{
					State: svc.StopPending,
				}
				return false, 0
			}
		}
	}
}

func runProbe() probeResult {
	result := probeResult{
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Volume:     `\\.\C:`,
		Results:    make([]accessResult, 0),
	}

	value, checkpointPath, err := loadCheckpoint()
	if err != nil {
		result.CheckpointError = err.Error()
		return result
	}

	result.CheckpointLoaded = true
	result.CheckpointPath = checkpointPath
	result.JournalID = value.JournalID
	result.StartUSN = value.NextUSN

	journalID, err := strconv.ParseUint(value.JournalID, 10, 64)
	if err != nil {
		result.CheckpointError = fmt.Sprintf("parse journal_id: %v", err)
		return result
	}

	startUSNUint, err := strconv.ParseUint(value.NextUSN, 10, 64)
	if err != nil {
		result.CheckpointError = fmt.Sprintf("parse next_usn: %v", err)
		return result
	}

	if startUSNUint > uint64(^uint64(0)>>1) {
		result.CheckpointError = "next_usn exceeds signed 64-bit range"
		return result
	}

	startUSN := int64(startUSNUint)

	tests := []accessCase{
		{
			Name: "NoAccess",
			Mask: 0,
		},
		{
			Name: "FileReadAttributes",
			Mask: fileReadAttributes,
		},
		{
			Name: "FileReadData",
			Mask: fileReadData,
		},
		{
			Name: "FileReadDataAttributes",
			Mask: fileReadData | fileReadAttributes,
		},
		{
			Name: "GenericReadComponentsWithoutStandardRights",
			Mask: fileReadData | fileReadEA | fileReadAttributes,
		},
		{
			Name: "GenericReadComponentsWithoutSynchronize",
			Mask: fileReadData | fileReadEA | fileReadAttributes | readControl,
		},
		{
			Name: "GenericReadComponents",
			Mask: fileReadData | fileReadEA | fileReadAttributes | readControl | synchronize,
		},
		{
			Name: "GenericRead",
			Mask: genericRead,
		},
	}

	for _, test := range tests {
		result.Results = append(
			result.Results,
			runAccessCase(
				result.Volume,
				test,
				startUSN,
				journalID,
			),
		)
	}

	return result
}

func runAccessCase(
	volume string,
	test accessCase,
	startUSN int64,
	journalID uint64,
) accessResult {
	result := accessResult{
		Name:       test.Name,
		AccessMask: fmt.Sprintf("0x%08X", test.Mask),
	}

	volumePath, err := syscall.UTF16PtrFromString(volume)
	if err != nil {
		result.OpenError = err.Error()
		return result
	}

	handle, err := syscall.CreateFile(
		volumePath,
		test.Mask,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		result.OpenError = err.Error()
		result.OpenErrorCode = windowsErrorCode(err)
		return result
	}
	defer syscall.CloseHandle(handle)

	result.OpenSucceeded = true

	result.QueryAttempted = true

	journal, err := queryJournal(handle)
	if err != nil {
		result.QueryError = err.Error()
		result.QueryErrorCode = windowsErrorCode(err)
	} else {
		result.QuerySucceeded = true
		result.QueryJournalID = strconv.FormatUint(journal.JournalID, 10)
		result.QueryFirstUSN = strconv.FormatInt(journal.FirstUSN, 10)
		result.QueryNextUSN = strconv.FormatInt(journal.NextUSN, 10)
	}

	result.ReadAttempted = true

	buffer, returned, err := readJournal(
		handle,
		startUSN,
		journalID,
	)
	if err != nil {
		result.ReadError = err.Error()
		result.ReadErrorCode = windowsErrorCode(err)
		return result
	}

	result.ReadSucceeded = true
	result.BytesReturned = returned

	continuation, recordCount, err := summarizeReadBuffer(buffer)
	if err != nil {
		result.ReadSucceeded = false
		result.ReadError = err.Error()
		return result
	}

	result.ContinuationUSN = continuation
	result.RecordCount = recordCount

	return result
}

func loadCheckpoint() (checkpoint, string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return checkpoint{}, "", errors.New("ProgramData is not set")
	}

	pattern := filepath.Join(
		programData,
		"FI",
		"state",
		"root-*-usn.json",
	)

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return checkpoint{}, "", err
	}

	switch len(matches) {
	case 0:
		return checkpoint{}, "", fmt.Errorf(
			"no FI governed-root checkpoint matched %q",
			pattern,
		)

	case 1:
		// Expected for this single-root Server 2016 lab.

	default:
		return checkpoint{}, "", fmt.Errorf(
			"expected one FI governed-root checkpoint, found %d",
			len(matches),
		)
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		return checkpoint{}, "", err
	}

	var value checkpoint
	if err := json.Unmarshal(data, &value); err != nil {
		return checkpoint{}, "", err
	}

	if value.JournalID == "" {
		return checkpoint{}, "", errors.New(
			"checkpoint journal_id is empty",
		)
	}

	if value.NextUSN == "" {
		return checkpoint{}, "", errors.New(
			"checkpoint next_usn is empty",
		)
	}

	return value, matches[0], nil
}

func queryJournal(handle syscall.Handle) (journalDataV0, error) {
	var journal journalDataV0
	var returned uint32

	r1, _, callErr := procDeviceIoControl.Call(
		uintptr(handle),
		uintptr(fsctlQueryUSNJournal),
		0,
		0,
		uintptr(unsafe.Pointer(&journal)),
		unsafe.Sizeof(journal),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)

	if r1 == 0 {
		return journalDataV0{}, normalizeCallError(callErr)
	}

	if returned < uint32(unsafe.Sizeof(journal)) {
		return journalDataV0{}, fmt.Errorf(
			"FSCTL_QUERY_USN_JOURNAL returned %d bytes; expected at least %d",
			returned,
			unsafe.Sizeof(journal),
		)
	}

	return journal, nil
}

func readJournal(
	handle syscall.Handle,
	startUSN int64,
	journalID uint64,
) ([]byte, uint32, error) {
	request := readJournalDataV0{
		StartUSN:          startUSN,
		ReasonMask:        0xFFFFFFFF,
		ReturnOnlyOnClose: 0,
		Timeout:           0,
		BytesToWaitFor:    0,
		JournalID:         journalID,
	}

	buffer := make([]byte, readBufferSize)

	var returned uint32

	r1, _, callErr := procDeviceIoControl.Call(
		uintptr(handle),
		uintptr(fsctlReadUSNJournal),
		uintptr(unsafe.Pointer(&request)),
		unsafe.Sizeof(request),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)

	if r1 == 0 {
		return nil, 0, normalizeCallError(callErr)
	}

	if returned < 8 {
		return nil, returned, fmt.Errorf(
			"FSCTL_READ_USN_JOURNAL returned only %d bytes",
			returned,
		)
	}

	return append([]byte(nil), buffer[:returned]...), returned, nil
}

func summarizeReadBuffer(buffer []byte) (string, int, error) {
	if len(buffer) < 8 {
		return "", 0, errors.New(
			"USN buffer is shorter than continuation USN",
		)
	}

	continuation := int64(
		binary.LittleEndian.Uint64(buffer[:8]),
	)

	offset := 8
	recordCount := 0

	for offset < len(buffer) {
		if len(buffer)-offset < usnV2HeaderSize {
			return "", 0, fmt.Errorf(
				"trailing USN data is shorter than V2 header: %d bytes",
				len(buffer)-offset,
			)
		}

		record := buffer[offset:]

		recordLength := int(
			binary.LittleEndian.Uint32(record[0:4]),
		)

		if recordLength < usnV2HeaderSize {
			return "", 0, fmt.Errorf(
				"invalid USN record length %d",
				recordLength,
			)
		}

		if offset+recordLength > len(buffer) {
			return "", 0, fmt.Errorf(
				"USN record length %d exceeds remaining buffer %d",
				recordLength,
				len(buffer)-offset,
			)
		}

		major := binary.LittleEndian.Uint16(record[4:6])
		minor := binary.LittleEndian.Uint16(record[6:8])

		if major != 2 {
			return "", 0, fmt.Errorf(
				"probe received unsupported USN record version %d.%d",
				major,
				minor,
			)
		}

		recordCount++
		offset += recordLength
	}

	return strconv.FormatInt(continuation, 10), recordCount, nil
}

func writeProbeResult(result probeResult) error {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return errors.New("ProgramData is not set")
	}

	stateDir := filepath.Join(
		programData,
		"FI",
		"state",
	)

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}

	path := filepath.Join(
		stateDir,
		"usn-access-matrix-probe.json",
	)

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return writeJSON(file, result)
}

func writeProbeFailure(probeErr error) error {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return probeErr
	}

	stateDir := filepath.Join(
		programData,
		"FI",
		"state",
	)

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}

	path := filepath.Join(
		stateDir,
		"usn-access-matrix-probe-error.txt",
	)

	return os.WriteFile(
		path,
		[]byte(probeErr.Error()+"\n"),
		0600,
	)
}

func writeJSON(
	file *os.File,
	value any,
) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func normalizeCallError(err error) error {
	if err == nil {
		return errors.New(
			"Windows call failed without an error code",
		)
	}

	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New(
			"Windows call failed without an error code",
		)
	}

	return err
}

func windowsErrorCode(err error) uint32 {
	var errno syscall.Errno

	if errors.As(err, &errno) {
		return uint32(errno)
	}

	return 0
}
