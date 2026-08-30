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
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/svc"
)

const (
	probeVersion = "windows-server-2022-usn-characterization/0.2"
	serviceName  = "FIUSNProbe2022"

	probeInputPath  = `C:\FI-Test\usnprobe\input-2022.json`
	probeResultPath = `C:\FI-Test\usnprobe\usn-access-matrix-2022.json`
	probeErrorPath  = `C:\FI-Test\usnprobe\usn-access-matrix-2022-error.txt`

	fsctlQueryUSNJournal = 0x000900F4
	fsctlReadUSNJournal  = 0x000900BB

	fileReadData       = 0x00000001
	fileReadEA         = 0x00000008
	fileReadAttributes = 0x00000080
	readControl        = 0x00020000
	synchronize        = 0x00100000
	genericRead        = 0x80000000

	tokenQuery            = 0x0008
	tokenAdjustPrivileges = 0x0020
	sePrivilegeEnabled    = 0x00000002
	errorNotAllAssigned   = 1300

	readBufferSize  = 1024 * 1024
	usnV2HeaderSize = 60
)

var (
	advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	procDeviceIoControl       = kernel32.NewProc("DeviceIoControl")
	procGetCurrentProcess     = kernel32.NewProc("GetCurrentProcess")
	procLookupPrivilegeValueW = advapi32.NewProc("LookupPrivilegeValueW")
	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procSetLastError          = kernel32.NewProc("SetLastError")
)

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

type journalDataV0 struct {
	JournalID       uint64
	FirstUSN        int64
	NextUSN         int64
	LowestValidUSN  int64
	MaxUSN          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	LUID       luid
	Attributes uint32
}

type privilegeResult struct {
	Name            string `json:"name"`
	EnableAttempted bool   `json:"enable_attempted"`
	PresentInToken  bool   `json:"present_in_token"`
	Enabled         bool   `json:"enabled"`
	Error           string `json:"error,omitempty"`
	ErrorCode       uint32 `json:"error_code,omitempty"`
}

type probeInput struct {
	JournalID string `json:"journal_id"`
	StartUSN  string `json:"start_usn"`
}

type probeResult struct {
	Version    string `json:"version"`
	ObservedAt string `json:"observed_at"`

	Volume string `json:"volume"`

	InputPath   string `json:"input_path"`
	InputLoaded bool   `json:"input_loaded"`
	InputError  string `json:"input_error,omitempty"`

	JournalID string `json:"journal_id,omitempty"`
	StartUSN  string `json:"start_usn,omitempty"`

	SeManageVolumePrivilege privilegeResult `json:"se_manage_volume_privilege"`

	Results []accessResult `json:"results"`
}

type readJournalDataV0 struct {
	StartUSN          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	JournalID         uint64
}

type serviceHandler struct{}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

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

func enablePrivilege(name string) privilegeResult {
	result := privilegeResult{
		Name:            name,
		EnableAttempted: true,
	}

	process, _, _ := procGetCurrentProcess.Call()

	var token syscall.Handle
	r1, _, callErr := procOpenProcessToken.Call(
		process,
		uintptr(tokenQuery|tokenAdjustPrivileges),
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 == 0 {
		err := normalizeCallError(callErr)
		result.Error = fmt.Sprintf("OpenProcessToken: %v", err)
		result.ErrorCode = windowsErrorCode(err)
		return result
	}
	defer syscall.CloseHandle(token)

	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	var privilegeLUID luid
	r1, _, callErr = procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(&privilegeLUID)),
	)
	if r1 == 0 {
		err := normalizeCallError(callErr)
		result.Error = fmt.Sprintf("LookupPrivilegeValueW: %v", err)
		result.ErrorCode = windowsErrorCode(err)
		return result
	}

	state := tokenPrivileges{
		PrivilegeCount: 1,
	}
	state.Privileges[0] = luidAndAttributes{
		LUID:       privilegeLUID,
		Attributes: sePrivilegeEnabled,
	}

	_, _, _ = procSetLastError.Call(0)

	r1, _, callErr = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&state)),
		0,
		0,
		0,
	)
	if r1 == 0 {
		err := normalizeCallError(callErr)
		result.Error = fmt.Sprintf("AdjustTokenPrivileges: %v", err)
		result.ErrorCode = windowsErrorCode(err)
		return result
	}

	errorCode := windowsErrorCode(callErr)

	switch errorCode {
	case 0:
		result.PresentInToken = true
		result.Enabled = true
		return result

	case errorNotAllAssigned:
		result.Error = "privilege is not present in the service token"
		result.ErrorCode = errorCode
		return result

	default:
		result.Error = fmt.Sprintf(
			"AdjustTokenPrivileges succeeded with unexpected last error %d: %v",
			errorCode,
			callErr,
		)
		result.ErrorCode = errorCode
		return result
	}
}

func loadProbeInput() (probeInput, error) {
	data, err := os.ReadFile(probeInputPath)
	if err != nil {
		return probeInput{}, err
	}

	var value probeInput
	if err := json.Unmarshal(data, &value); err != nil {
		return probeInput{}, err
	}

	if value.JournalID == "" {
		return probeInput{}, errors.New(
			"input journal_id is empty",
		)
	}

	if value.StartUSN == "" {
		return probeInput{}, errors.New(
			"input start_usn is empty",
		)
	}

	return value, nil
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

func runProbe() probeResult {
	result := probeResult{
		Version:    probeVersion,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Volume:     `\\.\C:`,
		InputPath:  probeInputPath,
		Results:    make([]accessResult, 0),
	}

	result.SeManageVolumePrivilege = enablePrivilege(
		"SeManageVolumePrivilege",
	)

	value, err := loadProbeInput()
	if err != nil {
		result.InputError = err.Error()
		return result
	}

	result.InputLoaded = true
	result.JournalID = value.JournalID
	result.StartUSN = value.StartUSN

	journalID, err := strconv.ParseUint(value.JournalID, 10, 64)
	if err != nil {
		result.InputError = fmt.Sprintf("parse journal_id: %v", err)
		return result
	}

	startUSNUint, err := strconv.ParseUint(value.StartUSN, 10, 64)
	if err != nil {
		result.InputError = fmt.Sprintf("parse start_usn: %v", err)
		return result
	}

	if startUSNUint > uint64(^uint64(0)>>1) {
		result.InputError = "start_usn exceeds signed 64-bit range"
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

func windowsErrorCode(err error) uint32 {
	var errno syscall.Errno

	if errors.As(err, &errno) {
		return uint32(errno)
	}

	return 0
}

func writeJSON(
	file *os.File,
	value any,
) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeProbeFailure(probeErr error) error {
	return os.WriteFile(
		probeErrorPath,
		[]byte(probeErr.Error()+"\n"),
		0600,
	)
}

func writeProbeResult(result probeResult) error {
	file, err := os.Create(probeResultPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return writeJSON(file, result)
}
