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
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/svc"
)

const (
	probeVersion = "windows-server-2025-protected-containment/0.1"
	serviceName  = "FIContainmentProbe2025"

	probeInputPath  = `C:\FI-Test\containment\input-2025.json`
	probeResultPath = `C:\FI-Test\containment\containment-2025.json`
	probeErrorPath  = `C:\FI-Test\containment\containment-2025-error.txt`

	fileIDType         = 0
	fileReadAttributes = 0x00000080
	fileNameNormalized = 0x0000
	volumeNameGUID     = 0x0001
	maximumPathUnits   = 64 * 1024

	tokenQuery            = 0x0008
	tokenAdjustPrivileges = 0x0020
	sePrivilegeEnabled    = 0x00000002
	errorNotAllAssigned   = 1300
)

type fileIDDescriptor struct {
	Size       uint32
	Type       uint32
	Identifier [16]byte
}

type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	LUID       luid
	Attributes uint32
}

type openResult struct {
	Attempted     bool   `json:"attempted"`
	OpenSucceeded bool   `json:"open_succeeded"`
	Error         string `json:"error,omitempty"`
	ErrorCode     uint32 `json:"error_code,omitempty"`
	FinalPath     string `json:"final_path,omitempty"`
	Contained     *bool  `json:"contained,omitempty"`
}

type privilegeResult struct {
	Name             string `json:"name"`
	EnableAttempted  bool   `json:"enable_attempted"`
	PresentInToken   bool   `json:"present_in_token"`
	InitialEnabled   bool   `json:"initial_enabled"`
	EnabledForRetry  bool   `json:"enabled_for_retry"`
	RestoreAttempted bool   `json:"restore_attempted"`
	RestoreSucceeded bool   `json:"restore_succeeded"`
	RestoreError     string `json:"restore_error,omitempty"`
	RestoreErrorCode uint32 `json:"restore_error_code,omitempty"`
}

type privilegeScope struct {
	Token         syscall.Handle
	Previous      tokenPrivileges
	RestoreNeeded bool
}

type probeInput struct {
	GovernedRoot        string `json:"governed_root"`
	FileReferenceNumber string `json:"file_reference_number"`
	SequenceNumber      string `json:"sequence_number"`
	TargetDescription   string `json:"target_description,omitempty"`
}

type probeResult struct {
	Version    string `json:"version"`
	ObservedAt string `json:"observed_at"`

	InputPath   string `json:"input_path"`
	InputLoaded bool   `json:"input_loaded"`
	InputError  string `json:"input_error,omitempty"`

	GovernedRoot        string `json:"governed_root,omitempty"`
	RootFinalPath       string `json:"root_final_path,omitempty"`
	FileReferenceNumber string `json:"file_reference_number,omitempty"`
	SequenceNumber      string `json:"sequence_number,omitempty"`
	TargetDescription   string `json:"target_description,omitempty"`

	BeforePrivilege openResult      `json:"before_privilege"`
	SeBackup        privilegeResult `json:"se_backup_privilege"`
	WithPrivilege   openResult      `json:"with_privilege"`
	AfterRestore    openResult      `json:"after_restore"`
}

type serviceHandler struct{}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

var (
	advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	procGetCurrentProcess     = kernel32.NewProc("GetCurrentProcess")
	procGetFinalPathName      = kernel32.NewProc("GetFinalPathNameByHandleW")
	procLookupPrivilegeValueW = advapi32.NewProc("LookupPrivilegeValueW")
	procOpenFileByID          = kernel32.NewProc("OpenFileById")
	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procSetLastError          = kernel32.NewProc("SetLastError")
)

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
	status <- svc.Status{State: svc.StartPending}
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
				status <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

func enableBackupPrivilege() (privilegeScope, privilegeResult, error) {
	result := privilegeResult{
		Name:            "SeBackupPrivilege",
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
		return privilegeScope{}, result, fmt.Errorf("OpenProcessToken: %w", err)
	}

	closeOnError := true
	defer func() {
		if closeOnError {
			_ = syscall.CloseHandle(token)
		}
	}()

	name, err := syscall.UTF16PtrFromString("SeBackupPrivilege")
	if err != nil {
		return privilegeScope{}, result, err
	}

	var privilegeLUID luid
	r1, _, callErr = procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&privilegeLUID)),
	)
	if r1 == 0 {
		return privilegeScope{}, result,
			fmt.Errorf("LookupPrivilegeValueW: %w", normalizeCallError(callErr))
	}

	newState := tokenPrivileges{PrivilegeCount: 1}
	newState.Privileges[0] = luidAndAttributes{
		LUID:       privilegeLUID,
		Attributes: sePrivilegeEnabled,
	}

	var previous tokenPrivileges
	var previousLength uint32

	_, _, _ = procSetLastError.Call(0)

	r1, _, callErr = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&newState)),
		unsafe.Sizeof(previous),
		uintptr(unsafe.Pointer(&previous)),
		uintptr(unsafe.Pointer(&previousLength)),
	)
	if r1 == 0 {
		return privilegeScope{}, result,
			fmt.Errorf("AdjustTokenPrivileges: %w", normalizeCallError(callErr))
	}

	switch code := windowsErrorCode(callErr); code {
	case 0:
		result.PresentInToken = true
		result.EnabledForRetry = true

		if previous.PrivilegeCount == 0 {
			result.InitialEnabled = true
		} else {
			result.InitialEnabled =
				previous.Privileges[0].Attributes&sePrivilegeEnabled != 0
		}

		closeOnError = false

		return privilegeScope{
			Token:         token,
			Previous:      previous,
			RestoreNeeded: previous.PrivilegeCount > 0,
		}, result, nil

	case errorNotAllAssigned:
		return privilegeScope{}, result,
			errors.New("SeBackupPrivilege is not present in the service token")

	default:
		return privilegeScope{}, result,
			fmt.Errorf(
				"AdjustTokenPrivileges returned Windows error %d: %w",
				code,
				normalizeCallError(callErr),
			)
	}
}

func finalVolumePath(handle syscall.Handle) (string, error) {
	buffer := make([]uint16, 512)

	for attempts := 0; attempts < 3; attempts++ {
		length, _, callErr := procGetFinalPathName.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			fileNameNormalized|volumeNameGUID,
		)
		if length == 0 {
			return "", normalizeCallError(callErr)
		}
		if length < uintptr(len(buffer)) {
			return syscall.UTF16ToString(buffer[:length]), nil
		}
		if length >= uintptr(maximumPathUnits) {
			return "", errors.New("final path exceeds bounded UTF-16 limit")
		}

		buffer = make([]uint16, int(length)+1)
	}

	return "", errors.New("final path exceeded retry bound")
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

	if strings.TrimSpace(value.GovernedRoot) == "" {
		return probeInput{}, errors.New("governed_root is empty")
	}
	if strings.TrimSpace(value.FileReferenceNumber) == "" {
		return probeInput{}, errors.New("file_reference_number is empty")
	}
	if strings.TrimSpace(value.SequenceNumber) == "" {
		return probeInput{}, errors.New("sequence_number is empty")
	}

	return value, nil
}

func normalizeCallError(err error) error {
	if err == nil {
		return errors.New("Windows call failed without an error code")
	}

	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New("Windows call failed without an error code")
	}

	return err
}

func openFileByID(
	volumeHint syscall.Handle,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
) (syscall.Handle, error) {
	fileID := fileReferenceNumber | uint64(sequenceNumber)<<48

	descriptor := fileIDDescriptor{
		Size: uint32(unsafe.Sizeof(fileIDDescriptor{})),
		Type: fileIDType,
	}
	binary.LittleEndian.PutUint64(descriptor.Identifier[:8], fileID)

	r1, _, callErr := procOpenFileByID.Call(
		uintptr(volumeHint),
		uintptr(unsafe.Pointer(&descriptor)),
		0,
		uintptr(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE),
		0,
		uintptr(syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT),
	)
	runtime.KeepAlive(&descriptor)

	handle := syscall.Handle(r1)
	if handle == syscall.InvalidHandle {
		return syscall.InvalidHandle, normalizeCallError(callErr)
	}

	return handle, nil
}

func openPath(path string) (syscall.Handle, error) {
	units, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	return syscall.CreateFile(
		units,
		fileReadAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func pathContainedBy(root, target string) bool {
	root = strings.TrimRight(root, `\`)
	target = strings.TrimRight(target, `\`)

	if root == "" || target == "" {
		return false
	}

	root = strings.ToLower(root)
	target = strings.ToLower(target)

	if target == root {
		return true
	}

	return len(target) > len(root) &&
		strings.HasPrefix(target, root) &&
		target[len(root)] == '\\'
}

func restoreBackupPrivilege(
	scope privilegeScope,
	result *privilegeResult,
) error {
	result.RestoreAttempted = true

	if scope.Token == 0 || scope.Token == syscall.InvalidHandle {
		return errors.New("process token handle is invalid")
	}

	var restoreErr error

	if scope.RestoreNeeded {
		_, _, _ = procSetLastError.Call(0)

		r1, _, callErr := procAdjustTokenPrivileges.Call(
			uintptr(scope.Token),
			0,
			uintptr(unsafe.Pointer(&scope.Previous)),
			0,
			0,
			0,
		)

		switch {
		case r1 == 0:
			restoreErr = normalizeCallError(callErr)

		case windowsErrorCode(callErr) != 0:
			restoreErr = fmt.Errorf(
				"Windows error %d: %w",
				windowsErrorCode(callErr),
				normalizeCallError(callErr),
			)
		}
	}

	closeErr := syscall.CloseHandle(scope.Token)

	if restoreErr == nil && closeErr == nil {
		result.RestoreSucceeded = true
		return nil
	}

	if restoreErr != nil {
		result.RestoreError = restoreErr.Error()
		result.RestoreErrorCode = windowsErrorCode(restoreErr)
	}

	return errors.Join(restoreErr, closeErr)
}

func runOpenAttempt(
	rootHandle syscall.Handle,
	rootPath string,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
) openResult {
	result := openResult{Attempted: true}

	handle, err := openFileByID(
		rootHandle,
		fileReferenceNumber,
		sequenceNumber,
	)
	if err != nil {
		result.Error = err.Error()
		result.ErrorCode = windowsErrorCode(err)
		return result
	}
	defer syscall.CloseHandle(handle)

	result.OpenSucceeded = true

	finalPath, err := finalVolumePath(handle)
	if err != nil {
		result.Error = fmt.Sprintf("GetFinalPathNameByHandleW: %v", err)
		result.ErrorCode = windowsErrorCode(err)
		return result
	}

	result.FinalPath = finalPath
	contained := pathContainedBy(rootPath, finalPath)
	result.Contained = &contained

	return result
}

func runProbe() probeResult {
	result := probeResult{
		Version:    probeVersion,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		InputPath:  probeInputPath,
		SeBackup: privilegeResult{
			Name: "SeBackupPrivilege",
		},
	}

	input, err := loadProbeInput()
	if err != nil {
		result.InputError = err.Error()
		return result
	}

	result.InputLoaded = true
	result.GovernedRoot = input.GovernedRoot
	result.FileReferenceNumber = input.FileReferenceNumber
	result.SequenceNumber = input.SequenceNumber
	result.TargetDescription = input.TargetDescription

	fileReferenceNumber, err := strconv.ParseUint(
		input.FileReferenceNumber,
		10,
		64,
	)
	if err != nil {
		result.InputError = fmt.Sprintf("parse file_reference_number: %v", err)
		return result
	}
	if fileReferenceNumber >= 1<<48 {
		result.InputError = "file_reference_number exceeds 48-bit NTFS record number"
		return result
	}

	sequenceValue, err := strconv.ParseUint(
		input.SequenceNumber,
		10,
		16,
	)
	if err != nil {
		result.InputError = fmt.Sprintf("parse sequence_number: %v", err)
		return result
	}
	sequenceNumber := uint16(sequenceValue)

	rootHandle, err := openPath(input.GovernedRoot)
	if err != nil {
		result.InputError = fmt.Sprintf("open governed root: %v", err)
		return result
	}
	defer syscall.CloseHandle(rootHandle)

	rootPath, err := finalVolumePath(rootHandle)
	if err != nil {
		result.InputError = fmt.Sprintf("resolve governed root final path: %v", err)
		return result
	}
	result.RootFinalPath = rootPath

	result.BeforePrivilege = runOpenAttempt(
		rootHandle,
		rootPath,
		fileReferenceNumber,
		sequenceNumber,
	)

	if result.BeforePrivilege.OpenSucceeded {
		return result
	}

	if result.BeforePrivilege.ErrorCode != uint32(syscall.ERROR_ACCESS_DENIED) {
		return result
	}

	scope, privilege, err := enableBackupPrivilege()
	result.SeBackup = privilege
	if err != nil {
		result.SeBackup.RestoreError = err.Error()
		result.SeBackup.RestoreErrorCode = windowsErrorCode(err)
		return result
	}

	result.WithPrivilege = runOpenAttempt(
		rootHandle,
		rootPath,
		fileReferenceNumber,
		sequenceNumber,
	)

	restoreErr := restoreBackupPrivilege(scope, &result.SeBackup)
	if restoreErr != nil {
		return result
	}

	result.AfterRestore = runOpenAttempt(
		rootHandle,
		rootPath,
		fileReferenceNumber,
		sequenceNumber,
	)

	return result
}

func windowsErrorCode(err error) uint32 {
	if err == nil {
		return 0
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}

	return 0
}

func writeJSON(file *os.File, value any) error {
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
