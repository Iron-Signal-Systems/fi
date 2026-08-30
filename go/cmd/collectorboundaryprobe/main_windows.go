// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	probeResultPath = `C:\ProgramData\FI\state\collector-token-boundary-probe.json`

	configPath = `C:\ProgramData\FI\config\fi.conf`
	fiPath     = `C:\Program Files\FI\fi.exe`
	fiUSNPath  = `C:\Program Files\FI\fi-usn.exe`

	programProbePath = `C:\Program Files\FI\fi-collector-boundary-probe.tmp`
	stateProbePath   = `C:\ProgramData\FI\state\fi-collector-boundary-probe.tmp`
	spoolProbePath   = `C:\ProgramData\FI\spool\fi-collector-boundary-probe.tmp`

	probeVersion = "fi-collector-token-boundary-probe/0.1"

	scManagerConnect    = 0x0001
	serviceChangeConfig = 0x0002
	serviceQueryStatus  = 0x0004
	writeDAC            = 0x00040000
	writeOwner          = 0x00080000
	deleteAccess        = 0x00010000
)

var (
	advapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procOpenSCManagerW     = advapi32.NewProc("OpenSCManagerW")
	procOpenServiceW       = advapi32.NewProc("OpenServiceW")
	procCloseServiceHandle = advapi32.NewProc("CloseServiceHandle")
)

type probeCheck struct {
	Name      string `json:"name"`
	Expect    string `json:"expect"`
	Result    string `json:"result"`
	ErrorCode uint32 `json:"error_code,omitempty"`
	Error     string `json:"error,omitempty"`
}

type probeResult struct {
	Version      string       `json:"version"`
	ObservedAt   string       `json:"observed_at"`
	ServiceName  string       `json:"service_name"`
	Overall      string       `json:"overall"`
	FailureCount int          `json:"failure_count"`
	Checks       []probeCheck `json:"checks"`
	WriteError   string       `json:"write_error,omitempty"`
}

type boundaryProbeService struct{}

func main() {
	_ = svc.Run("FICollector", &boundaryProbeService{})
}

func (service *boundaryProbeService) Execute(
	_ []string,
	_ <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	statuses <- svc.Status{State: svc.Running}

	result := runProbe()
	if err := writeResult(result); err != nil {
		result.WriteError = err.Error()
		statuses <- svc.Status{State: svc.StopPending}
		return false, 2
	}

	statuses <- svc.Status{State: svc.StopPending}
	if result.FailureCount != 0 {
		return false, 1
	}
	return false, 0
}

func runProbe() probeResult {
	result := probeResult{
		Version:     probeVersion,
		ObservedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		ServiceName: "FICollector",
		Overall:     "PASS",
		Checks:      make([]probeCheck, 0, 12),
	}

	addAllowed := func(name string, err error) {
		check := probeCheck{
			Name:   name,
			Expect: "allowed",
		}
		if err == nil {
			check.Result = "PASS"
		} else {
			check.Result = "FAIL"
			check.ErrorCode = errorCode(err)
			check.Error = err.Error()
			result.FailureCount++
		}
		result.Checks = append(result.Checks, check)
	}

	addDenied := func(name string, err error) {
		check := probeCheck{
			Name:   name,
			Expect: "access_denied",
		}
		switch {
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			check.Result = "PASS"
			check.ErrorCode = uint32(windows.ERROR_ACCESS_DENIED)
			check.Error = windows.ERROR_ACCESS_DENIED.Error()

		case err == nil:
			check.Result = "FAIL"
			check.Error = "access unexpectedly succeeded"
			result.FailureCount++

		default:
			check.Result = "FAIL"
			check.ErrorCode = errorCode(err)
			check.Error = err.Error()
			result.FailureCount++
		}
		result.Checks = append(result.Checks, check)
	}

	_, err := os.ReadFile(configPath)
	addAllowed("FICollector can read fi.conf", err)

	addAllowed(
		"FICollector can create/write/delete its own state temp file",
		createWriteDelete(stateProbePath),
	)

	addAllowed(
		"FICollector can create/write/delete its own spool temp file",
		createWriteDelete(spoolProbePath),
	)

	addDenied(
		"FICollector cannot open fi.conf for write",
		openExisting(configPath, windows.GENERIC_WRITE),
	)

	addDenied(
		`FICollector cannot create a file under C:\Program Files\FI`,
		createNew(programProbePath, windows.GENERIC_WRITE),
	)

	addDenied(
		"FICollector cannot open fi.exe for write",
		openExisting(fiPath, windows.GENERIC_WRITE),
	)

	addDenied(
		"FICollector cannot obtain DELETE access to fi.exe",
		openExisting(fiPath, deleteAccess),
	)

	addDenied(
		"FICollector cannot open fi-usn.exe for write",
		openExisting(fiUSNPath, windows.GENERIC_WRITE),
	)

	addDenied(
		"FICollector cannot obtain DELETE access to fi-usn.exe",
		openExisting(fiUSNPath, deleteAccess),
	)

	scm, err := openSCManager(scManagerConnect)
	addAllowed("FICollector can connect to the local Service Control Manager", err)
	if err == nil {
		defer closeServiceHandle(scm)

		addAllowed(
			"FICollector can obtain QUERY_STATUS on FIUSNReader",
			openAndCloseService(scm, "FIUSNReader", serviceQueryStatus),
		)

		addDenied(
			"FICollector cannot obtain CHANGE_CONFIG on FIUSNReader",
			openAndCloseService(scm, "FIUSNReader", serviceChangeConfig),
		)

		addDenied(
			"FICollector cannot obtain WRITE_DAC on FIUSNReader",
			openAndCloseService(scm, "FIUSNReader", writeDAC),
		)

		addDenied(
			"FICollector cannot obtain WRITE_OWNER on FIUSNReader",
			openAndCloseService(scm, "FIUSNReader", writeOwner),
		)
	}

	if result.FailureCount != 0 {
		result.Overall = "FAIL"
	}
	return result
}

func createWriteDelete(path string) error {
	if err := os.WriteFile(path, []byte("FI"), 0o600); err != nil {
		return fmt.Errorf("create/write %s: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete %s: %w", path, err)
	}
	return nil
}

func openExisting(path string, access uint32) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	handle, err := windows.CreateFile(
		pathPtr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

func createNew(path string, access uint32) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	handle, err := windows.CreateFile(
		pathPtr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

func openSCManager(access uint32) (windows.Handle, error) {
	handle, _, callErr := procOpenSCManagerW.Call(
		0,
		0,
		uintptr(access),
	)
	if handle == 0 {
		return 0, normalizeCallError(callErr)
	}
	return windows.Handle(handle), nil
}

func openAndCloseService(
	scm windows.Handle,
	name string,
	access uint32,
) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	handle, _, callErr := procOpenServiceW.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(access),
	)
	if handle == 0 {
		return normalizeCallError(callErr)
	}

	closeServiceHandle(windows.Handle(handle))
	return nil
}

func closeServiceHandle(handle windows.Handle) {
	if handle == 0 {
		return
	}
	_, _, _ = procCloseServiceHandle.Call(uintptr(handle))
}

func normalizeCallError(err error) error {
	if err == nil {
		return syscall.EINVAL
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return syscall.EINVAL
	}
	return err
}

func errorCode(err error) uint32 {
	if err == nil {
		return 0
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}

func writeResult(result probeResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(probeResultPath, data, 0o600)
}
