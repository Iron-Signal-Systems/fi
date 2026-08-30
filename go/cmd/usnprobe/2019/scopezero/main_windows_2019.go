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
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/svc"
)

const (
	fileIDType         = 0
	fileReadAttributes = 0x00000080

	fileNameNormalized = 0x0000
	volumeNameGUID     = 0x0001

	maximumFinalPathUTF16Units = 64 * 1024

	serviceName = "FIScopeProbe2019"

	inputPath  = `C:\FI-Test\scopezero-2019\input.json`
	resultPath = `C:\FI-Test\scopezero-2019\result.json`
	errorPath  = `C:\FI-Test\scopezero-2019\error.txt`
)

var (
	kernel32                      = syscall.NewLazyDLL("kernel32.dll")
	procGetFinalPathNameByHandleW = kernel32.NewProc("GetFinalPathNameByHandleW")
	procOpenFileByID              = kernel32.NewProc("OpenFileById")
)

type fileIDDescriptor struct {
	Size       uint32
	Type       uint32
	Identifier [16]byte
}

var (
	_ [24 - unsafe.Sizeof(fileIDDescriptor{})]byte
	_ [unsafe.Sizeof(fileIDDescriptor{}) - 24]byte
)

type probeAccessResult struct {
	AccessName              string `json:"access_name"`
	DesiredAccess           uint32 `json:"desired_access"`
	OpenSucceeded           bool   `json:"open_succeeded"`
	OpenError               string `json:"open_error,omitempty"`
	OpenErrorCode           uint32 `json:"open_error_code,omitempty"`
	FinalPathSucceeded      bool   `json:"final_path_succeeded"`
	FinalPath               string `json:"final_path,omitempty"`
	FinalPathError          string `json:"final_path_error,omitempty"`
	FinalPathErrorCode      uint32 `json:"final_path_error_code,omitempty"`
	ContainedByGovernedRoot bool   `json:"contained_by_governed_root"`
}

type probeInput struct {
	GovernedRoot string        `json:"governed_root"`
	Objects      []probeObject `json:"objects"`
}

type probeObject struct {
	Label               string `json:"label"`
	FileReferenceNumber uint64 `json:"file_reference_number"`
	SequenceNumber      uint16 `json:"sequence_number"`
}

type probeObjectResult struct {
	Label               string              `json:"label"`
	FileReferenceNumber uint64              `json:"file_reference_number"`
	SequenceNumber      uint16              `json:"sequence_number"`
	AccessResults       []probeAccessResult `json:"access_results"`
}

type probeResult struct {
	Version          string              `json:"version"`
	ObservedAt       string              `json:"observed_at"`
	GovernedRoot     string              `json:"governed_root"`
	GovernedRootPath string              `json:"governed_root_final_path"`
	Objects          []probeObjectResult `json:"objects"`
}

type windowsService struct{}

func main() {
	if err := svc.Run(serviceName, &windowsService{}); err != nil {
		_ = os.WriteFile(errorPath, []byte(err.Error()+"\r\n"), 0o600)
		os.Exit(1)
	}
}

func (service *windowsService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	statuses <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	done := make(chan error, 1)
	go func() {
		done <- runProbe()
	}()

	for {
		select {
		case err := <-done:
			statuses <- svc.Status{State: svc.StopPending}
			if err != nil {
				_ = os.WriteFile(errorPath, []byte(err.Error()+"\r\n"), 0o600)
				return false, 1
			}
			_ = os.Remove(errorPath)
			return false, 0

		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- svc.Status{
					State:   svc.Running,
					Accepts: svc.AcceptStop | svc.AcceptShutdown,
				}
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

func runProbe() error {
	inputBytes, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	var input probeInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		return fmt.Errorf("parse input: %w", err)
	}
	if strings.TrimSpace(input.GovernedRoot) == "" {
		return errors.New("governed_root is required")
	}
	if len(input.Objects) == 0 {
		return errors.New("at least one object is required")
	}

	rootHandle, err := openPath(input.GovernedRoot, fileReadAttributes)
	if err != nil {
		return fmt.Errorf("open governed root: %w", err)
	}
	defer syscall.CloseHandle(rootHandle)

	rootFinalPath, err := finalVolumePath(rootHandle)
	if err != nil {
		return fmt.Errorf("resolve governed root final path: %w", err)
	}

	result := probeResult{
		Version:          "windows-server-2019-scope-zero-access/0.1",
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		GovernedRoot:     input.GovernedRoot,
		GovernedRootPath: rootFinalPath,
		Objects:          make([]probeObjectResult, 0, len(input.Objects)),
	}

	for _, object := range input.Objects {
		objectResult := probeObjectResult{
			Label:               object.Label,
			FileReferenceNumber: object.FileReferenceNumber,
			SequenceNumber:      object.SequenceNumber,
			AccessResults:       make([]probeAccessResult, 0, 2),
		}

		for _, access := range []struct {
			name string
			mask uint32
		}{
			{name: "NoAccess", mask: 0},
			{name: "FileReadAttributes", mask: fileReadAttributes},
		} {
			objectResult.AccessResults = append(
				objectResult.AccessResults,
				probeOne(rootHandle, rootFinalPath, object, access.name, access.mask),
			)
		}

		result.Objects = append(result.Objects, objectResult)
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	encoded = append(encoded, '\r', '\n')

	if err := os.WriteFile(resultPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func probeOne(
	volumeHint syscall.Handle,
	rootFinalPath string,
	object probeObject,
	accessName string,
	desiredAccess uint32,
) probeAccessResult {
	result := probeAccessResult{
		AccessName:    accessName,
		DesiredAccess: desiredAccess,
	}

	handle, err := openFileByID(
		volumeHint,
		object.FileReferenceNumber,
		object.SequenceNumber,
		desiredAccess,
	)
	if err != nil {
		result.OpenError = err.Error()
		result.OpenErrorCode = errnoCode(err)
		return result
	}
	defer syscall.CloseHandle(handle)

	result.OpenSucceeded = true

	finalPath, err := finalVolumePath(handle)
	if err != nil {
		result.FinalPathError = err.Error()
		result.FinalPathErrorCode = errnoCode(err)
		return result
	}

	result.FinalPathSucceeded = true
	result.FinalPath = finalPath
	result.ContainedByGovernedRoot = pathContainedBy(rootFinalPath, finalPath)
	return result
}

func openFileByID(
	volumeHint syscall.Handle,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
	desiredAccess uint32,
) (syscall.Handle, error) {
	if fileReferenceNumber >= 1<<48 {
		return syscall.InvalidHandle, errors.New("file reference number exceeds 48-bit NTFS record number")
	}

	fileID := fileReferenceNumber | uint64(sequenceNumber)<<48

	descriptor := fileIDDescriptor{
		Size: uint32(unsafe.Sizeof(fileIDDescriptor{})),
		Type: fileIDType,
	}
	binary.LittleEndian.PutUint64(descriptor.Identifier[:8], fileID)

	r1, _, callErr := procOpenFileByID.Call(
		uintptr(volumeHint),
		uintptr(unsafe.Pointer(&descriptor)),
		uintptr(desiredAccess),
		uintptr(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE),
		0,
		uintptr(syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT),
	)
	runtime.KeepAlive(&descriptor)

	handle := syscall.Handle(r1)
	if handle == syscall.InvalidHandle {
		return syscall.InvalidHandle, callErr
	}
	return handle, nil
}

func openPath(path string, desiredAccess uint32) (syscall.Handle, error) {
	units, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	return syscall.CreateFile(
		units,
		desiredAccess,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func finalVolumePath(handle syscall.Handle) (string, error) {
	buffer := make([]uint16, 512)

	for attempts := 0; attempts < 3; attempts++ {
		length, _, callErr := procGetFinalPathNameByHandleW.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			fileNameNormalized|volumeNameGUID,
		)
		if length == 0 {
			return "", callErr
		}

		if length < uintptr(len(buffer)) {
			return syscall.UTF16ToString(buffer[:length]), nil
		}

		if length >= uintptr(maximumFinalPathUTF16Units) {
			return "", fmt.Errorf(
				"final path exceeds bounded UTF-16 limit: %d >= %d",
				length,
				maximumFinalPathUTF16Units,
			)
		}
		buffer = make([]uint16, int(length)+1)
	}

	return "", errors.New("final path exceeded retry bound")
}

func pathContainedBy(root, target string) bool {
	root = strings.TrimRight(root, `\`)
	target = strings.TrimRight(target, `\`)
	if root == "" || target == "" {
		return false
	}

	rootLower := strings.ToLower(root)
	targetLower := strings.ToLower(target)

	if targetLower == rootLower {
		return true
	}
	return len(targetLower) > len(rootLower) &&
		strings.HasPrefix(targetLower, rootLower) &&
		targetLower[len(rootLower)] == '\\'
}

func errnoCode(err error) uint32 {
	if err == nil {
		return 0
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}
