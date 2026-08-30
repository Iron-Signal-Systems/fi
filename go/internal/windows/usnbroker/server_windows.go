// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnbroker

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnraw"
	"golang.org/x/sys/windows"
)

const (
	CollectorServiceName = "FICollector"
	HelperServiceName    = "FIUSNReader"

	pipeAccessDuplex          = 0x00000003
	fileFlagFirstPipeInstance = 0x00080000
	pipeRejectRemoteClients   = 0x00000008
	pipeBufferSize            = 64 * 1024
)

var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
)

// Serve accepts local FICollector requests until ctx is canceled. Every client
// must carry the FICollector service SID; ordinary processes using the same
// account do not satisfy that check.
func Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	collectorSID, _, _, err := windows.LookupSID("", `NT SERVICE\`+CollectorServiceName)
	if err != nil {
		return fmt.Errorf("resolve FICollector service SID: %w", err)
	}
	securityAttributes, err := pipeSecurityAttributes(collectorSID)
	if err != nil {
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		handle, err := createServerPipe(securityAttributes)
		if err != nil {
			return err
		}

		connectErr := windows.ConnectNamedPipe(handle, nil)
		if connectErr != nil && connectErr != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(handle)
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("connect FI USN named pipe: %w", connectErr)
		}
		if ctx.Err() != nil {
			windows.DisconnectNamedPipe(handle)
			windows.CloseHandle(handle)
			return nil
		}

		connectionErr := handleConnection(handle, collectorSID)
		if connectionErr == nil {
			// Named-pipe writes may still be buffered when writeResponse returns.
			// Flush before disconnecting so the client can consume the complete
			// response instead of racing DisconnectNamedPipe.
			_ = syscall.FlushFileBuffers(syscall.Handle(handle))
		}
		_ = windows.DisconnectNamedPipe(handle)
		_ = windows.CloseHandle(handle)
	}
}

// Wake connects to the helper pipe so a service stop can release a blocking
// ConnectNamedPipe call. The server checks ctx immediately after the connection.
func Wake() {
	pipeUnits, err := windows.UTF16PtrFromString(PipePath)
	if err != nil {
		return
	}
	handle, err := windows.CreateFile(
		pipeUnits,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err == nil {
		_ = windows.CloseHandle(handle)
	}
}

func allowedGovernedRoot(governedRoot string) (bool, error) {
	value, _, err := config.LoadDefault()
	if err != nil {
		return false, err
	}
	requested := normalizedGovernedRoot(governedRoot)
	for _, configuredRoot := range value.GovernedRoots {
		if strings.EqualFold(normalizedGovernedRoot(configuredRoot), requested) {
			return true, nil
		}
	}
	return false, nil
}

func allowedVolume(governedRoot string) (bool, error) {
	requestedDrive, err := usnraw.DriveForRoot(governedRoot)
	if err != nil {
		return false, err
	}

	value, _, err := config.LoadDefault()
	if err != nil {
		return false, err
	}
	for _, configuredRoot := range value.GovernedRoots {
		drive, err := usnraw.DriveForRoot(configuredRoot)
		if err != nil {
			return false, err
		}
		if strings.EqualFold(drive, requestedDrive) {
			return true, nil
		}
	}
	return false, nil
}

func authorizeClient(handle windows.Handle, expectedSID *windows.SID) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	r1, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(handle))
	if r1 == 0 {
		if callErr == nil || callErr == syscall.Errno(0) {
			return false, windows.ERROR_ACCESS_DENIED
		}
		return false, callErr
	}

	authorized, authErr := func() (bool, error) {
		var token windows.Token
		if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
			return false, err
		}
		defer token.Close()

		groups, err := token.GetTokenGroups()
		if err != nil {
			return false, err
		}
		for _, group := range groups.AllGroups() {
			if group.Sid != nil &&
				group.Sid.Equals(expectedSID) &&
				group.Attributes&windows.SE_GROUP_ENABLED != 0 &&
				group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
				return true, nil
			}
		}
		return false, nil
	}()

	revertErr := windows.RevertToSelf()
	if authErr != nil {
		return false, authErr
	}
	if revertErr != nil {
		return false, revertErr
	}
	return authorized, nil
}

func brokerContainment(value usnraw.ContainmentResult) (ContainmentResult, error) {
	switch value {
	case usnraw.ContainmentContained:
		return ContainmentContained, nil
	case usnraw.ContainmentOutside:
		return ContainmentOutside, nil
	case usnraw.ContainmentUnavailable:
		return ContainmentUnavailable, nil
	default:
		return 0, errors.New("invalid FIUSNReader containment result")
	}
}

func brokerJournal(value usnraw.Journal) Journal {
	return Journal{
		JournalID:       value.JournalID,
		FirstUSN:        value.FirstUSN,
		NextUSN:         value.NextUSN,
		LowestValidUSN:  value.LowestValidUSN,
		MaxUSN:          value.MaxUSN,
		MaximumSize:     value.MaximumSize,
		AllocationDelta: value.AllocationDelta,
	}
}

func createServerPipe(securityAttributes *windows.SecurityAttributes) (windows.Handle, error) {
	pipeUnits, err := windows.UTF16PtrFromString(PipePath)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, err := windows.CreateNamedPipe(
		pipeUnits,
		pipeAccessDuplex|fileFlagFirstPipeInstance,
		pipeRejectRemoteClients,
		1,
		pipeBufferSize,
		pipeBufferSize,
		0,
		securityAttributes,
	)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("create FI USN named pipe: %w", err)
	}
	return handle, nil
}

func handleConnection(handle windows.Handle, collectorSID *windows.SID) error {
	stream := handleIO{handle: handle}

	// ImpersonateNamedPipeClient uses the security context of the last message
	// read from the pipe. Read the bounded request before impersonating, then
	// authenticate the connected client before performing any privileged work.
	value, err := readRequest(stream)
	if err != nil {
		return writeFailure(stream, err)
	}

	authorized, err := authorizeClient(handle, collectorSID)
	if err != nil {
		return writeFailure(stream, fmt.Errorf("authenticate FICollector pipe client: %w", err))
	}
	if !authorized {
		return writeFailureCode(stream, uint32(windows.ERROR_ACCESS_DENIED), "FICollector service SID is required")
	}

	switch value.Operation {
	case operationQuery:
		allowed, err := allowedVolume(value.GovernedRoot)
		if err != nil {
			return writeFailure(stream, err)
		}
		if !allowed {
			return writeFailureCode(stream, uint32(windows.ERROR_ACCESS_DENIED), "requested volume is not configured for FI")
		}

		journal, err := usnraw.Query(value.GovernedRoot)
		if err != nil {
			return writeFailure(stream, err)
		}
		return writeResponse(stream, response{Journal: brokerJournal(journal)})

	case operationRead:
		allowed, err := allowedVolume(value.GovernedRoot)
		if err != nil {
			return writeFailure(stream, err)
		}
		if !allowed {
			return writeFailureCode(stream, uint32(windows.ERROR_ACCESS_DENIED), "requested volume is not configured for FI")
		}

		journal, data, err := usnraw.Read(value.GovernedRoot, value.StartUSN)
		if err != nil {
			return writeFailure(stream, err)
		}
		return writeResponse(stream, response{
			Journal: brokerJournal(journal),
			Data:    data,
		})

	case operationContainment:
		allowed, err := allowedGovernedRoot(value.GovernedRoot)
		if err != nil {
			return writeFailure(stream, err)
		}
		if !allowed {
			return writeFailureCode(stream, uint32(windows.ERROR_ACCESS_DENIED), "requested governed root is not configured for FI")
		}

		containment, err := usnraw.CheckContainment(
			value.GovernedRoot,
			value.FileReferenceNumber,
			value.SequenceNumber,
		)
		if err != nil {
			return writeFailure(stream, err)
		}
		result, err := brokerContainment(containment)
		if err != nil {
			return writeFailure(stream, err)
		}
		return writeResponse(stream, response{Data: []byte{byte(result)}})

	default:
		return writeFailure(stream, errors.New("unsupported FI USN operation"))
	}
}

func normalizedGovernedRoot(value string) string {
	value = strings.TrimRight(value, `\`)
	if len(value) == 2 && value[1] == ':' {
		value += `\`
	}
	return value
}

func pipeSecurityAttributes(collectorSID *windows.SID) (*windows.SecurityAttributes, error) {
	if collectorSID == nil || !collectorSID.IsValid() {
		return nil, errors.New("valid FICollector service SID is required")
	}

	sddl := "D:P" +
		"(A;;GA;;;SY)" +
		"(A;;GA;;;BA)" +
		"(A;;GRGW;;;" + collectorSID.String() + ")"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build FI USN pipe security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}

func writeFailure(writer handleIO, err error) error {
	return writeFailureCode(writer, windowsErrorCode(err), boundedError(err))
}

func writeFailureCode(writer handleIO, code uint32, message string) error {
	return writeResponse(writer, response{
		ErrorCode: code,
		Error:     message,
	})
}

func boundedError(err error) string {
	if err == nil {
		return "unspecified helper failure"
	}
	message := err.Error()
	if len(message) <= maxErrorBytes {
		return message
	}
	message = message[:maxErrorBytes]
	for len(message) > 0 && !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return message
}

func windowsErrorCode(err error) uint32 {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}
