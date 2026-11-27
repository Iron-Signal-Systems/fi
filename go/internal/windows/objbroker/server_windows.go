// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package objbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/scopeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/objraw"
	"golang.org/x/sys/windows"
)

const (
	CollectorServiceName = "FICollector"
	HelperServiceName    = "FIObjReader"

	pipeAccessDuplex          = 0x00000003
	fileFlagFirstPipeInstance = 0x00080000
	pipeRejectRemoteClients   = 0x00000008
	pipeBufferSize            = 64 * 1024
)

var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
)

type governedRootAuthority struct {
	GovernedRoot   string
	NormalizedRoot string
	ScopeID        string
}

type authoritySnapshot struct {
	governedRoots []governedRootAuthority
}

func newAuthoritySnapshot(governedRoots []string) (authoritySnapshot, error) {
	if len(governedRoots) == 0 {
		return authoritySnapshot{}, errors.New("at least one FI governed root is required")
	}

	value := authoritySnapshot{
		governedRoots: make([]governedRootAuthority, 0, len(governedRoots)),
	}

	for _, governedRoot := range governedRoots {
		normalized := normalizedGovernedRoot(governedRoot)
		if strings.TrimSpace(normalized) == "" {
			return authoritySnapshot{}, errors.New("FI governed root is empty")
		}

		value.governedRoots = append(
			value.governedRoots,
			governedRootAuthority{
				GovernedRoot:   governedRoot,
				NormalizedRoot: normalized,
				ScopeID:        scopeidentity.GovernedRootScopeID(governedRoot),
			},
		)
	}

	return value, nil
}

func (value authoritySnapshot) resolveGovernedRoot(
	governedRoot string,
) (governedRootAuthority, bool) {
	requested := normalizedGovernedRoot(governedRoot)
	for _, configuredRoot := range value.governedRoots {
		if strings.EqualFold(configuredRoot.NormalizedRoot, requested) {
			return configuredRoot, true
		}
	}

	return governedRootAuthority{}, false
}

// Serve accepts local FICollector requests until ctx is canceled. Every client
// must carry the enabled FICollector service SID. Governed-root authority is
// captured once at FIObjReader startup and is not reloaded while the service is
// running.
func Serve(ctx context.Context, governedRoots []string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	authority, err := newAuthoritySnapshot(governedRoots)
	if err != nil {
		return err
	}

	collectorSID, _, _, err := windows.LookupSID(
		"",
		`NT SERVICE\`+CollectorServiceName,
	)
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
			return fmt.Errorf("connect FI object named pipe: %w", connectErr)
		}

		if ctx.Err() != nil {
			windows.DisconnectNamedPipe(handle)
			windows.CloseHandle(handle)
			return nil
		}

		connectionErr := handleConnection(
			ctx,
			handle,
			collectorSID,
			authority,
		)
		if connectionErr == nil {
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

func authorizeClient(
	handle windows.Handle,
	expectedSID *windows.SID,
) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(handle))
	if result == 0 {
		if callErr == nil || callErr == syscall.Errno(0) {
			return false, windows.ERROR_ACCESS_DENIED
		}
		return false, callErr
	}

	authorized, authErr := func() (bool, error) {
		var token windows.Token
		if err := windows.OpenThreadToken(
			windows.CurrentThread(),
			windows.TOKEN_QUERY,
			true,
			&token,
		); err != nil {
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

func createServerPipe(
	securityAttributes *windows.SecurityAttributes,
) (windows.Handle, error) {
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
		return windows.InvalidHandle, fmt.Errorf(
			"create FI object named pipe: %w",
			err,
		)
	}

	return handle, nil
}

func handleConnection(
	ctx context.Context,
	handle windows.Handle,
	collectorSID *windows.SID,
	authority authoritySnapshot,
) error {
	stream := handleIO{handle: handle}

	// Named-pipe client impersonation uses the security context of the last
	// message read. Read the bounded request first, authenticate the connected
	// client, and only then perform privileged observation.
	value, err := readRequest(stream)
	if err != nil {
		return writeFailure(stream, err)
	}

	authorized, err := authorizeClient(handle, collectorSID)
	if err != nil {
		return writeFailure(
			stream,
			fmt.Errorf("authenticate FICollector pipe client: %w", err),
		)
	}
	if !authorized {
		return writeFailureCode(
			stream,
			uint32(windows.ERROR_ACCESS_DENIED),
			"FICollector service SID is required",
		)
	}

	rootAuthority, ok := authority.resolveGovernedRoot(value.GovernedRoot)
	if !ok {
		return writeFailureCode(
			stream,
			uint32(windows.ERROR_ACCESS_DENIED),
			"requested governed root is not configured for FI",
		)
	}

	if err := ctx.Err(); err != nil {
		return writeFailure(stream, err)
	}

	objectIdentity := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: strconv.FormatUint(value.FileReferenceNumber, 10),
		SequenceNumber:      strconv.FormatUint(uint64(value.SequenceNumber), 10),
	}

	observation, err := objraw.ObserveObject(
		ctx,
		rootAuthority.ScopeID,
		rootAuthority.GovernedRoot,
		objectIdentity,
	)
	if err != nil {
		return writeFailure(stream, err)
	}

	if observation.CollectionMethod != records.CollectionBackupAuthorityWindowsNTFS {
		return writeFailure(
			stream,
			errors.New("FIObjReader produced an unexpected collection method"),
		)
	}
	if observation.ObjectIdentity != objectIdentity {
		return writeFailure(
			stream,
			errors.New("FIObjReader produced a different NTFS object identity"),
		)
	}
	if observation.GovernedRoot.ScopeID != rootAuthority.ScopeID {
		return writeFailure(
			stream,
			errors.New("FIObjReader produced a different governed-root scope id"),
		)
	}
	if err := ntfs.ValidateObservation(observation); err != nil {
		return writeFailure(
			stream,
			fmt.Errorf("validate FIObjReader observation before broker response: %w", err),
		)
	}

	data, err := json.Marshal(observation)
	if err != nil {
		return writeFailure(
			stream,
			fmt.Errorf("encode FIObjReader observation: %w", err),
		)
	}
	if len(data) == 0 || len(data) > MaxObservationBytes {
		return writeFailure(
			stream,
			errors.New("FIObjReader observation exceeded the bounded response contract"),
		)
	}

	return writeResponse(stream, response{Data: data})
}

func normalizedGovernedRoot(value string) string {
	value = strings.TrimRight(value, `\`)
	if len(value) == 2 && value[1] == ':' {
		value += `\`
	}
	return value
}

func pipeSecurityAttributes(
	collectorSID *windows.SID,
) (*windows.SecurityAttributes, error) {
	if collectorSID == nil || !collectorSID.IsValid() {
		return nil, errors.New("valid FICollector service SID is required")
	}

	sddl := "D:P" +
		"(A;;GA;;;SY)" +
		"(A;;GA;;;BA)" +
		"(A;;GRGW;;;" + collectorSID.String() + ")"

	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf(
			"build FI object pipe security descriptor: %w",
			err,
		)
	}

	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}

func writeFailure(writer handleIO, err error) error {
	return writeFailureCode(
		writer,
		windowsErrorCode(err),
		boundedError(err),
	)
}

func writeFailureCode(
	writer handleIO,
	code uint32,
	message string,
) error {
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
	if errors.Is(err, objraw.ErrBackupPrivilegeUnavailable) {
		return 1300
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}

	return 0
}
