// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certEnrollContextMachine                   = uint32(0x2)
	certEnrollContextAdministratorForceMachine = uint32(0x3)

	clsctxInprocServer = uint32(0x1)

	coinitApartmentThreaded = uint32(0x2)

	dispatchMethod      = uint16(0x1)
	dispatchPropertyPut = uint16(0x4)

	dispidPropertyPut = int32(-3)

	localeUserDefault = uint32(0x0400)

	variantBool = uint16(11)
	variantBSTR = uint16(8)
	variantI4   = uint16(3)

	variantTrue = uint16(0xffff)
)

var (
	certEnrollIIDIDispatch = windows.GUID{
		Data1: 0x00020400,
		Data2: 0x0000,
		Data3: 0x0000,
		Data4: [8]byte{
			0xc0, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x46,
		},
	}

	certEnrollIIDNull windows.GUID

	ole32PKIDLL = windows.NewLazySystemDLL(
		"ole32.dll",
	)
	oleaut32PKIDLL = windows.NewLazySystemDLL(
		"oleaut32.dll",
	)

	clsidFromProgIDPKIProc = ole32PKIDLL.NewProc(
		"CLSIDFromProgID",
	)
	coCreateInstancePKIProc = ole32PKIDLL.NewProc(
		"CoCreateInstance",
	)
	coInitializeExPKIProc = ole32PKIDLL.NewProc(
		"CoInitializeEx",
	)
	coUninitializePKIProc = ole32PKIDLL.NewProc(
		"CoUninitialize",
	)
	sysAllocStringPKIProc = oleaut32PKIDLL.NewProc(
		"SysAllocString",
	)
	sysFreeStringPKIProc = oleaut32PKIDLL.NewProc(
		"SysFreeString",
	)
	sysStringLenPKIProc = oleaut32PKIDLL.NewProc(
		"SysStringLen",
	)
)

type certEnrollDispatch struct {
	VTable *certEnrollDispatchVTable
}

type certEnrollDispatchParams struct {
	Arguments      *certEnrollVariant
	NamedArguments *int32
	ArgumentCount  uint32
	NamedCount     uint32
}

type certEnrollDispatchVTable struct {
	QueryInterface   uintptr
	AddRef           uintptr
	Release          uintptr
	GetTypeInfoCount uintptr
	GetTypeInfo      uintptr
	GetIDsOfNames    uintptr
	Invoke           uintptr
}

type certEnrollExceptionInfo struct {
	Code            uint16
	Reserved        uint16
	Source          *uint16
	Description     *uint16
	HelpFile        *uint16
	HelpContext     uint32
	ReservedPointer uintptr
	DeferredFillIn  uintptr
	SCode           int32
}

type certEnrollVariant struct {
	Type      uint16
	Reserved1 uint16
	Reserved2 uint16
	Reserved3 uint16
	Value     uintptr
	Extra     uintptr
}

func certEnrollGetDispatchID(
	dispatch *certEnrollDispatch,
	name string,
) (int32, error) {
	if dispatch == nil || dispatch.VTable == nil {
		return 0, fmt.Errorf(
			"CertEnroll dispatch interface is unavailable",
		)
	}

	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf(
			"encode CertEnroll method name %q: %w",
			name,
			err,
		)
	}

	names := []*uint16{
		namePointer,
	}

	var dispatchID int32

	result, _, _ := syscall.SyscallN(
		dispatch.VTable.GetIDsOfNames,
		uintptr(
			unsafe.Pointer(
				dispatch,
			),
		),
		uintptr(
			unsafe.Pointer(
				&certEnrollIIDNull,
			),
		),
		uintptr(
			unsafe.Pointer(
				&names[0],
			),
		),
		uintptr(len(names)),
		uintptr(localeUserDefault),
		uintptr(
			unsafe.Pointer(
				&dispatchID,
			),
		),
	)

	runtime.KeepAlive(namePointer)
	runtime.KeepAlive(names)

	if certEnrollHRESULTFailed(result) {
		return 0, certEnrollHRESULTError(
			"CertEnroll IDispatch.GetIDsOfNames("+name+")",
			result,
		)
	}

	return dispatchID, nil
}

func certEnrollHRESULTError(
	operation string,
	result uintptr,
) error {
	return fmt.Errorf(
		"%s: HRESULT=0x%08X",
		operation,
		uint32(result),
	)
}

func certEnrollHRESULTFailed(
	result uintptr,
) bool {
	return int32(
		uint32(result),
	) < 0
}

func certEnrollInvoke(
	dispatch *certEnrollDispatch,
	dispatchID int32,
	flags uint16,
	parameters *certEnrollDispatchParams,
) error {
	if dispatch == nil || dispatch.VTable == nil {
		return fmt.Errorf(
			"CertEnroll dispatch interface is unavailable",
		)
	}

	var (
		argumentError uint32
		exception     certEnrollExceptionInfo
	)

	result, _, _ := syscall.SyscallN(
		dispatch.VTable.Invoke,
		uintptr(
			unsafe.Pointer(
				dispatch,
			),
		),
		uintptr(
			uint32(dispatchID),
		),
		uintptr(
			unsafe.Pointer(
				&certEnrollIIDNull,
			),
		),
		uintptr(localeUserDefault),
		uintptr(flags),
		uintptr(
			unsafe.Pointer(
				parameters,
			),
		),
		0,
		uintptr(
			unsafe.Pointer(
				&exception,
			),
		),
		uintptr(
			unsafe.Pointer(
				&argumentError,
			),
		),
	)

	if certEnrollHRESULTFailed(result) {
		if uint32(result) == 0x80020009 {
			if exception.DeferredFillIn != 0 {
				_, _, _ = syscall.SyscallN(
					exception.DeferredFillIn,
					uintptr(
						unsafe.Pointer(
							&exception,
						),
					),
				)
			}

			source := certEnrollBSTRString(
				exception.Source,
			)
			description := certEnrollBSTRString(
				exception.Description,
			)
			helpFile := certEnrollBSTRString(
				exception.HelpFile,
			)

			certEnrollFreeExceptionInfo(
				&exception,
			)

			return fmt.Errorf(
				"CertEnroll IDispatch.Invoke: HRESULT=0x%08X exception_scode=0x%08X exception_code=%d source=%q description=%q help_file=%q help_context=%d",
				uint32(result),
				uint32(exception.SCode),
				exception.Code,
				source,
				description,
				helpFile,
				exception.HelpContext,
			)
		}

		return fmt.Errorf(
			"%w argument_index=%d",
			certEnrollHRESULTError(
				"CertEnroll IDispatch.Invoke",
				result,
			),
			argumentError,
		)
	}

	return nil
}

func certEnrollBSTRString(
	value *uint16,
) string {
	if value == nil {
		return ""
	}

	length, _, _ := sysStringLenPKIProc.Call(
		uintptr(
			unsafe.Pointer(
				value,
			),
		),
	)

	if length == 0 {
		return ""
	}

	return string(
		utf16.Decode(
			unsafe.Slice(
				value,
				int(length),
			),
		),
	)
}

func certEnrollFreeExceptionInfo(
	exception *certEnrollExceptionInfo,
) {
	if exception == nil {
		return
	}

	for _, value := range []*uint16{
		exception.Source,
		exception.Description,
		exception.HelpFile,
	} {
		if value == nil {
			continue
		}

		_, _, _ = sysFreeStringPKIProc.Call(
			uintptr(
				unsafe.Pointer(
					value,
				),
			),
		)
	}
}

func certEnrollInvokeMethod(
	dispatch *certEnrollDispatch,
	name string,
	arguments []certEnrollVariant,
) error {
	dispatchID, err := certEnrollGetDispatchID(
		dispatch,
		name,
	)
	if err != nil {
		return err
	}

	parameters := certEnrollDispatchParams{
		ArgumentCount: uint32(
			len(arguments),
		),
	}

	if len(arguments) != 0 {
		parameters.Arguments = &arguments[0]
	}

	if err := certEnrollInvoke(
		dispatch,
		dispatchID,
		dispatchMethod,
		&parameters,
	); err != nil {
		return fmt.Errorf(
			"%s: %w",
			name,
			err,
		)
	}

	runtime.KeepAlive(arguments)

	return nil
}

func certEnrollPutBoolProperty(
	dispatch *certEnrollDispatch,
	name string,
	value bool,
) error {
	dispatchID, err := certEnrollGetDispatchID(
		dispatch,
		name,
	)
	if err != nil {
		return err
	}

	var raw uint16
	if value {
		raw = variantTrue
	}

	argument := certEnrollVariant{
		Type:  variantBool,
		Value: uintptr(raw),
	}

	named := dispidPropertyPut

	parameters := certEnrollDispatchParams{
		Arguments:      &argument,
		NamedArguments: &named,
		ArgumentCount:  1,
		NamedCount:     1,
	}

	if err := certEnrollInvoke(
		dispatch,
		dispatchID,
		dispatchPropertyPut,
		&parameters,
	); err != nil {
		return fmt.Errorf(
			"set CertEnroll property %s: %w",
			name,
			err,
		)
	}

	runtime.KeepAlive(argument)
	runtime.KeepAlive(named)

	return nil
}

func enrollMachineCertificateTemplate(
	templateName string,
) error {
	if templateName == "" {
		return fmt.Errorf(
			"certificate template name is required",
		)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	initializeResult, _, _ := coInitializeExPKIProc.Call(
		0,
		uintptr(coinitApartmentThreaded),
	)
	if certEnrollHRESULTFailed(
		initializeResult,
	) {
		return certEnrollHRESULTError(
			"CoInitializeEx",
			initializeResult,
		)
	}
	defer coUninitializePKIProc.Call()

	progIDPointer, err := syscall.UTF16PtrFromString(
		"X509Enrollment.CX509Enrollment",
	)
	if err != nil {
		return fmt.Errorf(
			"encode CertEnroll ProgID: %w",
			err,
		)
	}

	var classID windows.GUID

	result, _, _ := clsidFromProgIDPKIProc.Call(
		uintptr(
			unsafe.Pointer(
				progIDPointer,
			),
		),
		uintptr(
			unsafe.Pointer(
				&classID,
			),
		),
	)
	runtime.KeepAlive(progIDPointer)

	if certEnrollHRESULTFailed(result) {
		return certEnrollHRESULTError(
			"CLSIDFromProgID(X509Enrollment.CX509Enrollment)",
			result,
		)
	}

	var dispatch *certEnrollDispatch

	result, _, _ = coCreateInstancePKIProc.Call(
		uintptr(
			unsafe.Pointer(
				&classID,
			),
		),
		0,
		uintptr(clsctxInprocServer),
		uintptr(
			unsafe.Pointer(
				&certEnrollIIDIDispatch,
			),
		),
		uintptr(
			unsafe.Pointer(
				&dispatch,
			),
		),
	)

	if certEnrollHRESULTFailed(result) {
		return certEnrollHRESULTError(
			"CoCreateInstance(X509Enrollment.CX509Enrollment)",
			result,
		)
	}
	if dispatch == nil || dispatch.VTable == nil {
		return fmt.Errorf(
			"CertEnroll returned no IDispatch interface",
		)
	}

	defer syscall.SyscallN(
		dispatch.VTable.Release,
		uintptr(
			unsafe.Pointer(
				dispatch,
			),
		),
	)

	if err := certEnrollPutBoolProperty(
		dispatch,
		"Silent",
		true,
	); err != nil {
		return err
	}

	templatePointer, err := syscall.UTF16PtrFromString(
		templateName,
	)
	if err != nil {
		return fmt.Errorf(
			"encode certificate template %q: %w",
			templateName,
			err,
		)
	}

	bstr, _, _ := sysAllocStringPKIProc.Call(
		uintptr(
			unsafe.Pointer(
				templatePointer,
			),
		),
	)
	runtime.KeepAlive(templatePointer)

	if bstr == 0 {
		return fmt.Errorf(
			"SysAllocString failed for certificate template %q",
			templateName,
		)
	}
	defer sysFreeStringPKIProc.Call(
		bstr,
	)

	// IDispatch receives positional arguments in reverse order:
	//
	// InitializeFromTemplateName(
	//     ContextMachine,
	//     templateName,
	// )
	arguments := []certEnrollVariant{
		{
			Type:  variantBSTR,
			Value: bstr,
		},
		{
			Type:  variantI4,
			Value: uintptr(certEnrollContextAdministratorForceMachine),
		},
	}

	if err := certEnrollInvokeMethod(
		dispatch,
		"InitializeFromTemplateName",
		arguments,
	); err != nil {
		return fmt.Errorf(
			"initialize machine certificate enrollment from template %q: %w",
			templateName,
			err,
		)
	}

	if err := certEnrollInvokeMethod(
		dispatch,
		"Enroll",
		nil,
	); err != nil {
		return fmt.Errorf(
			"enroll machine certificate from template %q: %w",
			templateName,
			err,
		)
	}

	return nil
}
