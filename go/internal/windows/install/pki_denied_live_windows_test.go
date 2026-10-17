// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certSrvSubjectDNSRequiredHRESULT = "8009480F"
)

func TestLivePKIDeniedEnrollmentLeavesNoMachineKey(
	t *testing.T,
) {
	if os.Getenv(
		"FI_LIVE_PKI_DENIED_KEY_CHARACTERIZATION",
	) != "1" {
		t.Skip(
			"set FI_LIVE_PKI_DENIED_KEY_CHARACTERIZATION=1 to characterize denied AD CS enrollment CNG key cleanup",
		)
	}

	contract := pkiEnrollmentContract{
		ExpectedDNS: strings.TrimSpace(
			os.Getenv(
				"FI_LIVE_PKI_EXPECTED_DNS",
			),
		),
		TemplateName: strings.TrimSpace(
			os.Getenv(
				"FI_LIVE_PKI_TEMPLATE",
			),
		),
		TemplateOID: strings.TrimSpace(
			os.Getenv(
				"FI_LIVE_PKI_TEMPLATE_OID",
			),
		),
	}

	if err := validatePKIEnrollmentContract(
		contract,
	); err != nil {
		t.Fatal(err)
	}

	beforeCertificates, err :=
		snapshotLocalMachinePKICertificates(
			contract.TemplateOID,
		)
	if err != nil {
		t.Fatalf(
			"snapshot certificates before denied enrollment: %v",
			err,
		)
	}

	beforeKeys, err :=
		snapshotFIMachineCNGKeys()
	if err != nil {
		t.Fatalf(
			"snapshot machine CNG keys before denied enrollment: %v",
			err,
		)
	}

	mutation, enrollErr :=
		enrollMachineCertificateTemplateTrackedWithInvoker(
			contract,
			func(
				templateName string,
			) error {
				return enrollMachineCertificateTemplateWithContextForLiveTest(
					templateName,
					certEnrollContextMachine,
				)
			},
		)

	if mutation.Owned {
		t.Cleanup(
			func() {
				if err := rollbackOwnedPKIEnrollment(
					mutation,
				); err != nil {
					t.Errorf(
						"cleanup unexpected transaction-owned certificate SHA256=%s key=%q: %v",
						mutation.Certificate.CertificateSHA256,
						mutation.Key.KeyName,
						err,
					)
				}
			},
		)
	}

	if len(mutation.NewMachineKeys) != 0 {
		keys := append(
			[]machineCNGKeyState(nil),
			mutation.NewMachineKeys...,
		)

		t.Cleanup(
			func() {
				if err := cleanupDeniedEnrollmentCharacterizationKey(
					contract,
					keys,
				); err != nil {
					t.Errorf(
						"cleanup denied-enrollment characterization key: %v",
						err,
					)
				}
			},
		)
	}

	if enrollErr == nil {
		t.Fatal(
			"ContextMachine characterization unexpectedly succeeded; expected AD CS denial",
		)
	}

	if !strings.Contains(
		strings.ToUpper(
			enrollErr.Error(),
		),
		certSrvSubjectDNSRequiredHRESULT,
	) {
		t.Fatalf(
			"denied enrollment returned unexpected failure; expected CERTSRV_E_SUBJECT_DNS_REQUIRED 0x%s, got: %v",
			certSrvSubjectDNSRequiredHRESULT,
			enrollErr,
		)
	}

	if mutation.Owned {
		t.Fatalf(
			"denied enrollment unexpectedly installed an owned certificate SHA256=%s key=%q: %v",
			mutation.Certificate.CertificateSHA256,
			mutation.Key.KeyName,
			enrollErr,
		)
	}

	if len(mutation.NewMachineKeys) != 0 {
		t.Fatalf(
			"denied enrollment left %d new Microsoft Software KSP machine key(s); production ownership is intentionally NOT claimed without an issued certificate: %+v",
			len(mutation.NewMachineKeys),
			mutation.NewMachineKeys,
		)
	}

	afterCertificates, err :=
		snapshotLocalMachinePKICertificates(
			contract.TemplateOID,
		)
	if err != nil {
		t.Fatalf(
			"snapshot certificates after denied enrollment: %v",
			err,
		)
	}

	afterKeys, err :=
		snapshotFIMachineCNGKeys()
	if err != nil {
		t.Fatalf(
			"snapshot machine CNG keys after denied enrollment: %v",
			err,
		)
	}

	if !reflect.DeepEqual(
		beforeCertificates,
		afterCertificates,
	) {
		t.Fatalf(
			"denied enrollment changed LocalMachine\\MY:\nbefore=%+v\nafter=%+v",
			beforeCertificates,
			afterCertificates,
		)
	}

	if !reflect.DeepEqual(
		beforeKeys,
		afterKeys,
	) {
		t.Fatalf(
			"denied enrollment changed Microsoft Software KSP machine-key inventory:\nbefore=%+v\nafter=%+v",
			beforeKeys,
			afterKeys,
		)
	}

	t.Logf(
		"denial confirmed: CERTSRV_E_SUBJECT_DNS_REQUIRED; certificates=%d machine_cng_keys=%d; no certificate or CNG key state was left behind",
		len(afterCertificates),
		len(afterKeys),
	)
}

func cleanupDeniedEnrollmentCharacterizationKey(
	contract pkiEnrollmentContract,
	keys []machineCNGKeyState,
) error {
	if len(keys) == 0 {
		return nil
	}

	if len(keys) != 1 {
		return fmt.Errorf(
			"refusing automatic characterization cleanup because %d new machine keys appeared",
			len(keys),
		)
	}

	state := keys[0]

	expectedPrefix := strings.ToLower(
		"te-" +
			strings.TrimSpace(
				contract.TemplateName,
			) +
			"-",
	)

	if !strings.HasPrefix(
		strings.ToLower(
			state.KeyName,
		),
		expectedPrefix,
	) {
		return fmt.Errorf(
			"refusing characterization cleanup for unexpected key name %q; expected prefix %q",
			state.KeyName,
			expectedPrefix,
		)
	}

	if state.ProviderName != fiPKICNGProviderName {
		return fmt.Errorf(
			"refusing characterization cleanup for provider %q",
			state.ProviderName,
		)
	}

	if !state.MachineKey {
		return fmt.Errorf(
			"refusing characterization cleanup for non-machine key %q",
			state.KeyName,
		)
	}

	if !strings.EqualFold(
		state.Algorithm,
		"RSA",
	) {
		return fmt.Errorf(
			"refusing characterization cleanup for key %q algorithm=%q",
			state.KeyName,
			state.Algorithm,
		)
	}

	return deleteCNGKey(
		cngKeyLocator{
			KeyName:      state.KeyName,
			KeySpec:      state.KeySpec,
			MachineKey:   true,
			ProviderName: state.ProviderName,
		},
	)
}

func enrollMachineCertificateTemplateWithContextForLiveTest(
	templateName string,
	enrollmentContext uint32,
) error {
	if strings.TrimSpace(
		templateName,
	) == "" {
		return fmt.Errorf(
			"certificate template name is required",
		)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	initializeResult, _, _ :=
		coInitializeExPKIProc.Call(
			0,
			uintptr(
				coinitApartmentThreaded,
			),
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

	progIDPointer, err :=
		syscall.UTF16PtrFromString(
			"X509Enrollment.CX509Enrollment",
		)
	if err != nil {
		return fmt.Errorf(
			"encode CertEnroll ProgID: %w",
			err,
		)
	}

	var classID windows.GUID

	result, _, _ :=
		clsidFromProgIDPKIProc.Call(
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

	runtime.KeepAlive(
		progIDPointer,
	)

	if certEnrollHRESULTFailed(
		result,
	) {
		return certEnrollHRESULTError(
			"CLSIDFromProgID(X509Enrollment.CX509Enrollment)",
			result,
		)
	}

	var dispatch *certEnrollDispatch

	result, _, _ =
		coCreateInstancePKIProc.Call(
			uintptr(
				unsafe.Pointer(
					&classID,
				),
			),
			0,
			uintptr(
				clsctxInprocServer,
			),
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

	if certEnrollHRESULTFailed(
		result,
	) {
		return certEnrollHRESULTError(
			"CoCreateInstance(X509Enrollment.CX509Enrollment)",
			result,
		)
	}

	if dispatch == nil ||
		dispatch.VTable == nil {
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

	templatePointer, err :=
		syscall.UTF16PtrFromString(
			templateName,
		)
	if err != nil {
		return fmt.Errorf(
			"encode certificate template %q: %w",
			templateName,
			err,
		)
	}

	bstr, _, _ :=
		sysAllocStringPKIProc.Call(
			uintptr(
				unsafe.Pointer(
					templatePointer,
				),
			),
		)

	runtime.KeepAlive(
		templatePointer,
	)

	if bstr == 0 {
		return fmt.Errorf(
			"SysAllocString failed for certificate template %q",
			templateName,
		)
	}

	defer sysFreeStringPKIProc.Call(
		bstr,
	)

	arguments := []certEnrollVariant{
		{
			Type:  variantBSTR,
			Value: bstr,
		},
		{
			Type: variantI4,
			Value: uintptr(
				enrollmentContext,
			),
		},
	}

	if err := certEnrollInvokeMethod(
		dispatch,
		"InitializeFromTemplateName",
		arguments,
	); err != nil {
		return fmt.Errorf(
			"initialize certificate enrollment context=0x%X template=%q: %w",
			enrollmentContext,
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
			"enroll certificate context=0x%X template=%q: %w",
			enrollmentContext,
			templateName,
			err,
		)
	}

	return nil
}
