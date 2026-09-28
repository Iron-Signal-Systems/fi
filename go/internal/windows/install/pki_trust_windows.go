// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func verifyLocalMachineCertificateTrust(
	certificateSHA256 string,
) error {
	store, err := openLocalMachinePKIStore()
	if err != nil {
		return err
	}
	defer closeLocalMachinePKIStore(
		store,
	)

	context, found, err :=
		findLocalMachinePKICertificateContextBySHA256(
			store,
			certificateSHA256,
		)
	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf(
			"certificate SHA256=%s disappeared from LocalMachine\\MY during trust verification",
			certificateSHA256,
		)
	}

	defer freeLocalMachinePKICertificateContext(
		context,
	)

	windowsContext := (*windows.CertContext)(
		unsafe.Pointer(
			context,
		),
	)

	chainParameters := windows.CertChainPara{
		Size: uint32(
			unsafe.Sizeof(
				windows.CertChainPara{},
			),
		),
		URLRetrievalTimeout: 10_000,
	}

	var chain *windows.CertChainContext

	if err := windows.CertGetCertificateChain(
		0,
		windowsContext,
		nil,
		windows.Handle(store),
		&chainParameters,
		certChainRevocationCheckChainExcludeRoot,
		0,
		&chain,
	); err != nil {
		return fmt.Errorf(
			"build certificate chain with revocation checking for SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	if chain == nil {
		return fmt.Errorf(
			"build certificate chain with revocation checking for SHA256=%s: no chain returned",
			certificateSHA256,
		)
	}

	defer windows.CertFreeCertificateChain(
		chain,
	)

	policyParameters := windows.CertChainPolicyPara{
		Size: uint32(
			unsafe.Sizeof(
				windows.CertChainPolicyPara{},
			),
		),
	}

	policyStatus := windows.CertChainPolicyStatus{
		Size: uint32(
			unsafe.Sizeof(
				windows.CertChainPolicyStatus{},
			),
		),
	}

	if err := windows.CertVerifyCertificateChainPolicy(
		windows.CERT_CHAIN_POLICY_BASE,
		chain,
		&policyParameters,
		&policyStatus,
	); err != nil {
		return fmt.Errorf(
			"verify certificate chain policy for SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	if policyStatus.Error != 0 {
		return fmt.Errorf(
			"verify certificate chain policy for SHA256=%s: status=0x%08X chain_index=%d element_index=%d",
			certificateSHA256,
			policyStatus.Error,
			policyStatus.ChainIndex,
			policyStatus.ElementIndex,
		)
	}

	if chain.TrustStatus.ErrorStatus != 0 {
		return fmt.Errorf(
			"verify certificate chain for SHA256=%s: trust_status=0x%08X",
			certificateSHA256,
			chain.TrustStatus.ErrorStatus,
		)
	}

	return nil
}
