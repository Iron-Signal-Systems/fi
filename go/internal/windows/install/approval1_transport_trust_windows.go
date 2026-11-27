// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportcrl"
	"golang.org/x/sys/windows"
)

const approval1TransportCRLDestination = `C:\ProgramData\FI\pki\crl\fi-transport-ca.crl.pem`

type approval1TransportTrustMaterial struct {
	CRLDestinationPath         string
	CRLDistributionPoint       string
	IssuerCertificateSHA256    string
	RootCertificateSHA256      string
	TransportCertificateSHA256 string
}

func deriveApproval1TransportTrustMaterial(
	certificateSHA256 string,
) (approval1TransportTrustMaterial, error) {
	if !validSHA256Hex(certificateSHA256) {
		return approval1TransportTrustMaterial{}, errors.New(
			"transport certificate SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	store, err := openLocalMachinePKIStore()
	if err != nil {
		return approval1TransportTrustMaterial{}, err
	}
	defer closeLocalMachinePKIStore(store)

	context, found, err := findLocalMachinePKICertificateContextBySHA256(
		store,
		certificateSHA256,
	)
	if err != nil {
		return approval1TransportTrustMaterial{}, err
	}
	if !found {
		return approval1TransportTrustMaterial{}, fmt.Errorf(
			"transport certificate SHA256=%s is not present in LocalMachine\\MY",
			certificateSHA256,
		)
	}
	defer freeLocalMachinePKICertificateContext(context)

	windowsContext := (*windows.CertContext)(
		unsafe.Pointer(context),
	)

	chainParameters := windows.CertChainPara{
		Size: uint32(
			unsafe.Sizeof(windows.CertChainPara{}),
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
		return approval1TransportTrustMaterial{}, fmt.Errorf(
			"build transport certificate chain for SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}
	if chain == nil {
		return approval1TransportTrustMaterial{}, fmt.Errorf(
			"build transport certificate chain for SHA256=%s: no chain returned",
			certificateSHA256,
		)
	}
	defer windows.CertFreeCertificateChain(chain)

	policyParameters := windows.CertChainPolicyPara{
		Size: uint32(
			unsafe.Sizeof(windows.CertChainPolicyPara{}),
		),
	}

	policyStatus := windows.CertChainPolicyStatus{
		Size: uint32(
			unsafe.Sizeof(windows.CertChainPolicyStatus{}),
		),
	}

	if err := windows.CertVerifyCertificateChainPolicy(
		windows.CERT_CHAIN_POLICY_BASE,
		chain,
		&policyParameters,
		&policyStatus,
	); err != nil {
		return approval1TransportTrustMaterial{}, fmt.Errorf(
			"verify transport certificate chain policy for SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	if policyStatus.Error != 0 {
		return approval1TransportTrustMaterial{}, fmt.Errorf(
			"verify transport certificate chain policy for SHA256=%s: status=0x%08X chain_index=%d element_index=%d",
			certificateSHA256,
			policyStatus.Error,
			policyStatus.ChainIndex,
			policyStatus.ElementIndex,
		)
	}

	if chain.TrustStatus.ErrorStatus != 0 {
		return approval1TransportTrustMaterial{}, fmt.Errorf(
			"transport certificate chain SHA256=%s has trust_status=0x%08X",
			certificateSHA256,
			chain.TrustStatus.ErrorStatus,
		)
	}

	certificates, err := approval1X509ChainCertificates(chain)
	if err != nil {
		return approval1TransportTrustMaterial{}, err
	}

	return approval1TransportTrustMaterialFromChain(
		certificateSHA256,
		certificates,
	)
}

func approval1TransportTrustMaterialFromChain(
	certificateSHA256 string,
	certificates []*x509.Certificate,
) (approval1TransportTrustMaterial, error) {
	if !validSHA256Hex(certificateSHA256) {
		return approval1TransportTrustMaterial{}, errors.New(
			"transport certificate SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	if len(certificates) < 2 {
		return approval1TransportTrustMaterial{}, fmt.Errorf(
			"transport certificate chain contains %d certificate(s); expected leaf plus at least one CA certificate",
			len(certificates),
		)
	}

	for index, certificate := range certificates {
		if certificate == nil || len(certificate.Raw) == 0 {
			return approval1TransportTrustMaterial{}, fmt.Errorf(
				"transport certificate chain element %d has no DER certificate",
				index,
			)
		}
	}

	leaf := certificates[0]

	observedLeafSHA256 := certificateRawSHA256(
		leaf,
	)

	if !strings.EqualFold(
		observedLeafSHA256,
		certificateSHA256,
	) {
		return approval1TransportTrustMaterial{}, fmt.Errorf(
			"transport chain leaf SHA256=%s does not match requested SHA256=%s",
			observedLeafSHA256,
			certificateSHA256,
		)
	}

	crlDistributionPoint, err := selectApproval1TransportCRLDistributionPoint(
		leaf.CRLDistributionPoints,
	)
	if err != nil {
		return approval1TransportTrustMaterial{}, err
	}

	issuer := certificates[1]
	root := certificates[len(certificates)-1]

	return approval1TransportTrustMaterial{
		CRLDestinationPath:         approval1TransportCRLDestination,
		CRLDistributionPoint:       crlDistributionPoint,
		IssuerCertificateSHA256:    certificateRawSHA256(issuer),
		RootCertificateSHA256:      certificateRawSHA256(root),
		TransportCertificateSHA256: observedLeafSHA256,
	}, nil
}

func approval1X509ChainCertificates(
	chain *windows.CertChainContext,
) ([]*x509.Certificate, error) {
	if chain == nil {
		return nil, errors.New(
			"Windows certificate chain is unavailable",
		)
	}

	if chain.ChainCount != 1 || chain.Chains == nil {
		return nil, fmt.Errorf(
			"Windows certificate chain contains %d simple chains; FI requires exactly one deterministic chain",
			chain.ChainCount,
		)
	}

	chains := unsafe.Slice(
		chain.Chains,
		int(chain.ChainCount),
	)

	simple := chains[0]
	if simple == nil {
		return nil, errors.New(
			"Windows certificate chain returned a nil simple chain",
		)
	}

	if simple.TrustStatus.ErrorStatus != 0 {
		return nil, fmt.Errorf(
			"Windows simple certificate chain has trust_status=0x%08X",
			simple.TrustStatus.ErrorStatus,
		)
	}

	if simple.NumElements < 2 ||
		simple.NumElements > 16 ||
		simple.Elements == nil {
		return nil, fmt.Errorf(
			"Windows simple certificate chain contains %d elements; expected between 2 and 16",
			simple.NumElements,
		)
	}

	elements := unsafe.Slice(
		simple.Elements,
		int(simple.NumElements),
	)

	certificates := make(
		[]*x509.Certificate,
		0,
		len(elements),
	)

	for index, element := range elements {
		if element == nil || element.CertContext == nil {
			return nil, fmt.Errorf(
				"Windows simple certificate chain element %d is unavailable",
				index,
			)
		}

		context := element.CertContext

		if context.EncodedCert == nil || context.Length == 0 {
			return nil, fmt.Errorf(
				"Windows simple certificate chain element %d has no DER certificate",
				index,
			)
		}

		raw := append(
			[]byte(nil),
			unsafe.Slice(
				context.EncodedCert,
				int(context.Length),
			)...,
		)

		certificate, err := x509.ParseCertificate(
			raw,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"parse Windows simple certificate chain element %d: %w",
				index,
				err,
			)
		}

		certificates = append(
			certificates,
			certificate,
		)
	}

	return certificates, nil
}

func certificateRawSHA256(
	certificate *x509.Certificate,
) string {
	if certificate == nil || len(certificate.Raw) == 0 {
		return ""
	}

	digest := sha256.Sum256(
		certificate.Raw,
	)

	return hex.EncodeToString(
		digest[:],
	)
}

func selectApproval1TransportCRLDistributionPoint(
	distributionPoints []string,
) (string, error) {
	return transportcrl.SelectDistributionPoint(
		distributionPoints,
	)
}

func approval1SupportedCRLDistributionPoint(
	raw string,
) bool {
	return transportcrl.SupportedDistributionPoint(
		raw,
	)
}
