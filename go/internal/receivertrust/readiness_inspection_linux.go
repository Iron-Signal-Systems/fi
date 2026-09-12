// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package receivertrust

import "fmt"

type readinessInspectionFunctions struct {
	inspectBatchCRL            func() ValidationState
	inspectBatchIssuer         func() ValidationState
	inspectParsing             func() ParseStatus
	inspectPresence            func() (Status, error)
	inspectReceiverCertificate func() ValidationState
	inspectReceiverHostname    func() ValidationState
	inspectReceiverKey         func() ValidationState
	inspectReceiverRevocation  func() ValidationState
	inspectRootCA              func() ValidationState
	inspectSourceRegistry      func() ValidationState
	inspectTransportCRL        func() ValidationState
	inspectTransportIssuer     func() ValidationState
	inspectTrustCustody        func() ValidationState
}

// InspectReadiness inspects the installed receiver trust state and returns the
// same aggregate readiness contract used by the trust-status command.
//
// Presence and parsing are checked first. If either broad layer is incomplete,
// later cryptographic and custody inspections are not required to establish
// that receiver trust is not ready.
func InspectReadiness() ReadinessState {
	return inspectReadiness(
		readinessInspectionFunctions{
			inspectBatchCRL:            InspectBatchCRLValidation,
			inspectBatchIssuer:         InspectBatchIssuerValidation,
			inspectParsing:             InspectParsing,
			inspectPresence:            Inspect,
			inspectReceiverCertificate: InspectReceiverCertificateValidation,
			inspectReceiverHostname:    InspectReceiverHostnameValidation,
			inspectReceiverKey:         InspectReceiverKeyValidation,
			inspectReceiverRevocation:  InspectReceiverRevocationValidation,
			inspectRootCA:              InspectRootCAValidation,
			inspectSourceRegistry:      InspectSourceRegistryValidation,
			inspectTransportCRL:        InspectTransportCRLValidation,
			inspectTransportIssuer:     InspectTransportIssuerValidation,
			inspectTrustCustody:        InspectTrustCustodyValidation,
		},
	)
}

func inspectReadiness(
	inspectors readinessInspectionFunctions,
) ReadinessState {
	presence, err := inspectors.inspectPresence()
	if err != nil {
		return ReadinessState{
			Detail: fmt.Sprintf(
				"inspect receiver trust presence: %v",
				err,
			),
		}
	}

	if !presence.Complete {
		return EvaluateReadiness(
			ReadinessInput{
				Presence: presence,
			},
		)
	}

	parsing := inspectors.inspectParsing()
	if !parsing.Complete {
		return EvaluateReadiness(
			ReadinessInput{
				Parsing:  parsing,
				Presence: presence,
			},
		)
	}

	return EvaluateReadiness(
		ReadinessInput{
			BatchCRL:            inspectors.inspectBatchCRL(),
			BatchIssuer:         inspectors.inspectBatchIssuer(),
			Parsing:             parsing,
			Presence:            presence,
			ReceiverCertificate: inspectors.inspectReceiverCertificate(),
			ReceiverHostname:    inspectors.inspectReceiverHostname(),
			ReceiverKey:         inspectors.inspectReceiverKey(),
			ReceiverRevocation:  inspectors.inspectReceiverRevocation(),
			RootCA:              inspectors.inspectRootCA(),
			SourceRegistry:      inspectors.inspectSourceRegistry(),
			TransportCRL:        inspectors.inspectTransportCRL(),
			TransportIssuer:     inspectors.inspectTransportIssuer(),
			TrustCustody:        inspectors.inspectTrustCustody(),
		},
	)
}
