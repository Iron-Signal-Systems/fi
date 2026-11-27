// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

// ReadinessInput contains every receiver trust state required before the
// receiver can declare its trust configuration ready.
type ReadinessInput struct {
	BatchCRL            ValidationState
	BatchIssuer         ValidationState
	Parsing             ParseStatus
	Presence            Status
	ReceiverCertificate ValidationState
	ReceiverHostname    ValidationState
	ReceiverKey         ValidationState
	ReceiverRevocation  ValidationState
	RootCA              ValidationState
	SourceRegistry      ValidationState
	TransportCRL        ValidationState
	TransportIssuer     ValidationState
	TrustCustody        ValidationState
}

// ReadinessState describes aggregate receiver trust readiness.
type ReadinessState struct {
	Detail string
	Ready  bool
}

// EvaluateReadiness returns READY only when every required trust layer has
// already succeeded.
//
// It does not perform filesystem, parsing, cryptographic, registry, or custody
// inspection itself. The caller supplies those already-computed states so the
// aggregate result exactly represents the checks reported to the operator.
func EvaluateReadiness(input ReadinessInput) ReadinessState {
	if !input.Presence.Complete {
		return ReadinessState{
			Detail: "required receiver trust material is incomplete",
		}
	}

	if !input.Parsing.Complete {
		return ReadinessState{
			Detail: "required receiver trust material did not parse completely",
		}
	}

	checks := []struct {
		name  string
		state ValidationState
	}{
		{
			name:  "root CA",
			state: input.RootCA,
		},
		{
			name:  "transport issuing CA",
			state: input.TransportIssuer,
		},
		{
			name:  "batch signing CA",
			state: input.BatchIssuer,
		},
		{
			name:  "transport CRL",
			state: input.TransportCRL,
		},
		{
			name:  "batch signing CRL",
			state: input.BatchCRL,
		},
		{
			name:  "receiver certificate",
			state: input.ReceiverCertificate,
		},
		{
			name:  "receiver private key",
			state: input.ReceiverKey,
		},
		{
			name:  "receiver hostname",
			state: input.ReceiverHostname,
		},
		{
			name:  "receiver revocation",
			state: input.ReceiverRevocation,
		},
		{
			name:  "source registry",
			state: input.SourceRegistry,
		},
		{
			name:  "trust custody",
			state: input.TrustCustody,
		},
	}

	for _, check := range checks {
		if check.state.Valid {
			continue
		}

		detail := check.name + " validation failed"
		if check.state.Detail != "" {
			detail += ": " + check.state.Detail
		}

		return ReadinessState{
			Detail: detail,
		}
	}

	return ReadinessState{
		Ready: true,
	}
}
