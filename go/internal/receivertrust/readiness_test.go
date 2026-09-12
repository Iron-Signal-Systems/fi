// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import "testing"

func TestEvaluateReadiness(t *testing.T) {
	input := readyReadinessInput()

	state := EvaluateReadiness(input)
	if !state.Ready {
		t.Fatalf(
			"ReadinessState.Ready = false, want true: %s",
			state.Detail,
		)
	}

	if state.Detail != "" {
		t.Fatalf(
			"ReadinessState.Detail = %q, want empty",
			state.Detail,
		)
	}
}

func TestEvaluateReadinessRejectsIncompletePresence(t *testing.T) {
	input := readyReadinessInput()
	input.Presence.Complete = false

	state := EvaluateReadiness(input)
	if state.Ready {
		t.Fatal("ReadinessState.Ready = true, want false")
	}

	if state.Detail == "" {
		t.Fatal("ReadinessState.Detail is empty, want failure detail")
	}
}

func TestEvaluateReadinessRejectsIncompleteParsing(t *testing.T) {
	input := readyReadinessInput()
	input.Parsing.Complete = false

	state := EvaluateReadiness(input)
	if state.Ready {
		t.Fatal("ReadinessState.Ready = true, want false")
	}

	if state.Detail == "" {
		t.Fatal("ReadinessState.Detail is empty, want failure detail")
	}
}

func TestEvaluateReadinessRejectsInvalidValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ReadinessInput)
	}{
		{
			name: "batch CRL",
			mutate: func(input *ReadinessInput) {
				input.BatchCRL = invalidReadinessValidation()
			},
		},
		{
			name: "batch issuer",
			mutate: func(input *ReadinessInput) {
				input.BatchIssuer = invalidReadinessValidation()
			},
		},
		{
			name: "receiver certificate",
			mutate: func(input *ReadinessInput) {
				input.ReceiverCertificate = invalidReadinessValidation()
			},
		},
		{
			name: "receiver hostname",
			mutate: func(input *ReadinessInput) {
				input.ReceiverHostname = invalidReadinessValidation()
			},
		},
		{
			name: "receiver key",
			mutate: func(input *ReadinessInput) {
				input.ReceiverKey = invalidReadinessValidation()
			},
		},
		{
			name: "receiver revocation",
			mutate: func(input *ReadinessInput) {
				input.ReceiverRevocation = invalidReadinessValidation()
			},
		},
		{
			name: "root CA",
			mutate: func(input *ReadinessInput) {
				input.RootCA = invalidReadinessValidation()
			},
		},
		{
			name: "source registry",
			mutate: func(input *ReadinessInput) {
				input.SourceRegistry = invalidReadinessValidation()
			},
		},
		{
			name: "transport CRL",
			mutate: func(input *ReadinessInput) {
				input.TransportCRL = invalidReadinessValidation()
			},
		},
		{
			name: "transport issuer",
			mutate: func(input *ReadinessInput) {
				input.TransportIssuer = invalidReadinessValidation()
			},
		},
		{
			name: "trust custody",
			mutate: func(input *ReadinessInput) {
				input.TrustCustody = invalidReadinessValidation()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := readyReadinessInput()
			test.mutate(&input)

			state := EvaluateReadiness(input)
			if state.Ready {
				t.Fatal("ReadinessState.Ready = true, want false")
			}

			if state.Detail == "" {
				t.Fatal(
					"ReadinessState.Detail is empty, want failure detail",
				)
			}
		})
	}
}

func invalidReadinessValidation() ValidationState {
	return ValidationState{
		Detail: "test validation failure",
	}
}

func readyReadinessInput() ReadinessInput {
	valid := ValidationState{
		Valid: true,
	}

	return ReadinessInput{
		BatchCRL:            valid,
		BatchIssuer:         valid,
		Parsing:             ParseStatus{Complete: true},
		Presence:            Status{Complete: true},
		ReceiverCertificate: valid,
		ReceiverHostname:    valid,
		ReceiverKey:         valid,
		ReceiverRevocation:  valid,
		RootCA:              valid,
		SourceRegistry:      valid,
		TransportCRL:        valid,
		TransportIssuer:     valid,
		TrustCustody:        valid,
	}
}
