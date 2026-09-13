// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportsender"
)

func TestValidateSenderConfigQueueMode(t *testing.T) {
	valid := senderConfig{
		BatchSigningCertificateSHA256: "batch-signing",
		PollInterval:                  5 * time.Second,
		ReceiverAddress:               "192.168.1.119:8443",
		ReceiverName:                  "fi-receiver-a.iss.local",
		RetryBackoff:                  10 * time.Second,
		RootCertificateSHA256:         "root",
		SourceID:                      "iss-fs-01.iss.local",
		SpoolDir:                      `C:\ProgramData\FI\spool`,
		StageDir:                      `C:\ProgramData\FI\transport-stage`,
		Timeout:                       30 * time.Second,
		TransportCRLPath:              `C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem`,
		TransportCertificateSHA256:    "transport",
		TransportIssuerSHA256:         "issuer",
	}

	if err := validateSenderConfig(valid); err != nil {
		t.Fatalf("validateSenderConfig(queue valid) error = %v", err)
	}

	missingBatchSigner := valid
	missingBatchSigner.BatchSigningCertificateSHA256 = ""
	if err := validateSenderConfig(missingBatchSigner); err == nil {
		t.Fatal("validateSenderConfig(queue missing batch signer) error = nil")
	}

	bothModes := valid
	bothModes.ManifestPath = `C:\ProgramData\FI\spool\batch-1.manifest.json`
	if err := validateSenderConfig(bothModes); err == nil {
		t.Fatal("validateSenderConfig(both modes) error = nil")
	}

	zeroPoll := valid
	zeroPoll.PollInterval = 0
	if err := validateSenderConfig(zeroPoll); err == nil {
		t.Fatal("validateSenderConfig(queue zero poll) error = nil")
	}

	zeroRetry := valid
	zeroRetry.RetryBackoff = 0
	if err := validateSenderConfig(zeroRetry); err == nil {
		t.Fatal("validateSenderConfig(queue zero retry) error = nil")
	}
}

func TestQueuedTransportFailureRetryable(t *testing.T) {
	retryable := transportsender.ErrRetryableTransport
	localFailure := errors.New("invalid local sender state")

	tests := []struct {
		name   string
		result senderResult
		err    error
		want   bool
	}{
		{name: "retryable transport", err: retryable, want: true},
		{name: "local failure", err: localFailure, want: false},
		{name: "nil error", err: nil, want: false},
		{
			name:   "durable new then local failure",
			result: senderResult{AcknowledgementOutcome: "DURABLE_NEW"},
			err:    retryable,
			want:   false,
		},
		{
			name:   "durable duplicate then local failure",
			result: senderResult{AcknowledgementOutcome: "DURABLE_DUPLICATE"},
			err:    retryable,
			want:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := queuedTransportFailureRetryable(test.result, test.err)
			if got != test.want {
				t.Fatalf("queuedTransportFailureRetryable() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRetryableSenderNetworkError(t *testing.T) {
	if !retryableSenderNetworkError(io.EOF) {
		t.Fatal("retryableSenderNetworkError(io.EOF) = false, want true")
	}
	if retryableSenderNetworkError(errors.New("certificate role mismatch")) {
		t.Fatal("retryableSenderNetworkError(local validation) = true, want false")
	}
}

func TestValidateSenderConfigRequiresOneInputMode(t *testing.T) {
	config := senderConfig{
		PollInterval:               5 * time.Second,
		ReceiverAddress:            "192.168.1.119:8443",
		ReceiverName:               "fi-receiver-a.iss.local",
		RetryBackoff:               10 * time.Second,
		RootCertificateSHA256:      "root",
		SourceID:                   "iss-fs-01.iss.local",
		StageDir:                   `C:\ProgramData\FI\transport-stage`,
		Timeout:                    30 * time.Second,
		TransportCRLPath:           `C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem`,
		TransportCertificateSHA256: "transport",
		TransportIssuerSHA256:      "issuer",
	}

	if err := validateSenderConfig(config); err == nil {
		t.Fatal("validateSenderConfig(no input mode) error = nil")
	}
}

func TestWaitForSenderIntervalCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if err := waitForSenderInterval(ctx, time.Minute); err == nil {
		t.Fatal("waitForSenderInterval(canceled) error = nil")
	}
	if time.Since(start) > time.Second {
		t.Fatal("waitForSenderInterval(canceled) did not return promptly")
	}
}
