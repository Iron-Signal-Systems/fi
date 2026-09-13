// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestListenOnceRejectsNilContext(t *testing.T) {
	_, err := ListenOnce(
		nil,
		validTestConfig(t),
	)
	if err == nil {
		t.Fatal("ListenOnce() error = nil, want context rejection")
	}

	if !strings.Contains(err.Error(), "context is required") {
		t.Fatalf(
			"ListenOnce() error = %q, want context rejection",
			err,
		)
	}
}

func TestListenOnceStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		100*time.Millisecond,
	)
	defer cancel()

	start := time.Now()

	_, err := ListenOnce(
		ctx,
		validTestConfig(t),
	)

	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ListenOnce() error = nil, want context cancellation")
	}

	if !strings.Contains(
		err.Error(),
		context.DeadlineExceeded.Error(),
	) {
		t.Fatalf(
			"ListenOnce() error = %q, want context deadline exceeded",
			err,
		)
	}

	if elapsed > 2*time.Second {
		t.Fatalf(
			"ListenOnce() took %s after context cancellation, want less than 2s",
			elapsed,
		)
	}
}

func TestReceiveAuthenticatedBatchWritesDurableAcknowledgement(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	config := validTestConfig(t)
	config.BatchCRL = fixture.config.BatchCRL
	config.BatchIssuer = fixture.config.BatchIssuer
	config.MaxDataBytes = fixture.config.MaxDataBytes
	config.Root = fixture.config.Root
	config.Source = fixture.config.Source

	var acknowledgement bytes.Buffer
	transaction, err := receiveAuthenticatedBatch(
		bytes.NewReader(frame),
		&acknowledgement,
		config,
		fixture.config.CurrentTime,
	)
	if err != nil {
		t.Fatalf("receiveAuthenticatedBatch() error = %v", err)
	}
	if transaction.Custody.Disposition != CustodyDispositionNew {
		t.Fatalf(
			"custody disposition = %q, want %q",
			transaction.Custody.Disposition,
			CustodyDispositionNew,
		)
	}
	if transaction.Custody.SourceID != fixture.config.Source.SourceID {
		t.Fatalf(
			"custody source ID = %q, want %q",
			transaction.Custody.SourceID,
			fixture.config.Source.SourceID,
		)
	}

	decoded, err := transportack.ReadAcknowledgement(
		bytes.NewReader(acknowledgement.Bytes()),
	)
	if err != nil {
		t.Fatalf("transportack.ReadAcknowledgement() error = %v", err)
	}
	if decoded.Outcome != transportack.OutcomeDurableNew {
		t.Fatalf(
			"acknowledgement outcome = %q, want %q",
			decoded.Outcome,
			transportack.OutcomeDurableNew,
		)
	}
	if decoded.FrameSHA256 != transaction.Custody.FrameSHA256 {
		t.Fatal("acknowledgement frame SHA-256 does not match durable custody")
	}
}

func TestValidateConfig(t *testing.T) {
	valid := validTestConfig(t)

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "valid",
		},
		{
			name: "missing batch CRL",
			mutate: func(value *Config) {
				value.BatchCRL = nil
			},
			wantErr: "batch-signing CRL is required",
		},
		{
			name: "missing batch issuer",
			mutate: func(value *Config) {
				value.BatchIssuer = nil
			},
			wantErr: "FI batch-signing issuer is required",
		},
		{
			name: "missing bind address",
			mutate: func(value *Config) {
				value.BindAddress = ""
			},
			wantErr: "bind address is required",
		},
		{
			name: "missing custody root",
			mutate: func(value *Config) {
				value.CustodyRoot = ""
			},
			wantErr: "durable custody root directory is required",
		},
		{
			name: "missing maximum data bytes",
			mutate: func(value *Config) {
				value.MaxDataBytes = 0
			},
			wantErr: "maximum batch data byte count must be greater than zero",
		},
		{
			name: "missing root",
			mutate: func(value *Config) {
				value.Root = nil
			},
			wantErr: "FI root certificate is required",
		},
		{
			name: "missing receiver certificate",
			mutate: func(value *Config) {
				value.ServerCertificate = tls.Certificate{
					PrivateKey: struct{}{},
				}
			},
			wantErr: "receiver TLS certificate is required",
		},
		{
			name: "missing receiver private key",
			mutate: func(value *Config) {
				value.ServerCertificate = tls.Certificate{
					Certificate: [][]byte{{1}},
				}
			},
			wantErr: "receiver TLS private key is required",
		},
		{
			name: "missing source",
			mutate: func(value *Config) {
				value.Source = transporttrust.SourceAuthorization{}
			},
			wantErr: "FI source authorization is required",
		},
		{
			name: "missing transport CRL",
			mutate: func(value *Config) {
				value.TransportCRL = nil
			},
			wantErr: "transport CRL is required",
		},
		{
			name: "missing transport issuer",
			mutate: func(value *Config) {
				value.TransportIssuer = nil
			},
			wantErr: "FI transport issuer is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			if test.mutate != nil {
				test.mutate(&value)
			}

			err := validateConfig(value)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateConfig() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf(
					"validateConfig() error = nil, want %q",
					test.wantErr,
				)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"validateConfig() error = %q, want containing %q",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func validTestConfig(t *testing.T) Config {
	t.Helper()

	return Config{
		BatchCRL:     &x509.RevocationList{},
		BatchIssuer:  &x509.Certificate{},
		BindAddress:  "127.0.0.1:0",
		CustodyRoot:  t.TempDir(),
		MaxDataBytes: 1,
		Root:         &x509.Certificate{},
		ServerCertificate: tls.Certificate{
			Certificate: [][]byte{{1}},
			PrivateKey:  struct{}{},
		},
		Source: transporttrust.SourceAuthorization{
			Enabled:  true,
			SourceID: "iss-fs-01.iss.local",
		},
		TransportCRL:    &x509.RevocationList{},
		TransportIssuer: &x509.Certificate{},
	}
}
