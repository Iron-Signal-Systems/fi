// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportreceiver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestListenOnceRejectsNilContext(t *testing.T) {
	_, err := ListenOnce(
		nil,
		validTestConfig(),
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
		validTestConfig(),
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

func TestValidateConfig(t *testing.T) {
	valid := validTestConfig()

	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name:   "valid",
			config: valid,
		},
		{
			name: "missing bind address",
			config: Config{
				CRL:               valid.CRL,
				Root:              valid.Root,
				ServerCertificate: valid.ServerCertificate,
				Source:            valid.Source,
				TransportIssuer:   valid.TransportIssuer,
			},
			wantErr: "bind address is required",
		},
		{
			name: "missing CRL",
			config: Config{
				BindAddress:       valid.BindAddress,
				Root:              valid.Root,
				ServerCertificate: valid.ServerCertificate,
				Source:            valid.Source,
				TransportIssuer:   valid.TransportIssuer,
			},
			wantErr: "transport CRL is required",
		},
		{
			name: "missing root",
			config: Config{
				BindAddress:       valid.BindAddress,
				CRL:               valid.CRL,
				ServerCertificate: valid.ServerCertificate,
				Source:            valid.Source,
				TransportIssuer:   valid.TransportIssuer,
			},
			wantErr: "FI root certificate is required",
		},
		{
			name: "missing receiver certificate",
			config: Config{
				BindAddress: valid.BindAddress,
				CRL:         valid.CRL,
				Root:        valid.Root,
				ServerCertificate: tls.Certificate{
					PrivateKey: struct{}{},
				},
				Source:          valid.Source,
				TransportIssuer: valid.TransportIssuer,
			},
			wantErr: "receiver TLS certificate is required",
		},
		{
			name: "missing receiver private key",
			config: Config{
				BindAddress: valid.BindAddress,
				CRL:         valid.CRL,
				Root:        valid.Root,
				ServerCertificate: tls.Certificate{
					Certificate: [][]byte{{1}},
				},
				Source:          valid.Source,
				TransportIssuer: valid.TransportIssuer,
			},
			wantErr: "receiver TLS private key is required",
		},
		{
			name: "missing source",
			config: Config{
				BindAddress:       valid.BindAddress,
				CRL:               valid.CRL,
				Root:              valid.Root,
				ServerCertificate: valid.ServerCertificate,
				TransportIssuer:   valid.TransportIssuer,
			},
			wantErr: "FI source authorization is required",
		},
		{
			name: "missing transport issuer",
			config: Config{
				BindAddress:       valid.BindAddress,
				CRL:               valid.CRL,
				Root:              valid.Root,
				ServerCertificate: valid.ServerCertificate,
				Source:            valid.Source,
			},
			wantErr: "FI transport issuer is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfig(test.config)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf(
						"validateConfig() error = %v",
						err,
					)
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

func validTestConfig() Config {
	return Config{
		BindAddress: "127.0.0.1:0",
		CRL:         &x509.RevocationList{},
		Root:        &x509.Certificate{},
		ServerCertificate: tls.Certificate{
			Certificate: [][]byte{{1}},
			PrivateKey:  struct{}{},
		},
		Source: transporttrust.SourceAuthorization{
			Enabled:  true,
			SourceID: "iss-fs-01.iss.local",
		},
		TransportIssuer: &x509.Certificate{},
	}
}
