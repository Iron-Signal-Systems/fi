// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportreceiver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

// Config defines the Phase 2 receiver transport-listener requirements.
type Config struct {
	BindAddress       string
	CRL               *x509.RevocationList
	Root              *x509.Certificate
	ServerCertificate tls.Certificate
	Source            transporttrust.SourceAuthorization
	TransportIssuer   *x509.Certificate
}

// Result describes one successfully authenticated and authorized connection.
type Result struct {
	CipherSuite string
	SourceID    string
	TLSVersion  string
}

// ListenOnce accepts and verifies one FI transport connection.
//
// This is intentionally single-connection while the Phase 2 transport contract
// is being established. Long-running receiver lifecycle belongs to the later
// receiver runtime.
func ListenOnce(
	ctx context.Context,
	config Config,
) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("context is required")
	}

	if err := validateConfig(config); err != nil {
		return Result{}, err
	}

	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		return Result{}, fmt.Errorf(
			"listen on %s: %w",
			config.BindAddress,
			err,
		)
	}
	defer listener.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			config.ServerCertificate,
		},
		ClientAuth: tls.RequireAnyClientCert,
		ClientCAs:  clientCAPool(config.TransportIssuer),
		MinVersion: tls.VersionTLS12,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("FI client certificate is required")
			}

			leaf := state.PeerCertificates[0]

			var intermediates []*x509.Certificate
			if len(state.PeerCertificates) > 1 {
				intermediates = state.PeerCertificates[1:]
			}

			outcome, err := transporttrust.VerifyTransportCertificate(
				leaf,
				intermediates,
				config.Root,
				config.TransportIssuer,
				config.CRL,
				config.Source,
				time.Now(),
			)
			if err != nil {
				return err
			}

			if outcome != transporttrust.AuthorizationAuthorized {
				return fmt.Errorf(
					"FI source authorization rejected: %s",
					outcome,
				)
			}

			return nil
		},
	}

	stopContextWatch := closeListenerOnContext(ctx, listener)

	connection, err := listener.Accept()

	stopContextWatch()

	if err != nil {
		if ctx.Err() != nil {
			return Result{}, fmt.Errorf(
				"accept connection: %w",
				ctx.Err(),
			)
		}

		return Result{}, fmt.Errorf(
			"accept connection: %w",
			err,
		)
	}
	defer connection.Close()

	tlsConnection := tls.Server(connection, tlsConfig)
	defer tlsConnection.Close()

	handshakeContext, cancel := context.WithTimeout(
		ctx,
		15*time.Second,
	)
	defer cancel()

	if err := tlsConnection.HandshakeContext(handshakeContext); err != nil {
		return Result{}, fmt.Errorf(
			"TLS handshake rejected: %w",
			err,
		)
	}

	state := tlsConnection.ConnectionState()

	if _, err := tlsConnection.Write(
		[]byte("FI TRANSPORT TRUST PASS\n"),
	); err != nil {
		return Result{}, fmt.Errorf(
			"write trust response: %w",
			err,
		)
	}

	return Result{
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		SourceID:    config.Source.SourceID,
		TLSVersion:  tlsVersion(state.Version),
	}, nil
}

func clientCAPool(issuer *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(issuer)

	return pool
}

func closeListenerOnContext(
	ctx context.Context,
	listener net.Listener,
) func() {
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()

	return func() {
		close(done)
	}
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func validateConfig(config Config) error {
	if config.BindAddress == "" {
		return errors.New("bind address is required")
	}

	if config.CRL == nil {
		return errors.New("transport CRL is required")
	}

	if config.Root == nil {
		return errors.New("FI root certificate is required")
	}

	if config.Source.SourceID == "" {
		return errors.New("FI source authorization is required")
	}

	if config.TransportIssuer == nil {
		return errors.New("FI transport issuer is required")
	}

	if len(config.ServerCertificate.Certificate) == 0 {
		return errors.New("receiver TLS certificate is required")
	}

	if config.ServerCertificate.PrivateKey == nil {
		return errors.New("receiver TLS private key is required")
	}

	return nil
}
