// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

// Config defines the Phase 2 receiver transport-listener requirements.
type Config struct {
	BatchCRL          *x509.RevocationList
	BatchIssuer       *x509.Certificate
	BindAddress       string
	CustodyRoot       string
	MaxDataBytes      uint64
	Root              *x509.Certificate
	ServerCertificate tls.Certificate
	Source            transporttrust.SourceAuthorization
	TransportCRL      *x509.RevocationList
	TransportIssuer   *x509.Certificate
}

// Result describes one successfully authenticated, authorized, durably received,
// and acknowledged FI transport connection.
type Result struct {
	BatchID            string
	CipherSuite        string
	CustodyDisposition CustodyDisposition
	DataBytes          uint64
	FrameSHA256        string
	SourceID           string
	TLSVersion         string
}

// ListenOnce accepts, authenticates, and receives one FI transport transaction.
//
// The transport client must first pass FI mTLS authorization. The authenticated
// stream is then handed directly to ReceiveAndAcknowledge, so no success response
// is written until the exact frame has crossed the durable receiver-custody
// boundary. Validation failure, custody conflict, storage failure, or context
// cancellation therefore produces no FI durable success acknowledgement.
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
				config.TransportCRL,
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
	stopConnectionWatch := closeConnectionOnContext(ctx, tlsConnection)
	defer stopConnectionWatch()

	transaction, err := receiveAuthenticatedBatch(
		tlsConnection,
		tlsConnection,
		config,
		time.Now(),
	)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, fmt.Errorf(
				"receive authenticated FI transport transaction: %w",
				ctx.Err(),
			)
		}
		return Result{}, fmt.Errorf(
			"receive authenticated FI transport transaction: %w",
			err,
		)
	}

	return Result{
		BatchID:            transaction.Custody.BatchID,
		CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
		CustodyDisposition: transaction.Custody.Disposition,
		DataBytes:          transaction.Custody.DataBytes,
		FrameSHA256:        transaction.Custody.FrameSHA256,
		SourceID:           transaction.Custody.SourceID,
		TLSVersion:         tlsVersion(state.Version),
	}, nil
}

func clientCAPool(issuer *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(issuer)

	return pool
}

func closeConnectionOnContext(
	ctx context.Context,
	connection io.Closer,
) func() {
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()

	return func() {
		close(done)
	}
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

func receiveAuthenticatedBatch(
	reader io.Reader,
	acknowledgementWriter io.Writer,
	config Config,
	currentTime time.Time,
) (ReceiveTransactionResult, error) {
	return ReceiveAndAcknowledge(
		reader,
		acknowledgementWriter,
		CustodyConfig{
			Intake: IntakeConfig{
				BatchCRL:     config.BatchCRL,
				BatchIssuer:  config.BatchIssuer,
				CurrentTime:  currentTime,
				MaxDataBytes: config.MaxDataBytes,
				Root:         config.Root,
				Source:       config.Source,
			},
			RootDir: config.CustodyRoot,
		},
	)
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
	if config.BatchCRL == nil {
		return errors.New("batch-signing CRL is required")
	}

	if config.BatchIssuer == nil {
		return errors.New("FI batch-signing issuer is required")
	}

	if config.BindAddress == "" {
		return errors.New("bind address is required")
	}

	if config.CustodyRoot == "" {
		return errors.New("durable custody root directory is required")
	}

	if config.MaxDataBytes == 0 {
		return errors.New("maximum batch data byte count must be greater than zero")
	}

	if config.Root == nil {
		return errors.New("FI root certificate is required")
	}

	if config.Source.SourceID == "" {
		return errors.New("FI source authorization is required")
	}

	if config.TransportCRL == nil {
		return errors.New("transport CRL is required")
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

	return validateCustodyConfig(CustodyConfig{
		Intake: IntakeConfig{
			BatchCRL:     config.BatchCRL,
			BatchIssuer:  config.BatchIssuer,
			CurrentTime:  time.Unix(1, 0),
			MaxDataBytes: config.MaxDataBytes,
			Root:         config.Root,
			Source:       config.Source,
		},
		RootDir: config.CustodyRoot,
	})
}
