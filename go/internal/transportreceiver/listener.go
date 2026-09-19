// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportrecovery"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

// Config defines the Phase 2 receiver transport-listener requirements.
type Config struct {
	BatchCRL                    *x509.RevocationList
	BatchIssuer                 *x509.Certificate
	BindAddress                 string
	CustodyRoot                 string
	GenerationEnabled           bool
	GenerationCustodyRoot       string
	GenerationMaxCanonicalBytes uint64
	GenerationMaxEncodedBytes   uint64
	GenerationMaxManifestBytes  uint64
	GenerationRecordedRoot      string
	MaxDataBytes                uint64
	RecoveryMaxCanonicalBytes   uint64
	RecoveryMaxEncodedBytes     uint64
	RecoveryMaxMembers          uint64
	Root                        *x509.Certificate
	ServerCertificate           tls.Certificate
	Source                      transporttrust.SourceAuthorization
	TransportCRL                *x509.RevocationList
	TransportIssuer             *x509.Certificate
}

// Result describes one successfully authenticated, authorized, durably received,
// and acknowledged FI transport connection.
type Result struct {
	BatchID                   string
	CipherSuite               string
	CustodyDisposition        CustodyDisposition
	DataBytes                 uint64
	FrameSHA256               string
	Generation                bool
	GenerationAcknowledgement string
	GenerationArtifactCount   uint64
	GenerationBatchCount      uint64
	GenerationCanonicalBytes  uint64
	GenerationDataBytes       uint64
	GenerationEncodedBytes    uint64
	GenerationID              string
	GenerationRecordCount     uint64
	GenerationRecordedState   string
	GenerationTransferSHA256  string
	Recovery                  bool
	RecoveryCanonicalBytes    uint64
	RecoveryID                string
	RecoveryMembers           uint64
	SourceID                  string
	TLSVersion                string
}

// ListenOnce accepts, authenticates, and receives one FI transport transaction.
//
// The transport client must first pass FI mTLS authorization. The authenticated
// application stream is then dispatched by its FI protocol magic. Batch and
// recovery transactions retain their existing durable-custody acknowledgement
// contracts. A generation transaction does not emit FIGA0001 until the exact
// FIGT0001 transfer is durable, current signing trust is revalidated, collector
// semantics pass, and the immutable recorder receipt is durable.
//
// Validation failure, custody conflict, recorder failure, storage failure, or
// context cancellation therefore produces no generation success acknowledgement.
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

	buffered := bufio.NewReader(tlsConnection)

	result, err := receiveAuthenticatedApplication(
		buffered,
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

	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.TLSVersion = tlsVersion(state.Version)

	return result, nil
}

func receiveAuthenticatedApplication(
	reader *bufio.Reader,
	writer io.Writer,
	config Config,
	currentTime time.Time,
) (Result, error) {
	if reader == nil {
		return Result{}, errors.New(
			"FI authenticated transport reader is required",
		)
	}

	if writer == nil {
		return Result{}, errors.New(
			"FI authenticated transport writer is required",
		)
	}

	magic, err := reader.Peek(8)
	if err != nil {
		return Result{}, fmt.Errorf(
			"read FI authenticated transport magic: %w",
			err,
		)
	}

	switch string(magic) {
	case transportgeneration.OfferMagic:
		generation, err := receiveAuthenticatedGeneration(
			reader,
			writer,
			config,
			currentTime,
		)
		if err != nil {
			return Result{}, fmt.Errorf(
				"receive authenticated FI generation transaction: %w",
				err,
			)
		}

		return Result{
			CustodyDisposition: CustodyDisposition(
				generation.Custody.Disposition,
			),
			Generation:                true,
			GenerationAcknowledgement: generation.Acknowledgement.Outcome,
			GenerationArtifactCount:   generation.Recorder.Receipt.Descriptor.ArtifactCount,
			GenerationBatchCount:      generation.Recorder.Receipt.BatchCount,
			GenerationCanonicalBytes:  generation.Recorder.Receipt.Descriptor.CanonicalBytes,
			GenerationDataBytes:       generation.Recorder.Receipt.DataBytes,
			GenerationEncodedBytes:    generation.Recorder.Receipt.Descriptor.EncodedDataBytes,
			GenerationID:              generation.Recorder.Receipt.Descriptor.GenerationID,
			GenerationRecordCount:     generation.Recorder.Receipt.RecordCount,
			GenerationRecordedState: string(
				generation.Recorder.Disposition,
			),
			GenerationTransferSHA256: generation.Custody.Transfer.TransferSHA256,
			SourceID:                 generation.Recorder.Receipt.Descriptor.SourceID,
		}, nil

	case transportrecovery.OfferMagic:
		recovery, err := receiveAuthenticatedRecovery(
			reader,
			writer,
			config,
			currentTime,
		)
		if err != nil {
			return Result{}, fmt.Errorf(
				"receive authenticated FI recovery transaction: %w",
				err,
			)
		}

		return Result{
			CustodyDisposition: CustodyDisposition(
				recovery.Custody.Disposition,
			),
			DataBytes:              recovery.Custody.Descriptor.EncodedDataBytes,
			FrameSHA256:            recovery.Custody.FrameSHA256,
			Recovery:               true,
			RecoveryCanonicalBytes: recovery.Custody.Descriptor.CanonicalBytes,
			RecoveryID:             recovery.Custody.Descriptor.RecoveryID,
			RecoveryMembers:        recovery.Custody.Descriptor.MemberCount,
			SourceID:               recovery.Custody.Descriptor.SourceID,
		}, nil

	default:
		transaction, err := receiveAuthenticatedBatch(
			reader,
			writer,
			config,
			currentTime,
		)
		if err != nil {
			return Result{}, err
		}

		return Result{
			BatchID:            transaction.Custody.BatchID,
			CustodyDisposition: transaction.Custody.Disposition,
			DataBytes:          transaction.Custody.DataBytes,
			FrameSHA256:        transaction.Custody.FrameSHA256,
			SourceID:           transaction.Custody.SourceID,
		}, nil
	}
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
	if err := validateGenerationListenerConfig(config); err != nil {
		return err
	}

	if err := validateRecoveryConfig(config); err != nil {
		return err
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
