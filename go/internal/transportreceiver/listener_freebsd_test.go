// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package transportreceiver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestServeListenerContinuesAfterConnectionError(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	listener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}

	results := make(
		chan Result,
		1,
	)
	connectionErrors := make(
		chan error,
		1,
	)
	done := make(
		chan error,
		1,
	)

	go func() {
		done <- serveListener(
			ctx,
			listener,
			2,
			func(
				_ context.Context,
				connection net.Conn,
			) (Result, error) {
				var marker [1]byte

				if _, err := io.ReadFull(
					connection,
					marker[:],
				); err != nil {
					return Result{}, err
				}

				if marker[0] == 'B' {
					return Result{},
						errors.New(
							"intentional bad connection",
						)
				}

				return Result{
					SourceID: "iss-fs-22.iss.local",
				}, nil
			},
			func(result Result) {
				results <- result
			},
			func(err error) {
				connectionErrors <- err
			},
		)
	}()

	dialAndWrite := func(marker byte) {
		t.Helper()

		connection, err := net.Dial(
			"tcp",
			listener.Addr().String(),
		)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := connection.Write(
			[]byte{marker},
		); err != nil {
			_ = connection.Close()
			t.Fatal(err)
		}

		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	}

	dialAndWrite('B')

	select {
	case err := <-connectionErrors:
		if !strings.Contains(
			err.Error(),
			"intentional bad connection",
		) {
			t.Fatalf(
				"connection error = %q",
				err,
			)
		}

	case <-time.After(2 * time.Second):
		t.Fatal(
			"bad connection was not reported",
		)
	}

	dialAndWrite('G')

	select {
	case result := <-results:
		if result.SourceID !=
			"iss-fs-22.iss.local" {
			t.Fatalf(
				"result source = %q",
				result.SourceID,
			)
		}

	case <-time.After(2 * time.Second):
		t.Fatal(
			"listener did not accept good connection after bad connection",
		)
	}

	cancel()

	select {
	case err := <-done:
		if !errors.Is(
			err,
			context.Canceled,
		) {
			t.Fatalf(
				"serveListener() error = %v, want context cancellation",
				err,
			)
		}

	case <-time.After(2 * time.Second):
		t.Fatal(
			"persistent listener did not stop after cancellation",
		)
	}
}

func TestServeListenerRejectsUnenrolledTLSClientThenAcceptsEnrolledClient(
	t *testing.T,
) {
	now := time.Now().UTC().Truncate(
		time.Second,
	)

	transportTemplateOID := asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 311, 21, 8, 100, 3,
	}

	rootKey := newIntakeTestRSAKey(t)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			CommonName: "FI Listener Test Root CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x11, 0x12, 0x13, 0x14},
	}

	root := createIntakeTestCertificate(
		t,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)

	issuerKey := newIntakeTestRSAKey(t)

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName: "FI Listener Test Transport CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x21, 0x22, 0x23, 0x24},
	}

	issuer := createIntakeTestCertificate(
		t,
		issuerTemplate,
		root,
		&issuerKey.PublicKey,
		rootKey,
	)

	transportCRL := createIntakeTestCRL(
		t,
		issuer,
		issuerKey,
		now,
		nil,
	)

	serverKey := newIntakeTestRSAKey(t)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		Subject: pkix.Name{
			CommonName: "fi-receiver.test.invalid",
		},
		DNSNames: []string{
			"fi-receiver.test.invalid",
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	serverLeaf := createIntakeTestCertificate(
		t,
		serverTemplate,
		root,
		&serverKey.PublicKey,
		rootKey,
	)

	newClient := func(
		serial int64,
		sourceID string,
	) (
		*x509.Certificate,
		tls.Certificate,
	) {
		t.Helper()

		key := newIntakeTestRSAKey(t)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject: pkix.Name{
				CommonName: sourceID,
			},
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature |
				x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			ExtraExtensions: []pkix.Extension{
				receiverTestCertificateTemplateExtension(
					t,
					transportTemplateOID,
				),
			},
		}

		leaf := createIntakeTestCertificate(
			t,
			template,
			issuer,
			&key.PublicKey,
			issuerKey,
		)

		return leaf, tls.Certificate{
			Certificate: [][]byte{
				leaf.Raw,
			},
			PrivateKey: key,
			Leaf:       leaf,
		}
	}

	badLeaf, badCertificate := newClient(
		1003,
		"iss-fs-19.iss.local",
	)

	goodLeaf, goodCertificate := newClient(
		1004,
		"iss-fs-22.iss.local",
	)

	goodIdentity, err :=
		transporttrust.IdentityFromCertificate(
			goodLeaf,
			issuer,
		)
	if err != nil {
		t.Fatal(err)
	}

	goodSource := transporttrust.SourceAuthorization{
		Enabled:   true,
		SourceID:  "iss-fs-22.iss.local",
		Transport: goodIdentity,
	}

	config := validTestConfig(t)
	config.Root = root
	config.ServerCertificate = tls.Certificate{
		Certificate: [][]byte{
			serverLeaf.Raw,
		},
		PrivateKey: serverKey,
		Leaf:       serverLeaf,
	}
	config.TransportCRL = transportCRL
	config.TransportIssuer = issuer
	config.ResolveSource = func(
		certificate *x509.Certificate,
	) (
		transporttrust.SourceAuthorization,
		bool,
		error,
	) {
		if certificate == nil {
			return transporttrust.SourceAuthorization{},
				false,
				nil
		}

		if bytes.Equal(
			certificate.Raw,
			goodLeaf.Raw,
		) {
			return goodSource,
				true,
				nil
		}

		return transporttrust.SourceAuthorization{},
			false,
			nil
	}
	config.Source = transporttrust.SourceAuthorization{}

	listener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	connectionErrors := make(
		chan error,
		2,
	)

	done := make(
		chan error,
		1,
	)

	tlsConfig := newServerTLSConfig(
		config,
	)

	go func() {
		done <- serveListener(
			ctx,
			listener,
			2,
			func(
				connectionContext context.Context,
				connection net.Conn,
			) (Result, error) {
				return receiveConnection(
					connectionContext,
					config,
					tlsConfig,
					connection,
				)
			},
			nil,
			func(err error) {
				connectionErrors <- err
			},
		)
	}()

	dialTLS := func(
		certificate tls.Certificate,
	) error {
		t.Helper()

		rawConnection, err := net.Dial(
			"tcp",
			listener.Addr().String(),
		)
		if err != nil {
			return err
		}

		connection := tls.Client(
			rawConnection,
			&tls.Config{
				Certificates: []tls.Certificate{
					certificate,
				},
				// Test-only: this test exercises receiver-side client
				// authentication and source authorization.
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		)
		defer connection.Close()

		handshakeContext, stop :=
			context.WithTimeout(
				context.Background(),
				2*time.Second,
			)
		defer stop()

		return connection.HandshakeContext(
			handshakeContext,
		)
	}

	// The receiver-side verification result is authoritative here.
	// Depending on TLS version and alert timing, the client can finish its
	// local handshake before observing the server's rejection.
	_ = dialTLS(
		badCertificate,
	)

	select {
	case err := <-connectionErrors:
		if !strings.Contains(
			err.Error(),
			"TLS handshake rejected",
		) ||
			!strings.Contains(
				err.Error(),
				"not enrolled",
			) {
			t.Fatalf(
				"unenrolled connection error = %q",
				err,
			)
		}

	case <-time.After(2 * time.Second):
		t.Fatal(
			"unenrolled TLS rejection was not reported",
		)
	}

	if bytes.Equal(
		badLeaf.Raw,
		goodLeaf.Raw,
	) {
		t.Fatal(
			"TLS isolation fixture generated identical client certificates",
		)
	}

	if err := dialTLS(
		goodCertificate,
	); err != nil {
		t.Fatalf(
			"enrolled transport client TLS handshake failed: %v",
			err,
		)
	}

	select {
	case err := <-connectionErrors:
		if strings.Contains(
			err.Error(),
			"TLS handshake rejected",
		) {
			t.Fatalf(
				"enrolled client failed TLS authorization: %v",
				err,
			)
		}

		if !strings.Contains(
			err.Error(),
			"receive authenticated FI transport transaction",
		) {
			t.Fatalf(
				"enrolled client did not reach application layer: %v",
				err,
			)
		}

	case <-time.After(2 * time.Second):
		t.Fatal(
			"enrolled client application-layer close was not reported",
		)
	}

	cancel()

	select {
	case err := <-done:
		if !errors.Is(
			err,
			context.Canceled,
		) {
			t.Fatalf(
				"serveListener() error = %v, want context cancellation",
				err,
			)
		}

	case <-time.After(2 * time.Second):
		t.Fatal(
			"persistent listener did not stop after TLS isolation test",
		)
	}
}

func TestServeListenerRunsConcurrentlyWithinBound(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	listener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}

	started := make(
		chan struct{},
		3,
	)
	release := make(
		chan struct{},
		3,
	)
	done := make(
		chan error,
		1,
	)

	go func() {
		done <- serveListener(
			ctx,
			listener,
			2,
			func(
				_ context.Context,
				_ net.Conn,
			) (Result, error) {
				started <- struct{}{}
				<-release
				return Result{}, nil
			},
			nil,
			nil,
		)
	}()

	connections := make(
		[]net.Conn,
		0,
		3,
	)

	for range 3 {
		connection, err := net.Dial(
			"tcp",
			listener.Addr().String(),
		)
		if err != nil {
			t.Fatal(err)
		}

		connections = append(
			connections,
			connection,
		)
	}

	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()

	for range 2 {
		select {
		case <-started:

		case <-time.After(2 * time.Second):
			t.Fatal(
				"two connections did not run concurrently",
			)
		}
	}

	select {
	case <-started:
		t.Fatal(
			"third connection exceeded concurrency bound",
		)

	case <-time.After(150 * time.Millisecond):
	}

	release <- struct{}{}

	select {
	case <-started:

	case <-time.After(2 * time.Second):
		t.Fatal(
			"third connection did not start after capacity became available",
		)
	}

	release <- struct{}{}
	release <- struct{}{}

	cancel()

	select {
	case err := <-done:
		if !errors.Is(
			err,
			context.Canceled,
		) {
			t.Fatalf(
				"serveListener() error = %v, want context cancellation",
				err,
			)
		}

	case <-time.After(2 * time.Second):
		t.Fatal(
			"persistent listener did not stop after cancellation",
		)
	}
}

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
			name: "concurrency exceeds structural maximum",
			mutate: func(value *Config) {
				value.MaxConcurrentConnections =
					MaxConcurrentConnections + 1
			},
			wantErr: "maximum concurrent connection count exceeds",
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
			wantErr: "FI source authorization or resolver is required",
		},
		{
			name: "resolver without static source",
			mutate: func(value *Config) {
				value.Source = transporttrust.SourceAuthorization{}
				value.ResolveSource = func(
					certificate *x509.Certificate,
				) (transporttrust.SourceAuthorization, bool, error) {
					return transporttrust.SourceAuthorization{
						Enabled:  true,
						SourceID: "iss-fs-22.iss.local",
					}, true, nil
				}
			},
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

func TestResolveTransportSourceUsesResolver(
	t *testing.T,
) {
	certificate := &x509.Certificate{
		Raw: []byte("FI multi-source client certificate"),
	}

	expected := transporttrust.SourceAuthorization{
		Enabled:  true,
		SourceID: "iss-fs-22.iss.local",
	}

	config := Config{
		ResolveSource: func(
			presented *x509.Certificate,
		) (
			transporttrust.SourceAuthorization,
			bool,
			error,
		) {
			if presented != certificate {
				t.Fatal(
					"resolver received unexpected certificate",
				)
			}

			return expected, true, nil
		},
	}

	resolved, found, err := resolveTransportSource(
		config,
		certificate,
	)
	if err != nil {
		t.Fatalf(
			"resolveTransportSource() error = %v",
			err,
		)
	}

	if !found {
		t.Fatal(
			"resolveTransportSource() found = false",
		)
	}

	if resolved.SourceID != expected.SourceID {
		t.Fatalf(
			"resolved SourceID = %q, want %q",
			resolved.SourceID,
			expected.SourceID,
		)
	}
}

func TestResolveTransportSourceRejectsUnknownCertificate(
	t *testing.T,
) {
	config := Config{
		ResolveSource: func(
			certificate *x509.Certificate,
		) (
			transporttrust.SourceAuthorization,
			bool,
			error,
		) {
			return transporttrust.SourceAuthorization{},
				false,
				nil
		},
	}

	_, found, err := resolveTransportSource(
		config,
		&x509.Certificate{
			Raw: []byte("unknown FI client certificate"),
		},
	)
	if err != nil {
		t.Fatalf(
			"resolveTransportSource() error = %v",
			err,
		)
	}

	if found {
		t.Fatal(
			"unknown FI certificate resolved to a source",
		)
	}
}

func TestResolveTransportSourcePreservesStaticSourceCompatibility(
	t *testing.T,
) {
	expected := transporttrust.SourceAuthorization{
		Enabled:  true,
		SourceID: "iss-fs-01.iss.local",
	}

	config := Config{
		Source: expected,
	}

	resolved, found, err := resolveTransportSource(
		config,
		&x509.Certificate{
			Raw: []byte("legacy single-source certificate"),
		},
	)
	if err != nil {
		t.Fatalf(
			"resolveTransportSource() error = %v",
			err,
		)
	}

	if !found {
		t.Fatal(
			"static FI source did not resolve",
		)
	}

	if resolved.SourceID != expected.SourceID {
		t.Fatalf(
			"resolved SourceID = %q, want %q",
			resolved.SourceID,
			expected.SourceID,
		)
	}
}

func TestResolveSourceIDUsesLookup(
	t *testing.T,
) {
	expected := transporttrust.SourceAuthorization{
		Enabled:  true,
		SourceID: "iss-fs-22.iss.local",
	}

	config := Config{
		LookupSource: func(
			sourceID string,
		) (
			transporttrust.SourceAuthorization,
			bool,
		) {
			if sourceID != expected.SourceID {
				t.Fatalf(
					"LookupSource sourceID = %q, want %q",
					sourceID,
					expected.SourceID,
				)
			}

			return expected, true
		},
	}

	resolved, found, err := resolveSourceID(
		config,
		expected.SourceID,
	)
	if err != nil {
		t.Fatalf(
			"resolveSourceID() error = %v",
			err,
		)
	}

	if !found {
		t.Fatal(
			"resolveSourceID() found = false",
		)
	}

	if resolved.SourceID != expected.SourceID {
		t.Fatalf(
			"resolved SourceID = %q, want %q",
			resolved.SourceID,
			expected.SourceID,
		)
	}
}

func TestResolveSourceIDRejectsUnknownSource(
	t *testing.T,
) {
	config := Config{
		LookupSource: func(
			sourceID string,
		) (
			transporttrust.SourceAuthorization,
			bool,
		) {
			return transporttrust.SourceAuthorization{},
				false
		},
	}

	_, found, err := resolveSourceID(
		config,
		"iss-fs-99.iss.local",
	)
	if err != nil {
		t.Fatalf(
			"resolveSourceID() error = %v",
			err,
		)
	}

	if found {
		t.Fatal(
			"unknown source resolved from registry",
		)
	}
}

func TestResolveSourceIDRejectsIdentityMismatch(
	t *testing.T,
) {
	config := Config{
		LookupSource: func(
			sourceID string,
		) (
			transporttrust.SourceAuthorization,
			bool,
		) {
			return transporttrust.SourceAuthorization{
				Enabled:  true,
				SourceID: "ISS-FS-22.iss.local",
			}, true
		},
	}

	_, found, err := resolveSourceID(
		config,
		"iss-fs-22.iss.local",
	)

	if err == nil {
		t.Fatal(
			"source lookup identity mismatch was accepted",
		)
	}

	if found {
		t.Fatal(
			"source lookup identity mismatch returned found=true",
		)
	}
}
