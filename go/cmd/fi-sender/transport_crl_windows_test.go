// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportsender"
)

func TestLoadAndValidateTransportCRLAcceptsCanonicalPEM(
	t *testing.T,
) {
	now := time.Now().UTC()

	issuer, key := newSenderCRLContractIssuer(
		t,
		"FI Sender CRL Contract CA",
	)

	crl := newSenderCRLContractCRL(
		t,
		issuer,
		key,
		now.Add(-time.Minute),
		now.Add(time.Hour),
	)

	path := writeSenderCRLContractPEM(
		t,
		crl,
	)

	observed, err := loadAndValidateTransportCRL(
		path,
		issuer,
		now,
	)
	if err != nil {
		t.Fatalf(
			"loadAndValidateTransportCRL() error = %v",
			err,
		)
	}

	if !bytes.Equal(
		observed.Raw,
		crl.Raw,
	) {
		t.Fatal(
			"loaded CRL DER differs from canonical PEM source",
		)
	}
}

func TestLoadAndValidateTransportCRLRejectsRawDER(
	t *testing.T,
) {
	now := time.Now().UTC()

	issuer, key := newSenderCRLContractIssuer(
		t,
		"FI Sender DER Rejection CA",
	)

	crl := newSenderCRLContractCRL(
		t,
		issuer,
		key,
		now.Add(-time.Minute),
		now.Add(time.Hour),
	)

	path := filepath.Join(
		t.TempDir(),
		"fi-transport-ca.crl.pem",
	)

	if err := os.WriteFile(
		path,
		crl.Raw,
		0600,
	); err != nil {
		t.Fatalf(
			"os.WriteFile() error = %v",
			err,
		)
	}

	_, err := loadAndValidateTransportCRL(
		path,
		issuer,
		now,
	)
	if err == nil {
		t.Fatal(
			"raw DER transport CRL was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not contain PEM data",
	) {
		t.Fatalf(
			"error = %q, want canonical PEM rejection",
			err,
		)
	}
}

func TestLoadAndValidateTransportCRLRejectsExpiredCRL(
	t *testing.T,
) {
	now := time.Now().UTC()

	issuer, key := newSenderCRLContractIssuer(
		t,
		"FI Sender Expired CRL CA",
	)

	crl := newSenderCRLContractCRL(
		t,
		issuer,
		key,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
	)

	path := writeSenderCRLContractPEM(
		t,
		crl,
	)

	_, err := loadAndValidateTransportCRL(
		path,
		issuer,
		now,
	)
	if err == nil {
		t.Fatal(
			"expired transport CRL was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"FI transport CRL is expired:",
	) {
		t.Fatalf(
			"error = %q, want sender fail-stop expiry context",
			err,
		)
	}
}

func TestLoadAndValidateTransportCRLRejectsWrongIssuer(
	t *testing.T,
) {
	now := time.Now().UTC()

	issuer, key := newSenderCRLContractIssuer(
		t,
		"FI Sender Actual CRL CA",
	)

	wrongIssuer, _ := newSenderCRLContractIssuer(
		t,
		"FI Sender Wrong CRL CA",
	)

	crl := newSenderCRLContractCRL(
		t,
		issuer,
		key,
		now.Add(-time.Minute),
		now.Add(time.Hour),
	)

	path := writeSenderCRLContractPEM(
		t,
		crl,
	)

	_, err := loadAndValidateTransportCRL(
		path,
		wrongIssuer,
		now,
	)
	if err == nil {
		t.Fatal(
			"transport CRL with wrong issuer was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"issuer does not match",
	) {
		t.Fatalf(
			"error = %q, want issuer mismatch",
			err,
		)
	}
}

func TestLoadAndValidateTransportCRLExpiredIsRetryableTrustState(
	t *testing.T,
) {
	now := time.Now().UTC()

	issuer, key := newSenderCRLContractIssuer(
		t,
		"FI Sender Retryable Expired CRL CA",
	)

	crl := newSenderCRLContractCRL(
		t,
		issuer,
		key,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
	)

	path := writeSenderCRLContractPEM(
		t,
		crl,
	)

	_, err := loadAndValidateTransportCRL(
		path,
		issuer,
		now,
	)
	if err == nil {
		t.Fatal(
			"expired transport CRL was unexpectedly accepted",
		)
	}

	if !errors.Is(
		err,
		errSenderTransportTrustUnavailable,
	) {
		t.Fatalf(
			"error = %v, want errSenderTransportTrustUnavailable",
			err,
		)
	}

	if !retryableSenderTransportState(err) {
		t.Fatalf(
			"retryableSenderTransportState(%v) = false, want true",
			err,
		)
	}
}

func TestRetryableSenderTransportState(
	t *testing.T,
) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "network transport",
			err: fmt.Errorf(
				"wrapped: %w",
				transportsender.ErrRetryableTransport,
			),
			want: true,
		},
		{
			name: "transport trust unavailable",
			err: fmt.Errorf(
				"wrapped: %w",
				errSenderTransportTrustUnavailable,
			),
			want: true,
		},
		{
			name: "unrelated failure",
			err:  errors.New("unrelated failure"),
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				got := retryableSenderTransportState(
					test.err,
				)

				if got != test.want {
					t.Fatalf(
						"retryableSenderTransportState() = %t, want %t",
						got,
						test.want,
					)
				}
			},
		)
	}
}

func TestQueuedTransportFailureRetryableTrustState(
	t *testing.T,
) {
	err := fmt.Errorf(
		"expired CRL: %w",
		errSenderTransportTrustUnavailable,
	)

	if !queuedTransportFailureRetryable(
		senderResult{},
		err,
	) {
		t.Fatal(
			"trust-unavailable transport should remain queued and retry",
		)
	}

	if queuedTransportFailureRetryable(
		senderResult{
			AcknowledgementOutcome: "Accepted",
		},
		err,
	) {
		t.Fatal(
			"acknowledged transport must not be retried",
		)
	}
}
func newSenderCRLContractIssuer(
	t *testing.T,
	commonName string,
) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatalf(
			"rsa.GenerateKey() error = %v",
			err,
		)
	}

	now := time.Now().UTC()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SubjectKeyId: []byte{
			0x11,
			0x22,
			0x33,
			0x44,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf(
			"x509.CreateCertificate() error = %v",
			err,
		)
	}

	certificate, err := x509.ParseCertificate(
		der,
	)
	if err != nil {
		t.Fatalf(
			"x509.ParseCertificate() error = %v",
			err,
		)
	}

	return certificate, key
}

func newSenderCRLContractCRL(
	t *testing.T,
	issuer *x509.Certificate,
	key *rsa.PrivateKey,
	thisUpdate time.Time,
	nextUpdate time.Time,
) *x509.RevocationList {
	t.Helper()

	der, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: thisUpdate,
			NextUpdate: nextUpdate,
		},
		issuer,
		key,
	)
	if err != nil {
		t.Fatalf(
			"x509.CreateRevocationList() error = %v",
			err,
		)
	}

	crl, err := x509.ParseRevocationList(
		der,
	)
	if err != nil {
		t.Fatalf(
			"x509.ParseRevocationList() error = %v",
			err,
		)
	}

	return crl
}

func writeSenderCRLContractPEM(
	t *testing.T,
	crl *x509.RevocationList,
) string {
	t.Helper()

	value := pem.EncodeToMemory(
		&pem.Block{
			Type:  "X509 CRL",
			Bytes: crl.Raw,
		},
	)
	if len(value) == 0 {
		t.Fatal(
			"pem.EncodeToMemory() returned no CRL data",
		)
	}

	path := filepath.Join(
		t.TempDir(),
		"fi-transport-ca.crl.pem",
	)

	if err := os.WriteFile(
		path,
		value,
		0600,
	); err != nil {
		t.Fatalf(
			"os.WriteFile() error = %v",
			err,
		)
	}

	return path
}
