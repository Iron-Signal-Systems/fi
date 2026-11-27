// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

type senderTrustFixture struct {
	alternateIssuer *x509.Certificate
	crl             *x509.RevocationList
	issuer          *x509.Certificate
	leaf            *x509.Certificate
	root            *x509.Certificate
}

func TestValidateReceiverConnectionAcceptsExactPinnedIssuer(t *testing.T) {
	fixture := newSenderTrustFixture(t)

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			fixture.leaf,
			fixture.issuer,
		},
		VerifiedChains: [][]*x509.Certificate{
			{
				fixture.leaf,
				fixture.issuer,
				fixture.root,
			},
		},
	}

	if err := validateReceiverConnection(
		state,
		fixture.issuer,
		fixture.crl,
		time.Now(),
	); err != nil {
		t.Fatalf("validateReceiverConnection() error = %v", err)
	}
}

func TestValidateReceiverConnectionRejectsEquivalentButUnpinnedIssuerCertificate(t *testing.T) {
	fixture := newSenderTrustFixture(t)

	// The alternate issuer has the same subject and public key as the pinned
	// issuer but different certificate bytes. The receiver leaf signature is
	// therefore valid under either certificate. FI must still require the exact
	// pinned issuer certificate selected by SHA-256.
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			fixture.leaf,
			fixture.alternateIssuer,
		},
		VerifiedChains: [][]*x509.Certificate{
			{
				fixture.leaf,
				fixture.alternateIssuer,
				fixture.root,
			},
		},
	}

	if err := validateReceiverConnection(
		state,
		fixture.issuer,
		fixture.crl,
		time.Now(),
	); err == nil {
		t.Fatal("validateReceiverConnection() error = nil, want exact pinned issuer rejection")
	}
}

func TestValidateSenderConfig(t *testing.T) {
	valid := senderConfig{
		ManifestPath:               `C:\FI\spool\batch-1.manifest.json`,
		ReceiverAddress:            "192.168.1.119:8443",
		ReceiverName:               "fi-receiver-a.iss.local",
		RootCertificateSHA256:      "root",
		SourceID:                   "iss-fs-01.iss.local",
		StageDir:                   `C:\FI\transport`,
		Timeout:                    30 * time.Second,
		TransportCRLPath:           `C:\FI\trust\fi-transport-ca.crl.pem`,
		TransportCertificateSHA256: "transport",
		TransportIssuerSHA256:      "issuer",
	}

	if err := validateSenderConfig(valid); err != nil {
		t.Fatalf("validateSenderConfig(valid) error = %v", err)
	}

	missingReceiver := valid
	missingReceiver.ReceiverAddress = ""
	if err := validateSenderConfig(missingReceiver); err == nil {
		t.Fatal("validateSenderConfig(missing receiver) error = nil")
	}

	invalidTimeout := valid
	invalidTimeout.Timeout = 0
	if err := validateSenderConfig(invalidTimeout); err == nil {
		t.Fatal("validateSenderConfig(zero timeout) error = nil")
	}

	invalidSource := valid
	invalidSource.SourceID = `..\iss-fs-01`
	if err := validateSenderConfig(invalidSource); err == nil {
		t.Fatal("validateSenderConfig(invalid source) error = nil")
	}
}

func TestValidateSourceTransportIdentity(t *testing.T) {
	certificate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "iss-fs-01.iss.local",
			OrganizationalUnit: []string{transporttrust.TransportOrganizationalUnit},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if err := validateSourceTransportIdentity(
		certificate,
		"iss-fs-01.iss.local",
	); err != nil {
		t.Fatalf("validateSourceTransportIdentity() error = %v", err)
	}

	wrongRole := *certificate
	wrongRole.Subject = certificate.Subject
	wrongRole.Subject.OrganizationalUnit = []string{"wrong"}
	if err := validateSourceTransportIdentity(
		&wrongRole,
		"iss-fs-01.iss.local",
	); err == nil {
		t.Fatal("validateSourceTransportIdentity(wrong role) error = nil")
	}
}

func newSenderTrustFixture(t *testing.T) senderTrustFixture {
	t.Helper()

	now := time.Now()
	rootKey := newRSAKey(t)
	issuerKey := newRSAKey(t)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "FI Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	root := createCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	issuerSubject := pkix.Name{CommonName: "FI Transport Issuing CA"}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               issuerSubject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuer := createCertificate(t, issuerTemplate, root, &issuerKey.PublicKey, rootKey)

	alternateIssuerTemplate := *issuerTemplate
	alternateIssuerTemplate.SerialNumber = big.NewInt(3)
	alternateIssuer := createCertificate(
		t,
		&alternateIssuerTemplate,
		root,
		&issuerKey.PublicKey,
		rootKey,
	)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			CommonName:         "fi-receiver-a.iss.local",
			OrganizationalUnit: []string{receiverTransportOrganizationalUnit},
		},
		DNSNames:    []string{"fi-receiver-a.iss.local"},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafKey := newRSAKey(t)
	leaf := createCertificate(
		t,
		leafTemplate,
		alternateIssuer,
		&leafKey.PublicKey,
		issuerKey,
	)

	crlDER, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(time.Hour),
		},
		issuer,
		issuerKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateRevocationList() error = %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("x509.ParseRevocationList() error = %v", err)
	}

	return senderTrustFixture{
		alternateIssuer: alternateIssuer,
		crl:             crl,
		issuer:          issuer,
		leaf:            leaf,
		root:            root,
	}
}

func createCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey any,
	parentKey any,
) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		parent,
		publicKey,
		parentKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return certificate
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}
