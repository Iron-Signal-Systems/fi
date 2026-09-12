// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateReceiverCertificate(t *testing.T) {
	root, issuer, leaf, _, _ := newReceiverIdentityMaterial(t)

	if err := ValidateReceiverCertificate(
		leaf,
		root,
		issuer,
		time.Now(),
	); err != nil {
		t.Fatalf("ValidateReceiverCertificate() error = %v", err)
	}
}

func TestValidateReceiverCertificateFailures(t *testing.T) {
	root, issuer, leaf, _, _ := newReceiverIdentityMaterial(t)
	otherRoot, otherIssuer, _, _, _ := newReceiverIdentityMaterial(t)
	at := time.Now()

	tests := []struct {
		name   string
		leaf   *x509.Certificate
		root   *x509.Certificate
		issuer *x509.Certificate
		at     time.Time
	}{
		{
			name:   "nil leaf",
			leaf:   nil,
			root:   root,
			issuer: issuer,
			at:     at,
		},
		{
			name:   "nil root",
			leaf:   leaf,
			root:   nil,
			issuer: issuer,
			at:     at,
		},
		{
			name:   "nil issuer",
			leaf:   leaf,
			root:   root,
			issuer: nil,
			at:     at,
		},
		{
			name:   "zero time",
			leaf:   leaf,
			root:   root,
			issuer: issuer,
			at:     time.Time{},
		},
		{
			name:   "wrong root",
			leaf:   leaf,
			root:   otherRoot,
			issuer: issuer,
			at:     at,
		},
		{
			name:   "wrong issuer",
			leaf:   leaf,
			root:   root,
			issuer: otherIssuer,
			at:     at,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReceiverCertificate(
				test.leaf,
				test.root,
				test.issuer,
				test.at,
			); err == nil {
				t.Fatal("ValidateReceiverCertificate() error = nil, want error")
			}
		})
	}
}

func TestValidateReceiverCertificateRejectsCA(t *testing.T) {
	root, issuer, _, issuerKey, _ := newReceiverIdentityMaterial(t)
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(44),
		Subject: pkix.Name{
			CommonName: "FI Invalid Receiver CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		issuer,
		&key.PublicKey,
		issuerKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	if err := ValidateReceiverCertificate(
		leaf,
		root,
		issuer,
		now,
	); err == nil {
		t.Fatal("ValidateReceiverCertificate() error = nil, want error")
	}
}

func TestValidateReceiverCertificateRejectsOrganizationalUnit(t *testing.T) {
	root, issuer, leaf, _, _ := newReceiverIdentityMaterial(t)
	at := time.Now()

	tests := []struct {
		name               string
		organizationalUnit []string
	}{
		{
			name:               "missing organizational unit",
			organizationalUnit: nil,
		},
		{
			name: "wrong organizational unit",
			organizationalUnit: []string{
				"FI Shipper Transport",
			},
		},
		{
			name: "multiple organizational units",
			organizationalUnit: []string{
				receiverTransportOrganizationalUnit,
				"FI Shipper Transport",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := *leaf
			candidate.Subject = leaf.Subject
			candidate.Subject.OrganizationalUnit = test.organizationalUnit

			if err := ValidateReceiverCertificate(
				&candidate,
				root,
				issuer,
				at,
			); err == nil {
				t.Fatal(
					"ValidateReceiverCertificate() error = nil, want error",
				)
			}
		})
	}
}

func TestValidateReceiverKeyPairFiles(t *testing.T) {
	root, issuer, leaf, _, leafKey := newReceiverIdentityMaterial(t)

	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "receiver-fullchain.pem")
	privateKeyPath := filepath.Join(directory, "receiver-key.pem")

	writeReceiverCertificateChain(
		t,
		certificatePath,
		leaf,
		issuer,
		root,
	)
	writeReceiverPrivateKey(t, privateKeyPath, leafKey)

	if err := ValidateReceiverKeyPair(
		certificatePath,
		privateKeyPath,
	); err != nil {
		t.Fatalf("ValidateReceiverKeyPair() error = %v", err)
	}

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(wrong) error = %v", err)
	}

	writeReceiverPrivateKey(t, privateKeyPath, wrongKey)

	if err := ValidateReceiverKeyPair(
		certificatePath,
		privateKeyPath,
	); err == nil {
		t.Fatal("ValidateReceiverKeyPair() error = nil, want mismatch error")
	}
}

func newReceiverIdentityMaterial(
	t *testing.T,
) (
	*x509.Certificate,
	*x509.Certificate,
	*x509.Certificate,
	*rsa.PrivateKey,
	*rsa.PrivateKey,
) {
	t.Helper()

	now := time.Now()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(root) error = %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "FI Receiver Test Root",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(root) error = %v", err)
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(root) error = %v", err)
	}

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(issuer) error = %v", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "FI Receiver Test Transport CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerDER, err := x509.CreateCertificate(
		rand.Reader,
		issuerTemplate,
		root,
		&issuerKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(issuer) error = %v", err)
	}

	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(issuer) error = %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(leaf) error = %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "fi-receiver-test.iss.local",
			OrganizationalUnit: []string{
				receiverTransportOrganizationalUnit,
			},
		},
		DNSNames:    []string{"fi-receiver-test.iss.local"},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		issuer,
		&leafKey.PublicKey,
		issuerKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(leaf) error = %v", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(leaf) error = %v", err)
	}

	return root, issuer, leaf, issuerKey, leafKey
}

func writeReceiverCertificateChain(
	t *testing.T,
	path string,
	certificates ...*x509.Certificate,
) {
	t.Helper()

	var value []byte

	for _, certificate := range certificates {
		value = append(value, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})...)
	}

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

func writeReceiverPrivateKey(
	t *testing.T,
	path string,
	key *rsa.PrivateKey,
) {
	t.Helper()

	value := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}
