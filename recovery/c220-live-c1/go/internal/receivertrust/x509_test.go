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

func TestLoadCertificate(t *testing.T) {
	certificatePEM, _ := newTestCertificateAndCRL(t)

	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, certificatePEM, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	certificate, err := LoadCertificate(path)
	if err != nil {
		t.Fatalf("LoadCertificate() error = %v", err)
	}

	if certificate.Subject.CommonName != "FI Test CA" {
		t.Fatalf(
			"certificate.Subject.CommonName = %q, want %q",
			certificate.Subject.CommonName,
			"FI Test CA",
		)
	}
}

func TestLoadCertificateChain(t *testing.T) {
	certificatePEM, _ := newTestCertificateAndCRL(t)

	value := make([]byte, 0, len(certificatePEM)*3)
	value = append(value, certificatePEM...)
	value = append(value, certificatePEM...)
	value = append(value, certificatePEM...)

	path := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	certificates, err := LoadCertificateChain(path)
	if err != nil {
		t.Fatalf("LoadCertificateChain() error = %v", err)
	}

	if len(certificates) != 3 {
		t.Fatalf(
			"len(certificates) = %d, want 3",
			len(certificates),
		)
	}

	for index, certificate := range certificates {
		if certificate.Subject.CommonName != "FI Test CA" {
			t.Fatalf(
				"certificates[%d].Subject.CommonName = %q, want %q",
				index,
				certificate.Subject.CommonName,
				"FI Test CA",
			)
		}
	}
}

func TestLoadCertificateChainMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pem")

	if _, err := LoadCertificateChain(path); err == nil {
		t.Fatal("LoadCertificateChain() error = nil, want error")
	}
}

func TestLoadCertificateChainUnexpectedData(t *testing.T) {
	certificatePEM, _ := newTestCertificateAndCRL(t)

	value := make([]byte, 0, len(certificatePEM)+len("unexpected"))
	value = append(value, certificatePEM...)
	value = append(value, []byte("unexpected")...)

	path := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := LoadCertificateChain(path); err == nil {
		t.Fatal("LoadCertificateChain() error = nil, want error")
	}
}

func TestLoadCertificateChainWrongPEMType(t *testing.T) {
	certificatePEM, crlPEM := newTestCertificateAndCRL(t)

	value := make([]byte, 0, len(certificatePEM)+len(crlPEM))
	value = append(value, certificatePEM...)
	value = append(value, crlPEM...)

	path := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := LoadCertificateChain(path); err == nil {
		t.Fatal("LoadCertificateChain() error = nil, want error")
	}
}

func TestLoadCertificateInvalidDER(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certificate.pem")

	value := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte{0x01, 0x02, 0x03},
	})

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := LoadCertificate(path); err == nil {
		t.Fatal("LoadCertificate() error = nil, want error")
	}
}

func TestLoadCertificateMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pem")

	if _, err := LoadCertificate(path); err == nil {
		t.Fatal("LoadCertificate() error = nil, want error")
	}
}

func TestLoadCertificateUnexpectedData(t *testing.T) {
	certificatePEM, _ := newTestCertificateAndCRL(t)

	value := append(
		append([]byte{}, certificatePEM...),
		[]byte("unexpected")...,
	)

	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := LoadCertificate(path); err == nil {
		t.Fatal("LoadCertificate() error = nil, want error")
	}
}

func TestLoadCertificateWrongPEMType(t *testing.T) {
	certificatePEM, _ := newTestCertificateAndCRL(t)

	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("pem.Decode() block = nil")
	}

	value := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: block.Bytes,
	})

	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := LoadCertificate(path); err == nil {
		t.Fatal("LoadCertificate() error = nil, want error")
	}
}

func TestLoadCRL(t *testing.T) {
	_, crlPEM := newTestCertificateAndCRL(t)

	path := filepath.Join(t.TempDir(), "crl.pem")
	if err := os.WriteFile(path, crlPEM, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	crl, err := LoadCRL(path)
	if err != nil {
		t.Fatalf("LoadCRL() error = %v", err)
	}

	if crl.Number == nil {
		t.Fatal("crl.Number = nil")
	}

	if crl.Number.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf(
			"crl.Number = %s, want 1",
			crl.Number.String(),
		)
	}
}

func TestLoadCRLInvalidDER(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crl.pem")

	value := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: []byte{0x01, 0x02, 0x03},
	})

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := LoadCRL(path); err == nil {
		t.Fatal("LoadCRL() error = nil, want error")
	}
}

func TestLoadCRLMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pem")

	if _, err := LoadCRL(path); err == nil {
		t.Fatal("LoadCRL() error = nil, want error")
	}
}

func TestLoadCRLUnexpectedData(t *testing.T) {
	_, crlPEM := newTestCertificateAndCRL(t)

	value := append(
		append([]byte{}, crlPEM...),
		[]byte("unexpected")...,
	)

	path := filepath.Join(t.TempDir(), "crl.pem")
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := LoadCRL(path); err == nil {
		t.Fatal("LoadCRL() error = nil, want error")
	}
}

func TestLoadCRLWrongPEMType(t *testing.T) {
	_, crlPEM := newTestCertificateAndCRL(t)

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("pem.Decode() block = nil")
	}

	value := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: block.Bytes,
	})

	path := filepath.Join(t.TempDir(), "crl.pem")
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := LoadCRL(path); err == nil {
		t.Fatal("LoadCRL() error = nil, want error")
	}
}

func newTestCertificateAndCRL(t *testing.T) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "FI Test CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	crlDER, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(time.Hour),
		},
		certificate,
		key,
	)
	if err != nil {
		t.Fatalf("x509.CreateRevocationList() error = %v", err)
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	return certificatePEM, crlPEM
}
