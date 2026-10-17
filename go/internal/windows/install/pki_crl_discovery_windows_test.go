// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectTransportCRLFileAtValid(t *testing.T) {
	now := time.Now().UTC()

	issuer, key := newInstallerCRLTestIssuer(
		t,
		"FI Installer CRL Test CA",
	)

	path := writeInstallerCRLTestFile(
		t,
		issuer,
		key,
		now.Add(-time.Minute),
		now.Add(time.Hour),
	)

	detail, err := inspectTransportCRLFileAt(
		path,
		issuer,
		now,
	)
	if err != nil {
		t.Fatalf(
			"inspectTransportCRLFileAt() error = %v",
			err,
		)
	}

	if !strings.Contains(detail, "this_update=") {
		t.Fatalf(
			"detail = %q, want this_update",
			detail,
		)
	}

	if !strings.Contains(detail, "next_update=") {
		t.Fatalf(
			"detail = %q, want next_update",
			detail,
		)
	}
}

func TestInspectTransportCRLFileAtExpired(t *testing.T) {
	now := time.Now().UTC()

	issuer, key := newInstallerCRLTestIssuer(
		t,
		"FI Installer Expired CRL Test CA",
	)

	path := writeInstallerCRLTestFile(
		t,
		issuer,
		key,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
	)

	_, err := inspectTransportCRLFileAt(
		path,
		issuer,
		now,
	)
	if err == nil {
		t.Fatal(
			"inspectTransportCRLFileAt() error = nil, want expired CRL rejection",
		)
	}

	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf(
			"inspectTransportCRLFileAt() error = %q, want expired",
			err,
		)
	}
}

func TestInspectTransportCRLFileAtFuture(t *testing.T) {
	now := time.Now().UTC()

	issuer, key := newInstallerCRLTestIssuer(
		t,
		"FI Installer Future CRL Test CA",
	)

	path := writeInstallerCRLTestFile(
		t,
		issuer,
		key,
		now.Add(time.Hour),
		now.Add(2*time.Hour),
	)

	_, err := inspectTransportCRLFileAt(
		path,
		issuer,
		now,
	)
	if err == nil {
		t.Fatal(
			"inspectTransportCRLFileAt() error = nil, want future CRL rejection",
		)
	}

	if !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf(
			"inspectTransportCRLFileAt() error = %q, want not yet valid",
			err,
		)
	}
}

func TestInspectTransportCRLFileAtWrongIssuer(t *testing.T) {
	now := time.Now().UTC()

	expectedIssuer, _ := newInstallerCRLTestIssuer(
		t,
		"FI Installer Expected CRL Test CA",
	)

	actualIssuer, actualKey := newInstallerCRLTestIssuer(
		t,
		"FI Installer Other CRL Test CA",
	)

	path := writeInstallerCRLTestFile(
		t,
		actualIssuer,
		actualKey,
		now.Add(-time.Minute),
		now.Add(time.Hour),
	)

	_, err := inspectTransportCRLFileAt(
		path,
		expectedIssuer,
		now,
	)
	if err == nil {
		t.Fatal(
			"inspectTransportCRLFileAt() error = nil, want issuer rejection",
		)
	}

	if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf(
			"inspectTransportCRLFileAt() error = %q, want issuer rejection",
			err,
		)
	}
}

func TestInspectTransportCRLFileAtMalformed(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"malformed.crl.pem",
	)

	if err := os.WriteFile(
		path,
		[]byte("not a CRL"),
		0600,
	); err != nil {
		t.Fatalf(
			"os.WriteFile() error = %v",
			err,
		)
	}

	_, err := inspectTransportCRLFileAt(
		path,
		nil,
		time.Now(),
	)
	if err == nil {
		t.Fatal(
			"inspectTransportCRLFileAt() error = nil, want malformed CRL rejection",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not contain PEM data",
	) {
		t.Fatalf(
			"inspectTransportCRLFileAt() error = %q, want PEM parse rejection",
			err,
		)
	}
}

func TestRecordTransportCRLCheckAtExpiredMarksReportFailure(
	t *testing.T,
) {
	now := time.Now().UTC()

	issuer, key := newInstallerCRLTestIssuer(
		t,
		"FI Installer Discovery Failure CRL Test CA",
	)

	path := writeInstallerCRLTestFile(
		t,
		issuer,
		key,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
	)

	var report Report

	recordTransportCRLCheckAt(
		&report,
		path,
		issuer,
		now,
	)

	if !report.HasFailures() {
		t.Fatal(
			"Report.HasFailures() = false, want true for expired transport CRL",
		)
	}

	var transportCRLChecks []Check

	for _, check := range report.Checks {
		if check.Name == "transport CRL" {
			transportCRLChecks = append(
				transportCRLChecks,
				check,
			)
		}
	}

	if len(transportCRLChecks) != 1 {
		t.Fatalf(
			"transport CRL check count = %d, want 1",
			len(transportCRLChecks),
		)
	}

	if transportCRLChecks[0].Status != checkFail {
		t.Fatalf(
			"transport CRL status = %q, want %q",
			transportCRLChecks[0].Status,
			checkFail,
		)
	}

	if !strings.Contains(
		transportCRLChecks[0].Detail,
		"expired",
	) {
		t.Fatalf(
			"transport CRL detail = %q, want expired",
			transportCRLChecks[0].Detail,
		)
	}

	if len(report.PKI) != 1 {
		t.Fatalf(
			"PKI state count = %d, want 1",
			len(report.PKI),
		)
	}

	if report.PKI[0].State != checkFail {
		t.Fatalf(
			"PKI transport CRL state = %q, want %q",
			report.PKI[0].State,
			checkFail,
		)
	}

	t.Logf(
		"expired CRL correctly produced discovery failure: %s",
		transportCRLChecks[0].Detail,
	)
}
func newInstallerCRLTestIssuer(
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
			0x01,
			0x02,
			0x03,
			0x04,
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

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf(
			"x509.ParseCertificate() error = %v",
			err,
		)
	}

	return certificate, key
}

func writeInstallerCRLTestFile(
	t *testing.T,
	issuer *x509.Certificate,
	key *rsa.PrivateKey,
	thisUpdate time.Time,
	nextUpdate time.Time,
) string {
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

	value := pem.EncodeToMemory(
		&pem.Block{
			Type:  "X509 CRL",
			Bytes: der,
		},
	)
	if len(value) == 0 {
		t.Fatal(
			"pem.EncodeToMemory() returned no CRL data",
		)
	}

	path := filepath.Join(
		t.TempDir(),
		"transport.crl.pem",
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
