// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
)

func TestApproval1TransportTrustMaterialFromChain(
	t *testing.T,
) {
	t.Parallel()

	leaf := &x509.Certificate{
		Raw: []byte("leaf-certificate-der"),
		CRLDistributionPoints: []string{
			"ldap:///CN=FI-Transport-CA",
			"http://ca.iss.local/CertEnroll/FI-Transport-CA.crl",
		},
	}

	issuer := &x509.Certificate{
		Raw: []byte("issuer-certificate-der"),
	}

	root := &x509.Certificate{
		Raw: []byte("root-certificate-der"),
	}

	leafSHA256 := testCertificateRawSHA256(
		leaf,
	)

	material, err :=
		approval1TransportTrustMaterialFromChain(
			leafSHA256,
			[]*x509.Certificate{
				leaf,
				issuer,
				root,
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if material.TransportCertificateSHA256 !=
		leafSHA256 {
		t.Fatalf(
			"transport SHA256=%s want=%s",
			material.TransportCertificateSHA256,
			leafSHA256,
		)
	}

	if material.IssuerCertificateSHA256 !=
		testCertificateRawSHA256(issuer) {
		t.Fatalf(
			"issuer SHA256=%s want=%s",
			material.IssuerCertificateSHA256,
			testCertificateRawSHA256(issuer),
		)
	}

	if material.RootCertificateSHA256 !=
		testCertificateRawSHA256(root) {
		t.Fatalf(
			"root SHA256=%s want=%s",
			material.RootCertificateSHA256,
			testCertificateRawSHA256(root),
		)
	}

	if material.CRLDistributionPoint !=
		"http://ca.iss.local/CertEnroll/FI-Transport-CA.crl" {
		t.Fatalf(
			"CRL distribution point=%q",
			material.CRLDistributionPoint,
		)
	}

	if material.CRLDestinationPath !=
		approval1TransportCRLDestination {
		t.Fatalf(
			"CRL destination=%q want=%q",
			material.CRLDestinationPath,
			approval1TransportCRLDestination,
		)
	}
}

func TestApproval1TransportTrustMaterialAllowsRootAsDirectIssuer(
	t *testing.T,
) {
	t.Parallel()

	leaf := &x509.Certificate{
		Raw: []byte("leaf-certificate-der"),
		CRLDistributionPoints: []string{
			"https://ca.iss.local/CertEnroll/ISS-Root-CA.crl",
		},
	}

	root := &x509.Certificate{
		Raw: []byte("root-certificate-der"),
	}

	material, err :=
		approval1TransportTrustMaterialFromChain(
			testCertificateRawSHA256(leaf),
			[]*x509.Certificate{
				leaf,
				root,
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if material.IssuerCertificateSHA256 !=
		material.RootCertificateSHA256 {
		t.Fatalf(
			"direct root issuer hashes differ: issuer=%s root=%s",
			material.IssuerCertificateSHA256,
			material.RootCertificateSHA256,
		)
	}
}

func TestApproval1TransportTrustMaterialRejectsLeafHashMismatch(
	t *testing.T,
) {
	t.Parallel()

	leaf := &x509.Certificate{
		Raw: []byte("leaf-certificate-der"),
		CRLDistributionPoints: []string{
			"https://ca.iss.local/CertEnroll/FI-Transport-CA.crl",
		},
	}

	root := &x509.Certificate{
		Raw: []byte("root-certificate-der"),
	}

	_, err :=
		approval1TransportTrustMaterialFromChain(
			strings.Repeat("A", 64),
			[]*x509.Certificate{
				leaf,
				root,
			},
		)

	if err == nil {
		t.Fatal(
			"leaf SHA-256 mismatch was unexpectedly accepted",
		)
	}
}

func TestSelectApproval1TransportCRLDistributionPointRejectsAmbiguousWebSources(
	t *testing.T,
) {
	t.Parallel()

	_, err :=
		selectApproval1TransportCRLDistributionPoint(
			[]string{
				"http://ca1.iss.local/one.crl",
				"https://ca2.iss.local/two.crl",
			},
		)

	if err == nil {
		t.Fatal(
			"ambiguous HTTP/HTTPS CRL sources were unexpectedly accepted",
		)
	}
}

func TestSelectApproval1TransportCRLDistributionPointRejectsUnsupportedSources(
	t *testing.T,
) {
	t.Parallel()

	_, err :=
		selectApproval1TransportCRLDistributionPoint(
			[]string{
				"ldap:///CN=FI-Transport-CA",
				`file:///C:/PKI/FI-Transport-CA.crl`,
			},
		)

	if err == nil {
		t.Fatal(
			"unsupported CRL sources were unexpectedly accepted",
		)
	}
}

func TestSelectApproval1TransportCRLDistributionPointDeduplicatesIdenticalSource(
	t *testing.T,
) {
	t.Parallel()

	got, err :=
		selectApproval1TransportCRLDistributionPoint(
			[]string{
				"https://ca.iss.local/CertEnroll/FI-Transport-CA.crl",
				"https://ca.iss.local/CertEnroll/FI-Transport-CA.crl",
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if got !=
		"https://ca.iss.local/CertEnroll/FI-Transport-CA.crl" {
		t.Fatalf(
			"CRL distribution point=%q",
			got,
		)
	}
}

func testCertificateRawSHA256(
	certificate *x509.Certificate,
) string {
	digest := sha256.Sum256(
		certificate.Raw,
	)

	return hex.EncodeToString(
		digest[:],
	)
}
