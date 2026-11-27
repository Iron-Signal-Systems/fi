// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package crlrefresh

import (
	"bytes"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportcrl"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/domaincontroller"
)

func TestRefreshOnceHTTPActivates(
	t *testing.T,
) {
	now := time.Date(
		2026,
		time.October,
		4,
		20,
		0,
		0,
		0,
		time.UTC,
	)

	const source = "https://ca.iss.local/CertEnroll/transport.crl"

	const activePath = `C:\ProgramData\FI\pki\trust\transport.crl.pem`

	current := &x509.RevocationList{
		Raw:        []byte("current-der"),
		Number:     big.NewInt(40),
		ThisUpdate: now.Add(-8 * time.Hour),
		NextUpdate: now.Add(8 * time.Hour),
	}

	candidate := &x509.RevocationList{
		Raw:        []byte("candidate-der"),
		Number:     big.NewInt(41),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(48 * time.Hour),
	}

	leaf := &x509.Certificate{
		CRLDistributionPoints: []string{
			source,
		},
	}

	issuer := &x509.Certificate{}

	dependencies :=
		defaultRefreshDependencies()

	dependencies.loadTrust =
		func(
			path string,
		) (config.TransportTrustConfig, error) {
			if path != "trust.conf" {
				t.Fatalf(
					"trust path=%q",
					path,
				)
			}

			return config.TransportTrustConfig{
				TransportCRLPath: activePath,
			}, nil
		}

	dependencies.loadCertificates =
		func(
			config.TransportTrustConfig,
		) (refreshCertificates, error) {
			return refreshCertificates{
				issuer: issuer,
				leaf:   leaf,
			}, nil
		}

	dependencies.readHTTP =
		func(
			got string,
		) ([]byte, error) {
			if got != source {
				t.Fatalf(
					"HTTP source=%q want=%q",
					got,
					source,
				)
			}

			return append(
				[]byte(nil),
				candidate.Raw...,
			), nil
		}

	dependencies.validateDER =
		func(
			raw []byte,
			gotIssuer *x509.Certificate,
			gotLeaf *x509.Certificate,
			at time.Time,
		) (*x509.RevocationList, error) {
			if !bytes.Equal(
				raw,
				candidate.Raw,
			) {
				t.Fatalf(
					"candidate DER=%q",
					raw,
				)
			}

			if gotIssuer != issuer {
				t.Fatal(
					"issuer dependency changed",
				)
			}

			if gotLeaf != leaf {
				t.Fatal(
					"leaf dependency changed",
				)
			}

			if !at.Equal(
				now,
			) {
				t.Fatalf(
					"validation time=%s",
					at,
				)
			}

			return candidate, nil
		}

	dependencies.loadActive =
		func(
			path string,
		) (*x509.RevocationList, error) {
			if path != activePath {
				t.Fatalf(
					"active path=%q",
					path,
				)
			}

			return current, nil
		}

	dependencies.activate =
		func(
			path string,
			raw []byte,
			gotIssuer *x509.Certificate,
			gotLeaf *x509.Certificate,
			at time.Time,
			transactionID string,
		) (transportcrl.ActivationResult, error) {
			if path != activePath {
				t.Fatalf(
					"activation path=%q",
					path,
				)
			}

			if !bytes.Equal(
				raw,
				candidate.Raw,
			) {
				t.Fatalf(
					"activation DER=%q",
					raw,
				)
			}

			if gotIssuer != issuer ||
				gotLeaf != leaf {
				t.Fatal(
					"activation certificate identity changed",
				)
			}

			if !at.Equal(
				now,
			) {
				t.Fatalf(
					"activation time=%s",
					at,
				)
			}

			if transactionID !=
				"refresh-http-1" {
				t.Fatalf(
					"transaction=%q",
					transactionID,
				)
			}

			return transportcrl.ActivationResult{
				Activated:  true,
				BackupPath: activePath + ".fi-backup-refresh-http-1",
				Reason:     "candidate progressed",
			}, nil
		}

	result, err :=
		refreshOnceWithDependencies(
			Options{
				At:              now,
				TransactionID:   "refresh-http-1",
				TrustConfigPath: "trust.conf",
			},
			dependencies,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Activated {
		t.Fatal(
			"HTTP candidate was not activated",
		)
	}

	if result.Source != source {
		t.Fatalf(
			"source=%q want=%q",
			result.Source,
			source,
		)
	}

	if result.PreviousCRLNumber != "40" {
		t.Fatalf(
			"previous CRL number=%q",
			result.PreviousCRLNumber,
		)
	}

	if result.CandidateCRLNumber != "41" {
		t.Fatalf(
			"candidate CRL number=%q",
			result.CandidateCRLNumber,
		)
	}

	if result.BackupPath == "" {
		t.Fatal(
			"backup path is empty",
		)
	}
}

func TestRefreshOnceLDAPUsesWritableSignedSealedBoundary(
	t *testing.T,
) {
	now := time.Date(
		2026,
		time.October,
		4,
		20,
		0,
		0,
		0,
		time.UTC,
	)

	const source = "ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint"

	current := &x509.RevocationList{
		Raw:        []byte("same-der"),
		Number:     big.NewInt(50),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
	}

	candidate := &x509.RevocationList{
		Raw:        []byte("same-der"),
		Number:     big.NewInt(50),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
	}

	leaf := &x509.Certificate{
		CRLDistributionPoints: []string{
			source,
		},
	}

	issuer := &x509.Certificate{}

	dependencies :=
		defaultRefreshDependencies()

	dependencies.loadTrust =
		func(
			string,
		) (config.TransportTrustConfig, error) {
			return config.TransportTrustConfig{
				TransportCRLPath: `C:\FI\transport.crl.pem`,
			}, nil
		}

	dependencies.loadCertificates =
		func(
			config.TransportTrustConfig,
		) (refreshCertificates, error) {
			return refreshCertificates{
				issuer: issuer,
				leaf:   leaf,
			}, nil
		}

	discovered := false
	opened := false
	read := false
	closed := false

	dependencies.discoverWritable =
		func(
			domain string,
		) (domaincontroller.Info, error) {
			if domain != "iss.local" {
				t.Fatalf(
					"domain=%q",
					domain,
				)
			}

			discovered = true

			return domaincontroller.Info{
				DomainController: "DC16.iss.local",
			}, nil
		}

	dependencies.openLDAP =
		func(
			host string,
		) (uintptr, error) {
			if host != "DC16.iss.local" {
				t.Fatalf(
					"LDAP host=%q",
					host,
				)
			}

			opened = true

			return 77, nil
		}

	dependencies.readLDAP =
		func(
			handle uintptr,
			base string,
			filter string,
			attribute string,
			maxBytes int,
		) ([]byte, error) {
			if handle != 77 {
				t.Fatalf(
					"LDAP handle=%d",
					handle,
				)
			}

			if !strings.Contains(
				base,
				"CN=ISS-Root-CA",
			) {
				t.Fatalf(
					"LDAP base=%q",
					base,
				)
			}

			if filter !=
				"(objectClass=cRLDistributionPoint)" {
				t.Fatalf(
					"LDAP filter=%q",
					filter,
				)
			}

			if attribute !=
				"certificateRevocationList" {
				t.Fatalf(
					"LDAP attribute=%q",
					attribute,
				)
			}

			if maxBytes !=
				int(
					transportcrl.MaximumBytes,
				) {
				t.Fatalf(
					"LDAP maxBytes=%d",
					maxBytes,
				)
			}

			read = true

			return append(
				[]byte(nil),
				candidate.Raw...,
			), nil
		}

	dependencies.closeLDAP =
		func(
			handle uintptr,
		) error {
			if handle != 77 {
				t.Fatalf(
					"close handle=%d",
					handle,
				)
			}

			closed = true

			return nil
		}

	dependencies.validateDER =
		func(
			[]byte,
			*x509.Certificate,
			*x509.Certificate,
			time.Time,
		) (*x509.RevocationList, error) {
			return candidate, nil
		}

	dependencies.loadActive =
		func(
			string,
		) (*x509.RevocationList, error) {
			return current, nil
		}

	dependencies.activate =
		func(
			string,
			[]byte,
			*x509.Certificate,
			*x509.Certificate,
			time.Time,
			string,
		) (transportcrl.ActivationResult, error) {
			return transportcrl.ActivationResult{
				Activated: false,
				Reason:    "candidate transport CRL matches current signed DER",
			}, nil
		}

	result, err :=
		refreshOnceWithDependencies(
			Options{
				At:              now,
				DomainDNS:       "iss.local",
				TransactionID:   "refresh-ldap-1",
				TrustConfigPath: "trust.conf",
			},
			dependencies,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !discovered ||
		!opened ||
		!read ||
		!closed {
		t.Fatalf(
			"LDAP boundary discovered=%t opened=%t read=%t closed=%t",
			discovered,
			opened,
			read,
			closed,
		)
	}

	if result.Activated {
		t.Fatal(
			"identical LDAP candidate unexpectedly activated",
		)
	}
}

func TestRefreshOnceLDAPRequiresDomainDNS(
	t *testing.T,
) {
	dependencies :=
		defaultRefreshDependencies()

	dependencies.loadTrust =
		func(
			string,
		) (config.TransportTrustConfig, error) {
			return config.TransportTrustConfig{
				TransportCRLPath: `C:\FI\transport.crl.pem`,
			}, nil
		}

	dependencies.loadCertificates =
		func(
			config.TransportTrustConfig,
		) (refreshCertificates, error) {
			return refreshCertificates{
				issuer: &x509.Certificate{},
				leaf: &x509.Certificate{
					CRLDistributionPoints: []string{
						"ldap:///CN=CA,DC=iss,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint",
					},
				},
			}, nil
		}

	_, err :=
		refreshOnceWithDependencies(
			Options{
				At:              time.Now().UTC(),
				TransactionID:   "missing-domain",
				TrustConfigPath: "trust.conf",
			},
			dependencies,
		)

	if err == nil {
		t.Fatal(
			"LDAP refresh without domain DNS was unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"domain DNS name is required",
	) {
		t.Fatalf(
			"error=%q",
			err,
		)
	}
}
