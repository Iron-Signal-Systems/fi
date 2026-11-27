// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportcrl"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ldapsecure"
)

const approval1MaximumCRLBytes = transportcrl.MaximumBytes

type approval1CRLMaterial struct {
	DER             []byte
	DestinationPath string
	NextUpdate      string
	SHA256          string
	Source          string
	ThisUpdate      string
}

type approval1LDAPCRLSource = transportcrl.LDAPSource

func acquireApproval1TransportCRL(
	session *ldapSession,
	trust approval1TransportTrustMaterial,
	at time.Time,
) (approval1CRLMaterial, error) {
	if at.IsZero() {
		return approval1CRLMaterial{}, errors.New(
			"current time is required for Approval 1 CRL validation",
		)
	}

	source := strings.TrimSpace(
		trust.CRLDistributionPoint,
	)
	if source == "" {
		return approval1CRLMaterial{}, errors.New(
			"transport CRL distribution point is required",
		)
	}

	parsed, err := url.Parse(source)
	if err != nil {
		return approval1CRLMaterial{}, fmt.Errorf(
			"parse transport CRL distribution point %q: %w",
			source,
			err,
		)
	}

	var raw []byte

	switch strings.ToLower(
		strings.TrimSpace(parsed.Scheme),
	) {
	case "ldap":
		if session == nil || session.handle == 0 {
			return approval1CRLMaterial{}, errors.New(
				"signed/sealed LDAP session is required for AD LDAP CRL retrieval",
			)
		}

		ldapSource, err :=
			parseApproval1LDAPCRLDistributionPoint(
				source,
			)
		if err != nil {
			return approval1CRLMaterial{}, err
		}

		raw, err = readApproval1LDAPCRL(
			session,
			ldapSource,
		)
		if err != nil {
			return approval1CRLMaterial{}, err
		}

	case "http", "https":
		raw, err = readApproval1HTTPCRL(
			source,
		)
		if err != nil {
			return approval1CRLMaterial{}, err
		}

	default:
		return approval1CRLMaterial{}, fmt.Errorf(
			"unsupported transport CRL distribution point scheme %q",
			parsed.Scheme,
		)
	}

	issuer, err := loadApproval1IssuerCertificate(
		trust.IssuerCertificateSHA256,
	)
	if err != nil {
		return approval1CRLMaterial{}, err
	}

	leaf, err := certstore.LoadLocalMachineCertificate(
		certstore.StoreMy,
		trust.TransportCertificateSHA256,
	)
	if err != nil {
		return approval1CRLMaterial{}, fmt.Errorf(
			"load exact transport certificate SHA256=%s for CRL validation: %w",
			trust.TransportCertificateSHA256,
			err,
		)
	}

	revocationList, err := validateApproval1TransportCRL(
		raw,
		issuer,
		leaf,
		at,
	)
	if err != nil {
		return approval1CRLMaterial{}, err
	}

	digest := sha256.Sum256(
		raw,
	)

	return approval1CRLMaterial{
		DER: append(
			[]byte(nil),
			raw...,
		),
		DestinationPath: trust.CRLDestinationPath,
		NextUpdate: revocationList.NextUpdate.UTC().Format(
			time.RFC3339,
		),
		SHA256: hex.EncodeToString(
			digest[:],
		),
		Source: source,
		ThisUpdate: revocationList.ThisUpdate.UTC().Format(
			time.RFC3339,
		),
	}, nil
}

func loadApproval1IssuerCertificate(
	certificateSHA256 string,
) (*x509.Certificate, error) {
	if !validSHA256Hex(
		certificateSHA256,
	) {
		return nil, errors.New(
			"transport issuer certificate SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	certificate, caErr :=
		certstore.LoadLocalMachineCertificate(
			certstore.StoreCA,
			certificateSHA256,
		)
	if caErr == nil {
		return certificate, nil
	}

	certificate, rootErr :=
		certstore.LoadLocalMachineCertificate(
			certstore.StoreRoot,
			certificateSHA256,
		)
	if rootErr == nil {
		return certificate, nil
	}

	return nil, errors.Join(
		fmt.Errorf(
			"load transport issuer SHA256=%s from LocalMachine\\CA: %w",
			certificateSHA256,
			caErr,
		),
		fmt.Errorf(
			"load transport issuer SHA256=%s from LocalMachine\\ROOT: %w",
			certificateSHA256,
			rootErr,
		),
	)
}

func parseApproval1LDAPCRLDistributionPoint(
	raw string,
) (approval1LDAPCRLSource, error) {
	return transportcrl.ParseLDAPDistributionPoint(
		raw,
	)
}

func readApproval1LDAPCRL(
	session *ldapSession,
	source approval1LDAPCRLSource,
) ([]byte, error) {
	if session == nil ||
		session.handle == 0 {
		return nil, errors.New(
			"LDAP session is unavailable for CRL retrieval",
		)
	}

	value, err := ldapsecure.ReadBaseBinary(
		session.handle,
		source.BaseDN,
		source.Filter,
		source.Attribute,
		int(
			approval1MaximumCRLBytes,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read AD CS CRL object %s: %w",
			source.BaseDN,
			err,
		)
	}

	return value, nil
}
func readApproval1HTTPCRL(
	source string,
) ([]byte, error) {
	return transportcrl.ReadHTTP(
		source,
	)
}

func validateApproval1TransportCRL(
	raw []byte,
	issuer *x509.Certificate,
	leaf *x509.Certificate,
	at time.Time,
) (*x509.RevocationList, error) {
	return transportcrl.ValidateDER(
		raw,
		issuer,
		leaf,
		at,
	)
}
