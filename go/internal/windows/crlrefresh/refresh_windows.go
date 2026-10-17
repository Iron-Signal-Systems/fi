// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package crlrefresh

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportcrl"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/domaincontroller"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ldapsecure"
)

const DefaultTrustConfigPath = `C:\ProgramData\FI\config\fi-transport-trust.conf`

type Options struct {
	At              time.Time
	DomainDNS       string
	TransactionID   string
	TrustConfigPath string
}

type Result struct {
	Activated          bool
	BackupPath         string
	CandidateCRLNumber string
	CandidateSHA256    string
	FailedPath         string
	NextUpdate         string
	PreviousCRLNumber  string
	PreviousSHA256     string
	Reason             string
	Source             string
	ThisUpdate         string
}

type refreshCertificates struct {
	issuer *x509.Certificate
	leaf   *x509.Certificate
	root   *x509.Certificate
}

type preparedRefresh struct {
	candidate    *x509.RevocationList
	candidateDER []byte
	certificates refreshCertificates
	source       string
	trust        config.TransportTrustConfig
}

type refreshDependencies struct {
	activate func(
		string,
		[]byte,
		*x509.Certificate,
		*x509.Certificate,
		time.Time,
		string,
	) (transportcrl.ActivationResult, error)

	closeLDAP func(uintptr) error

	discoverWritable func(
		string,
	) (domaincontroller.Info, error)

	loadActive func(
		string,
	) (*x509.RevocationList, error)

	loadCertificates func(
		config.TransportTrustConfig,
	) (refreshCertificates, error)

	loadTrust func(
		string,
	) (config.TransportTrustConfig, error)

	openLDAP func(
		string,
	) (uintptr, error)

	parseLDAP func(
		string,
	) (transportcrl.LDAPSource, error)

	readHTTP func(
		string,
	) ([]byte, error)

	readLDAP func(
		uintptr,
		string,
		string,
		string,
		int,
	) ([]byte, error)

	selectSource func(
		[]string,
	) (string, error)

	validateDER func(
		[]byte,
		*x509.Certificate,
		*x509.Certificate,
		time.Time,
	) (*x509.RevocationList, error)
}

func RefreshOnce(
	options Options,
) (Result, error) {
	return refreshOnceWithDependencies(
		options,
		defaultRefreshDependencies(),
	)
}

func acquireCandidate(
	source string,
	domainDNS string,
	dependencies refreshDependencies,
) ([]byte, error) {
	parsed, err := url.Parse(
		strings.TrimSpace(
			source,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse transport CRL source %q: %w",
			source,
			err,
		)
	}

	switch strings.ToLower(
		strings.TrimSpace(
			parsed.Scheme,
		),
	) {
	case "http", "https":
		value, err := dependencies.readHTTP(
			source,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"acquire transport CRL from %s: %w",
				parsed.Scheme,
				err,
			)
		}

		return value, nil

	case "ldap":
		domainDNS = strings.TrimSpace(
			domainDNS,
		)

		if domainDNS == "" {
			return nil, errors.New(
				"domain DNS name is required for AD LDAP CRL acquisition",
			)
		}

		ldapSource, err :=
			dependencies.parseLDAP(
				source,
			)
		if err != nil {
			return nil, fmt.Errorf(
				"parse AD LDAP CRL source: %w",
				err,
			)
		}

		controller, err :=
			dependencies.discoverWritable(
				domainDNS,
			)
		if err != nil {
			return nil, fmt.Errorf(
				"discover writable domain controller for CRL refresh: %w",
				err,
			)
		}

		if strings.TrimSpace(
			controller.DomainController,
		) == "" {
			return nil, errors.New(
				"writable domain controller discovery returned an empty host",
			)
		}

		handle, err :=
			dependencies.openLDAP(
				controller.DomainController,
			)
		if err != nil {
			return nil, fmt.Errorf(
				"open signed/sealed LDAP session to %s: %w",
				controller.DomainController,
				err,
			)
		}

		value, readErr :=
			dependencies.readLDAP(
				handle,
				ldapSource.BaseDN,
				ldapSource.Filter,
				ldapSource.Attribute,
				int(
					transportcrl.MaximumBytes,
				),
			)

		closeErr :=
			dependencies.closeLDAP(
				handle,
			)

		if readErr != nil {
			if closeErr != nil {
				return nil, errors.Join(
					fmt.Errorf(
						"read AD CS CRL from %s: %w",
						controller.DomainController,
						readErr,
					),
					fmt.Errorf(
						"close signed/sealed LDAP session: %w",
						closeErr,
					),
				)
			}

			return nil, fmt.Errorf(
				"read AD CS CRL from %s: %w",
				controller.DomainController,
				readErr,
			)
		}

		if closeErr != nil {
			return nil, fmt.Errorf(
				"close signed/sealed LDAP session: %w",
				closeErr,
			)
		}

		return value, nil

	default:
		return nil, fmt.Errorf(
			"unsupported transport CRL source scheme %q",
			parsed.Scheme,
		)
	}
}

func crlNumber(
	value *x509.RevocationList,
) string {
	if value == nil ||
		value.Number == nil {
		return ""
	}

	return value.Number.String()
}

func defaultRefreshDependencies() refreshDependencies {
	return refreshDependencies{
		activate:         transportcrl.ActivateCandidate,
		closeLDAP:        ldapsecure.Close,
		discoverWritable: domaincontroller.DiscoverWritable,
		loadActive:       receivertrust.LoadCRL,
		loadCertificates: loadRefreshCertificates,
		loadTrust:        config.LoadTransportTrust,
		openLDAP:         ldapsecure.Open,
		parseLDAP:        transportcrl.ParseLDAPDistributionPoint,
		readHTTP:         transportcrl.ReadHTTP,
		readLDAP:         ldapsecure.ReadBaseBinary,
		selectSource:     transportcrl.SelectDistributionPoint,
		validateDER:      transportcrl.ValidateDER,
	}
}

func loadRefreshCertificates(
	trust config.TransportTrustConfig,
) (refreshCertificates, error) {
	leaf, err :=
		certstore.LoadLocalMachineCertificate(
			certstore.StoreMy,
			trust.TransportCertificateSHA256,
		)
	if err != nil {
		return refreshCertificates{}, fmt.Errorf(
			"load pinned transport certificate SHA256=%s from LocalMachine\\MY: %w",
			trust.TransportCertificateSHA256,
			err,
		)
	}

	issuer, err :=
		loadRefreshIssuer(
			trust.TransportIssuerSHA256,
		)
	if err != nil {
		return refreshCertificates{}, err
	}

	root, err :=
		certstore.LoadLocalMachineCertificate(
			certstore.StoreRoot,
			trust.RootCertificateSHA256,
		)
	if err != nil {
		return refreshCertificates{}, fmt.Errorf(
			"load pinned FI root certificate SHA256=%s from LocalMachine\\ROOT: %w",
			trust.RootCertificateSHA256,
			err,
		)
	}

	if !issuer.IsCA {
		return refreshCertificates{}, errors.New(
			"pinned transport issuer certificate is not a CA certificate",
		)
	}

	if !root.IsCA {
		return refreshCertificates{}, errors.New(
			"pinned FI root certificate is not a CA certificate",
		)
	}

	if !bytes.Equal(
		leaf.RawIssuer,
		issuer.RawSubject,
	) {
		return refreshCertificates{}, errors.New(
			"pinned transport certificate issuer does not match pinned transport issuer",
		)
	}

	if err := leaf.CheckSignatureFrom(
		issuer,
	); err != nil {
		return refreshCertificates{}, fmt.Errorf(
			"validate pinned transport certificate signature: %w",
			err,
		)
	}

	if bytes.Equal(
		issuer.Raw,
		root.Raw,
	) {
		if err := root.CheckSignatureFrom(
			root,
		); err != nil {
			return refreshCertificates{}, fmt.Errorf(
				"validate pinned FI root self-signature: %w",
				err,
			)
		}
	} else {
		if !bytes.Equal(
			issuer.RawIssuer,
			root.RawSubject,
		) {
			return refreshCertificates{}, errors.New(
				"pinned transport issuer does not chain to pinned FI root",
			)
		}

		if err := issuer.CheckSignatureFrom(
			root,
		); err != nil {
			return refreshCertificates{}, fmt.Errorf(
				"validate pinned transport issuer signature: %w",
				err,
			)
		}
	}

	return refreshCertificates{
		issuer: issuer,
		leaf:   leaf,
		root:   root,
	}, nil
}

func loadRefreshIssuer(
	certificateSHA256 string,
) (*x509.Certificate, error) {
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
			"load pinned transport issuer SHA256=%s from LocalMachine\\CA: %w",
			certificateSHA256,
			caErr,
		),
		fmt.Errorf(
			"load pinned transport issuer SHA256=%s from LocalMachine\\ROOT: %w",
			certificateSHA256,
			rootErr,
		),
	)
}

func prepareRefresh(
	options Options,
	dependencies refreshDependencies,
) (preparedRefresh, error) {
	if strings.TrimSpace(
		options.TrustConfigPath,
	) == "" {
		return preparedRefresh{}, errors.New(
			"transport trust config path is required",
		)
	}

	if options.At.IsZero() {
		return preparedRefresh{}, errors.New(
			"CRL refresh evaluation time is required",
		)
	}

	trust, err :=
		dependencies.loadTrust(
			options.TrustConfigPath,
		)
	if err != nil {
		return preparedRefresh{}, fmt.Errorf(
			"load FI transport trust authority: %w",
			err,
		)
	}

	certificates, err :=
		dependencies.loadCertificates(
			trust,
		)
	if err != nil {
		return preparedRefresh{}, fmt.Errorf(
			"resolve pinned FI transport certificates: %w",
			err,
		)
	}

	source, err :=
		dependencies.selectSource(
			certificates.leaf.CRLDistributionPoints,
		)
	if err != nil {
		return preparedRefresh{}, fmt.Errorf(
			"derive transport CRL source from pinned certificate: %w",
			err,
		)
	}

	candidateDER, err :=
		acquireCandidate(
			source,
			options.DomainDNS,
			dependencies,
		)
	if err != nil {
		return preparedRefresh{}, err
	}

	candidate, err :=
		dependencies.validateDER(
			candidateDER,
			certificates.issuer,
			certificates.leaf,
			options.At,
		)
	if err != nil {
		return preparedRefresh{}, fmt.Errorf(
			"validate retrieved transport CRL candidate: %w",
			err,
		)
	}

	return preparedRefresh{
		candidate: candidate,
		candidateDER: append(
			[]byte(nil),
			candidateDER...,
		),
		certificates: certificates,
		source:       source,
		trust:        trust,
	}, nil
}

func refreshOnceWithDependencies(
	options Options,
	dependencies refreshDependencies,
) (Result, error) {
	if strings.TrimSpace(
		options.TransactionID,
	) == "" {
		return Result{}, errors.New(
			"CRL refresh transaction ID is required",
		)
	}

	prepared, err :=
		prepareRefresh(
			options,
			dependencies,
		)
	if err != nil {
		return Result{}, err
	}

	current, err :=
		dependencies.loadActive(
			prepared.trust.TransportCRLPath,
		)
	if err != nil {
		return Result{}, fmt.Errorf(
			"load current active transport CRL: %w",
			err,
		)
	}

	currentDigest :=
		sha256.Sum256(
			current.Raw,
		)

	candidateDigest :=
		sha256.Sum256(
			prepared.candidate.Raw,
		)

	result := Result{
		CandidateCRLNumber: crlNumber(
			prepared.candidate,
		),
		CandidateSHA256: hex.EncodeToString(
			candidateDigest[:],
		),
		NextUpdate: prepared.candidate.NextUpdate.UTC().Format(
			time.RFC3339,
		),
		PreviousCRLNumber: crlNumber(
			current,
		),
		PreviousSHA256: hex.EncodeToString(
			currentDigest[:],
		),
		Source: prepared.source,
		ThisUpdate: prepared.candidate.ThisUpdate.UTC().Format(
			time.RFC3339,
		),
	}

	activation, err :=
		dependencies.activate(
			prepared.trust.TransportCRLPath,
			prepared.candidateDER,
			prepared.certificates.issuer,
			prepared.certificates.leaf,
			options.At,
			options.TransactionID,
		)
	if err != nil {
		return result, fmt.Errorf(
			"activate validated transport CRL candidate: %w",
			err,
		)
	}

	result.Activated =
		activation.Activated

	result.BackupPath =
		activation.BackupPath

	result.FailedPath =
		activation.FailedPath

	result.Reason =
		activation.Reason

	return result, nil
}
