// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

const approval1MaximumCRLBytes = int64(4 * 1024 * 1024)

type approval1CRLMaterial struct {
	DER             []byte
	DestinationPath string
	NextUpdate      string
	SHA256          string
	Source          string
	ThisUpdate      string
}

type approval1LDAPCRLSource struct {
	Attribute string
	BaseDN    string
	Filter    string
}

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
	parsed, err := url.Parse(
		strings.TrimSpace(raw),
	)
	if err != nil {
		return approval1LDAPCRLSource{}, fmt.Errorf(
			"parse LDAP CRL distribution point %q: %w",
			raw,
			err,
		)
	}

	if !strings.EqualFold(
		parsed.Scheme,
		"ldap",
	) {
		return approval1LDAPCRLSource{}, fmt.Errorf(
			"CRL distribution point scheme=%q is not LDAP",
			parsed.Scheme,
		)
	}

	if strings.TrimSpace(
		parsed.Host,
	) != "" {
		return approval1LDAPCRLSource{}, fmt.Errorf(
			"LDAP CRL distribution point host %q is not supported; FI uses its already authenticated domain-controller session",
			parsed.Host,
		)
	}

	baseDN := strings.TrimPrefix(
		strings.TrimSpace(
			parsed.Path,
		),
		"/",
	)
	if baseDN == "" {
		return approval1LDAPCRLSource{}, errors.New(
			"LDAP CRL distribution point base distinguished name is empty",
		)
	}

	fields := strings.Split(
		parsed.RawQuery,
		"?",
	)

	if len(fields) < 2 ||
		len(fields) > 4 {
		return approval1LDAPCRLSource{}, fmt.Errorf(
			"LDAP CRL distribution point contains %d query fields; expected attributes, scope, optional filter, and optional extensions",
			len(fields),
		)
	}

	attributes := strings.Split(
		fields[0],
		",",
	)

	if len(attributes) != 1 ||
		!strings.EqualFold(
			strings.TrimSpace(
				attributes[0],
			),
			"certificateRevocationList",
		) {
		return approval1LDAPCRLSource{}, fmt.Errorf(
			"LDAP CRL distribution point must request exactly certificateRevocationList; observed=%q",
			fields[0],
		)
	}

	if !strings.EqualFold(
		strings.TrimSpace(
			fields[1],
		),
		"base",
	) {
		return approval1LDAPCRLSource{}, fmt.Errorf(
			"LDAP CRL distribution point must use base scope; observed=%q",
			fields[1],
		)
	}

	filter :=
		"(objectClass=cRLDistributionPoint)"

	if len(fields) >= 3 &&
		strings.TrimSpace(
			fields[2],
		) != "" {
		observed := strings.TrimSpace(
			fields[2],
		)

		normalized := strings.TrimPrefix(
			observed,
			"(",
		)
		normalized = strings.TrimSuffix(
			normalized,
			")",
		)

		if !strings.EqualFold(
			normalized,
			"objectClass=cRLDistributionPoint",
		) {
			return approval1LDAPCRLSource{}, fmt.Errorf(
				"LDAP CRL distribution point filter %q is not the accepted AD CS cRLDistributionPoint filter",
				observed,
			)
		}
	}

	if len(fields) == 4 &&
		strings.TrimSpace(
			fields[3],
		) != "" {
		return approval1LDAPCRLSource{}, errors.New(
			"LDAP CRL distribution point extensions are not supported",
		)
	}

	return approval1LDAPCRLSource{
		Attribute: "certificateRevocationList",
		BaseDN:    baseDN,
		Filter:    filter,
	}, nil
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

	entry, result, err :=
		session.searchSingleEntry(
			source.BaseDN,
			uint32(
				ldapScopeBase,
			),
			source.Filter,
			[]string{
				source.Attribute,
			},
		)

	if result != 0 {
		defer ldapMsgFreeProc.Call(
			result,
		)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"read AD CS CRL object %s: %w",
			source.BaseDN,
			err,
		)
	}

	value, err := session.getBinaryValue(
		entry,
		source.Attribute,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read AD CS %s from %s: %w",
			source.Attribute,
			source.BaseDN,
			err,
		)
	}

	if len(value) >
		int(
			approval1MaximumCRLBytes,
		) {
		return nil, fmt.Errorf(
			"AD CS CRL size=%d exceeds FI limit=%d bytes",
			len(value),
			approval1MaximumCRLBytes,
		)
	}

	return value, nil
}

func readApproval1HTTPCRL(
	source string,
) ([]byte, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	response, err := client.Get(
		source,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"retrieve transport CRL %q: %w",
			source,
			err,
		)
	}
	defer response.Body.Close()

	if response.StatusCode !=
		http.StatusOK {
		return nil, fmt.Errorf(
			"retrieve transport CRL %q: HTTP status=%d",
			source,
			response.StatusCode,
		)
	}

	limited := io.LimitReader(
		response.Body,
		approval1MaximumCRLBytes+1,
	)

	value, err := io.ReadAll(
		limited,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read transport CRL %q: %w",
			source,
			err,
		)
	}

	if int64(
		len(value),
	) > approval1MaximumCRLBytes {
		return nil, fmt.Errorf(
			"transport CRL %q exceeds FI limit=%d bytes",
			source,
			approval1MaximumCRLBytes,
		)
	}

	return value, nil
}

func validateApproval1TransportCRL(
	raw []byte,
	issuer *x509.Certificate,
	leaf *x509.Certificate,
	at time.Time,
) (*x509.RevocationList, error) {
	if len(raw) == 0 {
		return nil, errors.New(
			"transport CRL is empty",
		)
	}

	if issuer == nil {
		return nil, errors.New(
			"transport CRL issuer certificate is required",
		)
	}

	if leaf == nil {
		return nil, errors.New(
			"transport leaf certificate is required",
		)
	}

	if at.IsZero() {
		return nil, errors.New(
			"current time is required for transport CRL validation",
		)
	}

	revocationList, err :=
		x509.ParseRevocationList(
			raw,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"parse transport CRL DER: %w",
			err,
		)
	}

	if !bytes.Equal(
		revocationList.RawIssuer,
		issuer.RawSubject,
	) {
		return nil, errors.New(
			"transport CRL issuer does not match the derived transport issuing CA",
		)
	}

	if err :=
		revocationList.CheckSignatureFrom(
			issuer,
		); err != nil {
		return nil, fmt.Errorf(
			"transport CRL signature validation failed: %w",
			err,
		)
	}

	if revocationList.ThisUpdate.After(
		at,
	) {
		return nil, fmt.Errorf(
			"transport CRL is not yet valid: thisUpdate=%s",
			revocationList.ThisUpdate.UTC().Format(
				time.RFC3339,
			),
		)
	}

	if revocationList.NextUpdate.IsZero() {
		return nil, errors.New(
			"transport CRL nextUpdate is required",
		)
	}

	if !revocationList.NextUpdate.After(
		at,
	) {
		return nil, fmt.Errorf(
			"transport CRL is expired: nextUpdate=%s",
			revocationList.NextUpdate.UTC().Format(
				time.RFC3339,
			),
		)
	}

	if certificateRevokedByApproval1CRL(
		revocationList,
		leaf,
	) {
		return nil, fmt.Errorf(
			"transport certificate serial=%s is revoked by the retrieved CRL",
			leaf.SerialNumber.Text(
				16,
			),
		)
	}

	return revocationList, nil
}

func certificateRevokedByApproval1CRL(
	revocationList *x509.RevocationList,
	certificate *x509.Certificate,
) bool {
	if revocationList == nil ||
		certificate == nil ||
		certificate.SerialNumber == nil {
		return false
	}

	for _, entry := range revocationList.RevokedCertificateEntries {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(
				certificate.SerialNumber,
			) == 0 {
			return true
		}
	}

	for _, entry := range revocationList.RevokedCertificates {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(
				certificate.SerialNumber,
			) == 0 {
			return true
		}
	}

	return false
}
