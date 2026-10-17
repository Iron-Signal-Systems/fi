// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportcrl"
	"golang.org/x/sys/windows"
)

type approval2TransportTrustBackend interface {
	AcquireTransportCRL(
		session *ldapSession,
		trust approval1TransportTrustMaterial,
		at time.Time,
	) (approval1CRLMaterial, error)

	DeriveTransportTrust(
		certificateSHA256 string,
	) (approval1TransportTrustMaterial, error)
}

type nativeApproval2TransportTrustBackend struct{}

func (nativeApproval2TransportTrustBackend) AcquireTransportCRL(
	session *ldapSession,
	trust approval1TransportTrustMaterial,
	at time.Time,
) (approval1CRLMaterial, error) {
	return acquireApproval1TransportCRL(
		session,
		trust,
		at,
	)
}

func (nativeApproval2TransportTrustBackend) DeriveTransportTrust(
	certificateSHA256 string,
) (approval1TransportTrustMaterial, error) {
	return deriveApproval1TransportTrustMaterial(
		certificateSHA256,
	)
}

func createApproval2TransportTrust(
	session *ldapSession,
	report Report,
	handoff approval1PKIHandoff,
	transactionID string,
) (func() error, error) {
	expectedTrustPath, err :=
		config.DefaultTransportTrustPath()
	if err != nil {
		return nil, fmt.Errorf(
			"resolve fixed FI transport-trust path: %w",
			err,
		)
	}

	if !strings.EqualFold(
		filepath.Clean(
			strings.TrimSpace(
				report.Trust.Path,
			),
		),
		filepath.Clean(
			expectedTrustPath,
		),
	) {
		return nil, fmt.Errorf(
			"transport-trust path=%q does not match fixed FI path=%q",
			report.Trust.Path,
			expectedTrustPath,
		)
	}

	return createApproval2TransportTrustWithBackend(
		session,
		report,
		handoff,
		transactionID,
		time.Now(),
		nativeApproval2TransportTrustBackend{},
	)
}

func createApproval2TransportTrustWithBackend(
	session *ldapSession,
	report Report,
	handoff approval1PKIHandoff,
	transactionID string,
	at time.Time,
	backend approval2TransportTrustBackend,
) (func() error, error) {
	if backend == nil {
		return nil, errors.New(
			"Approval 2 transport-trust backend is required",
		)
	}

	if err := handoff.validate(); err != nil {
		return nil, fmt.Errorf(
			"Approval 2 transport-trust handoff is invalid: %w",
			err,
		)
	}

	if report.Trust.Presence != presenceAbsent {
		return nil, fmt.Errorf(
			"Approval 2 CREATE requires transport-trust presence=%s; expected=%s",
			report.Trust.Presence,
			presenceAbsent,
		)
	}

	trustPath := strings.TrimSpace(
		report.Trust.Path,
	)
	if trustPath == "" {
		return nil, errors.New(
			"Approval 2 transport-trust destination path is unavailable",
		)
	}

	if at.IsZero() {
		return nil, errors.New(
			"Approval 2 current time is required",
		)
	}

	derived, err := backend.DeriveTransportTrust(
		handoff.TransportCertificateSHA256,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"Approval 2 rederive transport trust: %w",
			err,
		)
	}

	if err := verifyApproval2DerivedTrustContract(
		handoff,
		derived,
	); err != nil {
		return nil, err
	}

	crl, err := backend.AcquireTransportCRL(
		session,
		derived,
		at,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"Approval 2 reacquire transport CRL: %w",
			err,
		)
	}

	if err := verifyApproval2ReacquiredCRLContract(
		handoff,
		crl,
	); err != nil {
		return nil, err
	}

	value := config.TransportTrustConfig{
		VersionID: config.TransportTrustVersion1,

		BatchSigningCertificateSHA256: strings.ToLower(
			handoff.BatchCertificateSHA256,
		),

		RootCertificateSHA256: strings.ToLower(
			handoff.RootCertificateSHA256,
		),

		TransportCertificateSHA256: strings.ToLower(
			handoff.TransportCertificateSHA256,
		),

		TransportCRLPath: handoff.CRLDestinationPath,

		TransportIssuerSHA256: strings.ToLower(
			handoff.TransportIssuerSHA256,
		),
	}

	configBytes, err :=
		renderApproval2TransportTrustConfig(
			value,
		)
	if err != nil {
		return nil, err
	}

	return createApproval2TransportTrustFiles(
		trustPath,
		handoff.CRLDestinationPath,
		configBytes,
		crl.DER,
		handoff.CRLSHA256,
		transactionID,
	)
}

func verifyApproval2DerivedTrustContract(
	handoff approval1PKIHandoff,
	derived approval1TransportTrustMaterial,
) error {
	if !strings.EqualFold(
		handoff.TransportCertificateSHA256,
		derived.TransportCertificateSHA256,
	) {
		return fmt.Errorf(
			"Approval 2 transport certificate drift: approved=%s observed=%s",
			handoff.TransportCertificateSHA256,
			derived.TransportCertificateSHA256,
		)
	}

	if !strings.EqualFold(
		handoff.TransportIssuerSHA256,
		derived.IssuerCertificateSHA256,
	) {
		return fmt.Errorf(
			"Approval 2 transport issuer drift: approved=%s observed=%s",
			handoff.TransportIssuerSHA256,
			derived.IssuerCertificateSHA256,
		)
	}

	if !strings.EqualFold(
		handoff.RootCertificateSHA256,
		derived.RootCertificateSHA256,
	) {
		return fmt.Errorf(
			"Approval 2 transport root drift: approved=%s observed=%s",
			handoff.RootCertificateSHA256,
			derived.RootCertificateSHA256,
		)
	}

	if strings.TrimSpace(
		handoff.CRLDistributionPoint,
	) != strings.TrimSpace(
		derived.CRLDistributionPoint,
	) {
		return fmt.Errorf(
			"Approval 2 transport CRL source drift: approved=%q observed=%q",
			handoff.CRLDistributionPoint,
			derived.CRLDistributionPoint,
		)
	}

	if !strings.EqualFold(
		filepath.Clean(
			handoff.CRLDestinationPath,
		),
		filepath.Clean(
			derived.CRLDestinationPath,
		),
	) {
		return fmt.Errorf(
			"Approval 2 transport CRL destination drift: approved=%q observed=%q",
			handoff.CRLDestinationPath,
			derived.CRLDestinationPath,
		)
	}

	return nil
}

func verifyApproval2ReacquiredCRLContract(
	handoff approval1PKIHandoff,
	crl approval1CRLMaterial,
) error {
	if len(crl.DER) == 0 {
		return errors.New(
			"Approval 2 reacquired transport CRL is empty",
		)
	}

	digest := sha256.Sum256(
		crl.DER,
	)
	observedSHA256 := hex.EncodeToString(
		digest[:],
	)

	if !strings.EqualFold(
		handoff.CRLSHA256,
		observedSHA256,
	) {
		return fmt.Errorf(
			"Approval 2 transport CRL DER drift: approved=%s observed=%s",
			handoff.CRLSHA256,
			observedSHA256,
		)
	}

	if !strings.EqualFold(
		handoff.CRLSHA256,
		crl.SHA256,
	) {
		return fmt.Errorf(
			"Approval 2 transport CRL reported SHA256=%s does not match approved SHA256=%s",
			crl.SHA256,
			handoff.CRLSHA256,
		)
	}

	if strings.TrimSpace(
		handoff.CRLDistributionPoint,
	) != strings.TrimSpace(
		crl.Source,
	) {
		return fmt.Errorf(
			"Approval 2 transport CRL source drift: approved=%q observed=%q",
			handoff.CRLDistributionPoint,
			crl.Source,
		)
	}

	if !strings.EqualFold(
		filepath.Clean(
			handoff.CRLDestinationPath,
		),
		filepath.Clean(
			crl.DestinationPath,
		),
	) {
		return fmt.Errorf(
			"Approval 2 transport CRL destination drift: approved=%q observed=%q",
			handoff.CRLDestinationPath,
			crl.DestinationPath,
		)
	}

	if strings.TrimSpace(
		handoff.CRLThisUpdate,
	) != strings.TrimSpace(
		crl.ThisUpdate,
	) {
		return fmt.Errorf(
			"Approval 2 transport CRL thisUpdate drift: approved=%s observed=%s",
			handoff.CRLThisUpdate,
			crl.ThisUpdate,
		)
	}

	if strings.TrimSpace(
		handoff.CRLNextUpdate,
	) != strings.TrimSpace(
		crl.NextUpdate,
	) {
		return fmt.Errorf(
			"Approval 2 transport CRL nextUpdate drift: approved=%s observed=%s",
			handoff.CRLNextUpdate,
			crl.NextUpdate,
		)
	}

	return nil
}

func renderApproval2TransportTrustConfig(
	value config.TransportTrustConfig,
) ([]byte, error) {
	var builder strings.Builder

	fmt.Fprintf(
		&builder,
		"version_id: %s\n\n",
		value.VersionID,
	)

	fmt.Fprintf(
		&builder,
		"trust.root_cert_sha256 = %s\n",
		strings.ToLower(
			value.RootCertificateSHA256,
		),
	)

	fmt.Fprintf(
		&builder,
		"trust.transport_cert_sha256 = %s\n",
		strings.ToLower(
			value.TransportCertificateSHA256,
		),
	)

	fmt.Fprintf(
		&builder,
		"trust.transport_issuer_sha256 = %s\n",
		strings.ToLower(
			value.TransportIssuerSHA256,
		),
	)

	fmt.Fprintf(
		&builder,
		"trust.batch_signing_cert_sha256 = %s\n",
		strings.ToLower(
			value.BatchSigningCertificateSHA256,
		),
	)

	fmt.Fprintf(
		&builder,
		"trust.transport_crl = %s\n",
		value.TransportCRLPath,
	)

	encoded := []byte(
		builder.String(),
	)

	parsed, err := config.ParseTransportTrust(
		bytes.NewReader(
			encoded,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"self-validate generated FI transport-trust configuration: %w",
			err,
		)
	}

	if !sameApproval2TransportTrustConfig(
		parsed,
		value,
	) {
		return nil, errors.New(
			"generated FI transport-trust configuration did not round-trip exactly",
		)
	}

	return encoded, nil
}

func sameApproval2TransportTrustConfig(
	left config.TransportTrustConfig,
	right config.TransportTrustConfig,
) bool {
	return left.VersionID == right.VersionID &&
		strings.EqualFold(
			left.BatchSigningCertificateSHA256,
			right.BatchSigningCertificateSHA256,
		) &&
		strings.EqualFold(
			left.RootCertificateSHA256,
			right.RootCertificateSHA256,
		) &&
		strings.EqualFold(
			left.TransportCertificateSHA256,
			right.TransportCertificateSHA256,
		) &&
		strings.EqualFold(
			filepath.Clean(
				left.TransportCRLPath,
			),
			filepath.Clean(
				right.TransportCRLPath,
			),
		) &&
		strings.EqualFold(
			left.TransportIssuerSHA256,
			right.TransportIssuerSHA256,
		)
}

func createApproval2TransportTrustFiles(
	trustPath string,
	crlPath string,
	trustBytes []byte,
	crlDER []byte,
	expectedCRLSHA256 string,
	transactionID string,
) (func() error, error) {
	return createApproval2TransportTrustFilesWithRename(
		trustPath,
		crlPath,
		trustBytes,
		crlDER,
		expectedCRLSHA256,
		transactionID,
		os.Rename,
	)
}

func createApproval2TransportTrustFilesWithRename(
	trustPath string,
	crlPath string,
	trustBytes []byte,
	crlDER []byte,
	expectedCRLSHA256 string,
	transactionID string,
	renameFile func(string, string) error,
) (func() error, error) {
	trustPath = filepath.Clean(
		strings.TrimSpace(
			trustPath,
		),
	)

	crlPath = filepath.Clean(
		strings.TrimSpace(
			crlPath,
		),
	)

	if renameFile == nil {
		return nil, errors.New(
			"Approval 2 transport-trust rename operation is required",
		)
	}

	if trustPath == "" ||
		trustPath == "." ||
		crlPath == "" ||
		crlPath == "." {
		return nil, errors.New(
			"Approval 2 transport-trust destinations are required",
		)
	}

	if strings.EqualFold(
		trustPath,
		crlPath,
	) {
		return nil, errors.New(
			"transport-trust configuration and CRL destinations must be different files",
		)
	}

	if !validSHA256Hex(
		expectedCRLSHA256,
	) {
		return nil, errors.New(
			"approved transport CRL SHA-256 is invalid",
		)
	}

	if !validApproval2TransactionID(
		transactionID,
	) {
		return nil, fmt.Errorf(
			"invalid Approval 2 transaction ID %q",
			transactionID,
		)
	}

	if err := requireApproval2PlainDirectory(
		filepath.Dir(
			trustPath,
		),
	); err != nil {
		return nil, err
	}

	if err := requireApproval2PlainDirectory(
		filepath.Dir(
			crlPath,
		),
	); err != nil {
		return nil, err
	}

	for _, destination := range []string{
		crlPath,
		trustPath,
	} {
		if _, err := os.Lstat(
			destination,
		); err == nil {
			return nil, fmt.Errorf(
				"Approval 2 CREATE refuses existing destination %s",
				destination,
			)
		} else if !errors.Is(
			err,
			os.ErrNotExist,
		) {
			return nil, fmt.Errorf(
				"inspect Approval 2 destination %s: %w",
				destination,
				err,
			)
		}
	}

	digest := sha256.Sum256(
		crlDER,
	)

	observedCRLSHA256 :=
		hex.EncodeToString(
			digest[:],
		)

	if !strings.EqualFold(
		observedCRLSHA256,
		expectedCRLSHA256,
	) {
		return nil, fmt.Errorf(
			"transport CRL DER SHA256=%s does not match approved SHA256=%s",
			observedCRLSHA256,
			expectedCRLSHA256,
		)
	}

	crlPEM, err := transportcrl.EncodeCanonicalPEM(
		crlDER,
	)
	if err != nil {
		return nil, err
	}

	crlStage := crlPath +
		".fi-new-" +
		transactionID

	trustStage := trustPath +
		".fi-new-" +
		transactionID

	cleanupStages := func() error {
		return removeApproval2TransportTrustFiles(
			crlStage,
			trustStage,
		)
	}

	rollbackActivated := func() error {
		return removeApproval2CreatedTransportTrustFiles(
			trustPath,
			crlPath,
		)
	}

	failStaged := func(
		base error,
	) (func() error, error) {
		return nil, joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "cleanup staged Approval 2 transport-trust files",
				run:  cleanupStages,
			},
		)
	}

	failActivated := func(
		base error,
	) (func() error, error) {
		return nil, joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "rollback activated Approval 2 transport-trust files",
				run:  rollbackActivated,
			},
			fiRecoveryStep{
				name: "cleanup staged Approval 2 transport-trust files",
				run:  cleanupStages,
			},
		)
	}

	if err := writeApproval2ExclusiveFile(
		crlStage,
		crlPEM,
	); err != nil {
		return failStaged(
			err,
		)
	}

	if err := verifyApproval2PersistedCRL(
		crlStage,
		crlDER,
		expectedCRLSHA256,
	); err != nil {
		return failStaged(
			err,
		)
	}

	if err := writeApproval2ExclusiveFile(
		trustStage,
		trustBytes,
	); err != nil {
		return failStaged(
			err,
		)
	}

	if _, err := config.LoadTransportTrust(
		trustStage,
	); err != nil {
		return failStaged(
			fmt.Errorf(
				"verify staged FI transport-trust configuration: %w",
				err,
			),
		)
	}

	if err := activateApproval2TransportTrustFiles(
		crlStage,
		crlPath,
		trustStage,
		trustPath,
		renameFile,
	); err != nil {
		return failActivated(
			err,
		)
	}

	if err := verifyApproval2PersistedCRL(
		crlPath,
		crlDER,
		expectedCRLSHA256,
	); err != nil {
		return nil, joinFIRecoveryFailures(
			err,
			fiRecoveryStep{
				name: "rollback activated Approval 2 transport-trust files",
				run:  rollbackActivated,
			},
		)
	}

	if _, err := config.LoadTransportTrust(
		trustPath,
	); err != nil {
		base := fmt.Errorf(
			"verify activated FI transport-trust configuration: %w",
			err,
		)

		return nil, joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "rollback activated Approval 2 transport-trust files",
				run:  rollbackActivated,
			},
		)
	}

	return rollbackActivated, nil
}

func activateApproval2TransportTrustFiles(
	crlStage string,
	crlPath string,
	trustStage string,
	trustPath string,
	renameFile func(string, string) error,
) error {
	if renameFile == nil {
		return errors.New(
			"Approval 2 transport-trust rename operation is required",
		)
	}

	if err := renameFile(
		crlStage,
		crlPath,
	); err != nil {
		return fmt.Errorf(
			"activate transport CRL %s: %w",
			crlPath,
			err,
		)
	}

	if err := renameFile(
		trustStage,
		trustPath,
	); err != nil {
		return fmt.Errorf(
			"activate FI transport-trust configuration %s: %w",
			trustPath,
			err,
		)
	}

	return nil
}

func removeApproval2TransportTrustFiles(
	paths ...string,
) error {
	var found []error

	for _, path := range paths {
		path = strings.TrimSpace(
			path,
		)

		if path == "" {
			continue
		}

		if err := removeFileWithRetry(
			path,
			5*time.Second,
		); err != nil &&
			!errors.Is(
				err,
				os.ErrNotExist,
			) {
			found = append(
				found,
				fmt.Errorf(
					"remove Approval 2 transport-trust file %s: %w",
					path,
					err,
				),
			)
		}
	}

	return errors.Join(
		found...,
	)
}
func verifyApproval2PersistedCRL(
	path string,
	expectedDER []byte,
	expectedSHA256 string,
) error {
	return transportcrl.VerifyPersistedPEM(
		path,
		expectedDER,
		expectedSHA256,
	)
}
func writeApproval2ExclusiveFile(
	path string,
	value []byte,
) error {
	file, err := os.OpenFile(
		path,
		os.O_CREATE|
			os.O_EXCL|
			os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf(
			"create Approval 2 staged file %s: %w",
			path,
			err,
		)
	}

	removeStage := func() error {
		err := removeFileWithRetry(
			path,
			5*time.Second,
		)
		if err == nil ||
			errors.Is(
				err,
				os.ErrNotExist,
			) {
			return nil
		}

		return fmt.Errorf(
			"remove failed Approval 2 staged file %s: %w",
			path,
			err,
		)
	}

	failWithOpenFile := func(
		base error,
	) error {
		return joinFIRecoveryFailures(
			base,
			fiRecoveryStep{
				name: "close failed Approval 2 staged file",
				run:  file.Close,
			},
			fiRecoveryStep{
				name: "remove failed Approval 2 staged file",
				run:  removeStage,
			},
		)
	}

	if _, err := file.Write(
		value,
	); err != nil {
		return failWithOpenFile(
			fmt.Errorf(
				"write Approval 2 staged file %s: %w",
				path,
				err,
			),
		)
	}

	if err := file.Sync(); err != nil {
		return failWithOpenFile(
			fmt.Errorf(
				"sync Approval 2 staged file %s: %w",
				path,
				err,
			),
		)
	}

	if err := file.Close(); err != nil {
		return joinFIRecoveryFailures(
			fmt.Errorf(
				"close Approval 2 staged file %s: %w",
				path,
				err,
			),
			fiRecoveryStep{
				name: "remove failed Approval 2 staged file",
				run:  removeStage,
			},
		)
	}

	return nil
}
func requireApproval2PlainDirectory(
	path string,
) error {
	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return fmt.Errorf(
			"Approval 2 requires pre-created protected directory %s: %w",
			path,
			err,
		)
	}

	if !info.IsDir() {
		return fmt.Errorf(
			"Approval 2 destination parent %s is not a directory",
			path,
		)
	}

	name, err := windows.UTF16PtrFromString(
		path,
	)
	if err != nil {
		return fmt.Errorf(
			"encode Approval 2 directory path %s: %w",
			path,
			err,
		)
	}

	attributes, err := windows.GetFileAttributes(
		name,
	)
	if err != nil {
		return fmt.Errorf(
			"read Approval 2 directory attributes %s: %w",
			path,
			err,
		)
	}

	if attributes&
		windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf(
			"Approval 2 refuses reparse-point destination directory %s",
			path,
		)
	}

	return nil
}

func removeApproval2CreatedTransportTrustFiles(
	trustPath string,
	crlPath string,
) error {
	return removeApproval2TransportTrustFiles(
		trustPath,
		crlPath,
	)
}

func validApproval2TransactionID(
	value string,
) bool {
	value = strings.TrimSpace(
		value,
	)
	if value == "" ||
		len(value) > 80 {
		return false
	}

	for _, current := range value {
		switch {
		case current >= 'a' &&
			current <= 'z':
		case current >= 'A' &&
			current <= 'Z':
		case current >= '0' &&
			current <= '9':
		case current == '-':
		case current == '_':
		case current == '.':
		default:
			return false
		}
	}

	return true
}
