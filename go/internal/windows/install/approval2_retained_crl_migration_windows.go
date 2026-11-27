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
	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportcrl"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

func retainedTransportCRLMigrationRequired(
	report Report,
) bool {
	if report.Trust.Presence !=
		presencePresent {
		return false
	}

	if !transportPKIComplete(
		report,
	) {
		return false
	}

	current :=
		strings.TrimSpace(
			report.Trust.TransportCRLPath,
		)

	desired :=
		strings.TrimSpace(
			approval1TransportCRLDestination,
		)

	if current == "" ||
		desired == "" {
		return false
	}

	return !strings.EqualFold(
		filepath.Clean(
			current,
		),
		filepath.Clean(
			desired,
		),
	)
}

func legacyTransportTrustDirectoryRequired(
	report Report,
) bool {
	current :=
		strings.TrimSpace(
			report.Trust.TransportCRLPath,
		)

	desired :=
		strings.TrimSpace(
			approval1TransportCRLDestination,
		)

	if current == "" ||
		desired == "" {
		return false
	}

	return !strings.EqualFold(
		filepath.Clean(
			current,
		),
		filepath.Clean(
			desired,
		),
	)
}

func retainedTransportTrustConfigFromReport(
	report Report,
) config.TransportTrustConfig {
	return config.TransportTrustConfig{
		VersionID: report.Trust.VersionID,

		BatchSigningCertificateSHA256: report.Trust.BatchSigningCertificateSHA256,

		RootCertificateSHA256: report.Trust.RootCertificateSHA256,

		TransportCertificateSHA256: report.Trust.TransportCertificateSHA256,

		TransportCRLPath: report.Trust.TransportCRLPath,

		TransportIssuerSHA256: report.Trust.TransportIssuerSHA256,
	}
}

func migrateRetainedTransportTrust(
	report Report,
	transactionID string,
	at time.Time,
) (func() error, error) {
	if !retainedTransportCRLMigrationRequired(
		report,
	) {
		return nil, errors.New(
			"retained transport-trust CRL migration is not required",
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

	if at.IsZero() {
		return nil, errors.New(
			"retained transport-trust migration requires current time",
		)
	}

	sourceCRLPath :=
		filepath.Clean(
			strings.TrimSpace(
				report.Trust.TransportCRLPath,
			),
		)

	destinationCRLPath :=
		filepath.Clean(
			strings.TrimSpace(
				approval1TransportCRLDestination,
			),
		)

	trustPath :=
		filepath.Clean(
			strings.TrimSpace(
				report.Trust.Path,
			),
		)

	if sourceCRLPath == "." ||
		destinationCRLPath == "." ||
		trustPath == "." {
		return nil, errors.New(
			"retained transport-trust migration paths are incomplete",
		)
	}

	if strings.EqualFold(
		sourceCRLPath,
		destinationCRLPath,
	) {
		return nil, errors.New(
			"retained transport CRL already uses the canonical activation path",
		)
	}

	if err :=
		requireRetainedMigrationRegularFile(
			sourceCRLPath,
		); err != nil {
		return nil, err
	}

	if err :=
		requireRetainedMigrationRegularFile(
			trustPath,
		); err != nil {
		return nil, err
	}

	originalTrustBytes, err :=
		os.ReadFile(
			trustPath,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"read retained FI transport-trust configuration: %w",
			err,
		)
	}

	originalTrust, err :=
		config.ParseTransportTrust(
			bytes.NewReader(
				originalTrustBytes,
			),
		)
	if err != nil {
		return nil, fmt.Errorf(
			"parse retained FI transport-trust configuration: %w",
			err,
		)
	}

	expectedTrust :=
		retainedTransportTrustConfigFromReport(
			report,
		)

	if !sameApproval2TransportTrustConfig(
		originalTrust,
		expectedTrust,
	) {
		return nil, errors.New(
			"retained FI transport-trust configuration changed after authoritative discovery",
		)
	}

	sourceCRL, err :=
		receivertrust.LoadCRL(
			sourceCRLPath,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"load retained transport CRL: %w",
			err,
		)
	}

	issuer, _, err :=
		loadLocalMachineTransportIssuer(
			report.Trust.TransportIssuerSHA256,
			report.Trust.RootCertificateSHA256,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"load pinned transport issuer for retained CRL migration: %w",
			err,
		)
	}

	leaf, err :=
		certstore.LoadLocalMachineCertificate(
			certstore.StoreMy,
			report.Trust.TransportCertificateSHA256,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"load pinned transport certificate for retained CRL migration: %w",
			err,
		)
	}

	validatedCRL, err :=
		transportcrl.ValidateDER(
			sourceCRL.Raw,
			issuer,
			leaf,
			at,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"validate retained transport CRL before migration: %w",
			err,
		)
	}

	if !bytes.Equal(
		validatedCRL.Raw,
		sourceCRL.Raw,
	) {
		return nil, errors.New(
			"validated retained transport CRL did not reproduce source DER",
		)
	}

	crlPEM, err :=
		transportcrl.EncodeCanonicalPEM(
			sourceCRL.Raw,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode retained transport CRL for migration: %w",
			err,
		)
	}

	digest :=
		sha256.Sum256(
			sourceCRL.Raw,
		)

	expectedCRLSHA256 :=
		hex.EncodeToString(
			digest[:],
		)

	destinationDirectory :=
		filepath.Dir(
			destinationCRLPath,
		)

	if err :=
		requireApproval2PlainDirectory(
			filepath.Dir(
				destinationDirectory,
			),
		); err != nil {
		return nil, err
	}

	if _, err :=
		os.Lstat(
			destinationDirectory,
		); err == nil {
		return nil, fmt.Errorf(
			"retained CRL migration refuses preexisting activation directory %s",
			destinationDirectory,
		)
	} else if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		return nil, fmt.Errorf(
			"inspect retained CRL migration activation directory %s: %w",
			destinationDirectory,
			err,
		)
	}

	createdDirectories, err :=
		prepareApproval2OwnedDirectories(
			[]string{
				destinationDirectory,
			},
		)
	if err != nil {
		return nil, err
	}

	rollbackDirectories :=
		func() error {
			return rollbackApproval2CreatedDirectories(
				createdDirectories,
			)
		}

	if err :=
		setNamedSecurityDescriptorFromSDDL(
			destinationDirectory,
			desiredProtectedDirectorySDDL(
				nil,
			),
		); err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"protect retained CRL migration activation directory: %w",
				err,
			),
			rollbackDirectories(),
		)
	}

	crlStage :=
		destinationCRLPath +
			".fi-migrate-" +
			transactionID

	trustStage :=
		trustPath +
			".fi-migrate-" +
			transactionID

	trustBackup :=
		trustPath +
			".fi-migrate-backup-" +
			transactionID

	for _, path := range []string{
		destinationCRLPath,
		crlStage,
		trustStage,
		trustBackup,
	} {
		if err :=
			requireRetainedMigrationAbsent(
				path,
			); err != nil {
			return nil, errors.Join(
				err,
				rollbackDirectories(),
			)
		}
	}

	cleanupBeforeActivation :=
		func() error {
			return errors.Join(
				removeRetainedMigrationPath(
					crlStage,
				),
				removeRetainedMigrationPath(
					trustStage,
				),
				removeRetainedMigrationPath(
					trustBackup,
				),
				rollbackDirectories(),
			)
		}

	if err :=
		writeApproval2ExclusiveFile(
			crlStage,
			crlPEM,
		); err != nil {
		return nil, errors.Join(
			err,
			cleanupBeforeActivation(),
		)
	}

	if err :=
		verifyApproval2PersistedCRL(
			crlStage,
			sourceCRL.Raw,
			expectedCRLSHA256,
		); err != nil {
		return nil, errors.Join(
			err,
			cleanupBeforeActivation(),
		)
	}

	migratedTrust :=
		originalTrust

	migratedTrust.TransportCRLPath =
		destinationCRLPath

	migratedTrustBytes, err :=
		renderApproval2TransportTrustConfig(
			migratedTrust,
		)
	if err != nil {
		return nil, errors.Join(
			err,
			cleanupBeforeActivation(),
		)
	}

	if err :=
		writeApproval2ExclusiveFile(
			trustStage,
			migratedTrustBytes,
		); err != nil {
		return nil, errors.Join(
			err,
			cleanupBeforeActivation(),
		)
	}

	stagedTrust, err :=
		config.LoadTransportTrust(
			trustStage,
		)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"verify staged retained transport-trust migration: %w",
				err,
			),
			cleanupBeforeActivation(),
		)
	}

	if !sameApproval2TransportTrustConfig(
		stagedTrust,
		migratedTrust,
	) {
		return nil, errors.Join(
			errors.New(
				"staged retained transport-trust migration did not round-trip exactly",
			),
			cleanupBeforeActivation(),
		)
	}

	latestSourceCRL, err :=
		receivertrust.LoadCRL(
			sourceCRLPath,
		)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"reread retained transport CRL before activation: %w",
				err,
			),
			cleanupBeforeActivation(),
		)
	}

	if !bytes.Equal(
		latestSourceCRL.Raw,
		sourceCRL.Raw,
	) {
		return nil, errors.Join(
			errors.New(
				"retained transport CRL changed during migration preparation",
			),
			cleanupBeforeActivation(),
		)
	}

	latestTrustBytes, err :=
		os.ReadFile(
			trustPath,
		)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"reread retained transport-trust configuration before activation: %w",
				err,
			),
			cleanupBeforeActivation(),
		)
	}

	if !bytes.Equal(
		latestTrustBytes,
		originalTrustBytes,
	) {
		return nil, errors.Join(
			errors.New(
				"retained transport-trust configuration changed during migration preparation",
			),
			cleanupBeforeActivation(),
		)
	}

	if err :=
		os.Rename(
			crlStage,
			destinationCRLPath,
		); err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"activate migrated transport CRL: %w",
				err,
			),
			cleanupBeforeActivation(),
		)
	}

	rollbackActivatedCRL :=
		func() error {
			return errors.Join(
				removeRetainedMigrationPath(
					destinationCRLPath,
				),
				removeRetainedMigrationPath(
					crlStage,
				),
				removeRetainedMigrationPath(
					trustStage,
				),
				removeRetainedMigrationPath(
					trustBackup,
				),
				rollbackDirectories(),
			)
		}

	if err :=
		transportcrl.ReplaceExistingFileWithBackup(
			trustPath,
			trustStage,
			trustBackup,
		); err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"activate migrated FI transport-trust configuration: %w",
				err,
			),
			rollbackActivatedCRL(),
		)
	}

	rollbackActivated :=
		func() error {
			return errors.Join(
				restoreRetainedTransportTrustConfig(
					trustPath,
					originalTrustBytes,
					originalTrust,
					trustBackup,
					transactionID,
				),
				removeRetainedMigrationPath(
					destinationCRLPath,
				),
				removeRetainedMigrationPath(
					crlStage,
				),
				removeRetainedMigrationPath(
					trustStage,
				),
				removeRetainedMigrationPath(
					trustBackup,
				),
				rollbackDirectories(),
			)
		}

	if err :=
		verifyApproval2PersistedCRL(
			destinationCRLPath,
			sourceCRL.Raw,
			expectedCRLSHA256,
		); err != nil {
		return nil, errors.Join(
			err,
			rollbackActivated(),
		)
	}

	activatedTrust, err :=
		config.LoadTransportTrust(
			trustPath,
		)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"verify activated retained transport-trust migration: %w",
				err,
			),
			rollbackActivated(),
		)
	}

	if !sameApproval2TransportTrustConfig(
		activatedTrust,
		migratedTrust,
	) {
		return nil, errors.Join(
			errors.New(
				"activated retained transport-trust migration does not match expected configuration",
			),
			rollbackActivated(),
		)
	}

	if err :=
		os.Remove(
			trustBackup,
		); err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"remove retained transport-trust forward backup: %w",
				err,
			),
			rollbackActivated(),
		)
	}

	return func() error {
		return errors.Join(
			restoreRetainedTransportTrustConfig(
				trustPath,
				originalTrustBytes,
				originalTrust,
				trustBackup,
				transactionID,
			),
			removeRetainedMigrationPath(
				destinationCRLPath,
			),
			rollbackDirectories(),
		)
	}, nil
}

func restoreRetainedTransportTrustConfig(
	trustPath string,
	originalBytes []byte,
	original config.TransportTrustConfig,
	forwardBackup string,
	transactionID string,
) error {
	if _, err :=
		os.Lstat(
			forwardBackup,
		); err == nil {
		discard :=
			trustPath +
				".fi-rollback-discard-" +
				transactionID

		if err :=
			requireRetainedMigrationAbsent(
				discard,
			); err != nil {
			return err
		}

		if err :=
			transportcrl.ReplaceExistingFileWithBackup(
				trustPath,
				forwardBackup,
				discard,
			); err != nil {
			return fmt.Errorf(
				"restore original FI transport-trust configuration from forward backup: %w",
				err,
			)
		}

		if err :=
			verifyRetainedTransportTrustConfig(
				trustPath,
				originalBytes,
				original,
			); err != nil {
			return errors.Join(
				err,
				removeRetainedMigrationPath(
					discard,
				),
			)
		}

		return removeRetainedMigrationPath(
			discard,
		)
	} else if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		return fmt.Errorf(
			"inspect retained transport-trust forward backup: %w",
			err,
		)
	}

	stage :=
		trustPath +
			".fi-rollback-" +
			transactionID

	discard :=
		trustPath +
			".fi-rollback-discard-" +
			transactionID

	for _, path := range []string{
		stage,
		discard,
	} {
		if err :=
			requireRetainedMigrationAbsent(
				path,
			); err != nil {
			return err
		}
	}

	if err :=
		writeApproval2ExclusiveFile(
			stage,
			originalBytes,
		); err != nil {
		return err
	}

	staged, err :=
		config.LoadTransportTrust(
			stage,
		)
	if err != nil {
		return errors.Join(
			fmt.Errorf(
				"verify staged retained transport-trust rollback: %w",
				err,
			),
			removeRetainedMigrationPath(
				stage,
			),
		)
	}

	if !sameApproval2TransportTrustConfig(
		staged,
		original,
	) {
		return errors.Join(
			errors.New(
				"staged retained transport-trust rollback does not match original configuration",
			),
			removeRetainedMigrationPath(
				stage,
			),
		)
	}

	if err :=
		transportcrl.ReplaceExistingFileWithBackup(
			trustPath,
			stage,
			discard,
		); err != nil {
		return errors.Join(
			fmt.Errorf(
				"restore original FI transport-trust configuration: %w",
				err,
			),
			removeRetainedMigrationPath(
				stage,
			),
		)
	}

	if err :=
		verifyRetainedTransportTrustConfig(
			trustPath,
			originalBytes,
			original,
		); err != nil {
		return errors.Join(
			err,
			removeRetainedMigrationPath(
				discard,
			),
		)
	}

	return removeRetainedMigrationPath(
		discard,
	)
}

func verifyRetainedTransportTrustConfig(
	path string,
	expectedBytes []byte,
	expected config.TransportTrustConfig,
) error {
	observedBytes, err :=
		os.ReadFile(
			path,
		)
	if err != nil {
		return fmt.Errorf(
			"read restored FI transport-trust configuration: %w",
			err,
		)
	}

	if !bytes.Equal(
		observedBytes,
		expectedBytes,
	) {
		return errors.New(
			"restored FI transport-trust bytes do not match original bytes",
		)
	}

	observed, err :=
		config.ParseTransportTrust(
			bytes.NewReader(
				observedBytes,
			),
		)
	if err != nil {
		return fmt.Errorf(
			"parse restored FI transport-trust configuration: %w",
			err,
		)
	}

	if !sameApproval2TransportTrustConfig(
		observed,
		expected,
	) {
		return errors.New(
			"restored FI transport-trust configuration does not match original authority",
		)
	}

	return nil
}

func requireRetainedMigrationRegularFile(
	path string,
) error {
	info, err :=
		os.Lstat(
			path,
		)
	if err != nil {
		return fmt.Errorf(
			"inspect retained migration file %s: %w",
			path,
			err,
		)
	}

	if info.Mode()&
		os.ModeSymlink != 0 {
		return fmt.Errorf(
			"retained migration file must not be a symbolic link: %s",
			path,
		)
	}

	if !info.Mode().
		IsRegular() {
		return fmt.Errorf(
			"retained migration file must be regular: %s",
			path,
		)
	}

	return nil
}

func requireRetainedMigrationAbsent(
	path string,
) error {
	_, err :=
		os.Lstat(
			path,
		)

	switch {
	case errors.Is(
		err,
		os.ErrNotExist,
	):
		return nil

	case err != nil:
		return fmt.Errorf(
			"inspect retained migration destination %s: %w",
			path,
			err,
		)

	default:
		return fmt.Errorf(
			"retained migration destination already exists: %s",
			path,
		)
	}
}

func removeRetainedMigrationPath(
	path string,
) error {
	err :=
		os.Remove(
			path,
		)

	if err == nil ||
		errors.Is(
			err,
			os.ErrNotExist,
		) {
		return nil
	}

	return fmt.Errorf(
		"remove retained migration path %s: %w",
		path,
		err,
	)
}
