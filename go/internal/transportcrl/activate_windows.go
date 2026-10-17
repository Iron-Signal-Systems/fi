// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportcrl

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
)

type ActivationResult struct {
	Activated  bool
	BackupPath string
	FailedPath string
	Reason     string
}

type activationDependencies struct {
	beforeFinalCheck func() error
	replace          func(string, string, string) error
	verify           func(string, []byte, string) error
}

func ActivateCandidate(
	activePath string,
	candidateDER []byte,
	issuer *x509.Certificate,
	leaf *x509.Certificate,
	at time.Time,
	transactionID string,
) (ActivationResult, error) {
	return activateCandidateWithDependencies(
		activePath,
		candidateDER,
		issuer,
		leaf,
		at,
		transactionID,
		activationDependencies{
			replace: ReplaceExistingFileWithBackup,
			verify:  VerifyPersistedPEM,
		},
	)
}

func activateCandidateWithDependencies(
	activePath string,
	candidateDER []byte,
	issuer *x509.Certificate,
	leaf *x509.Certificate,
	at time.Time,
	transactionID string,
	dependencies activationDependencies,
) (ActivationResult, error) {
	if dependencies.replace == nil {
		return ActivationResult{}, errors.New(
			"transport CRL replacement operation is required",
		)
	}

	if dependencies.verify == nil {
		return ActivationResult{}, errors.New(
			"transport CRL persisted-file verifier is required",
		)
	}

	transactionID, err :=
		validateActivationTransactionID(
			transactionID,
		)
	if err != nil {
		return ActivationResult{}, err
	}

	if err := requireRegularReplacementFile(
		"active",
		activePath,
	); err != nil {
		return ActivationResult{}, err
	}
	current, err := receivertrust.LoadCRL(
		activePath,
	)
	if err != nil {
		return ActivationResult{}, fmt.Errorf(
			"load active transport CRL %s: %w",
			activePath,
			err,
		)
	}

	if err := validateCurrentActivationBaseline(
		current,
		issuer,
		at,
	); err != nil {
		return ActivationResult{}, err
	}

	candidate, err := ValidateDER(
		candidateDER,
		issuer,
		leaf,
		at,
	)
	if err != nil {
		return ActivationResult{}, fmt.Errorf(
			"validate candidate transport CRL: %w",
			err,
		)
	}

	decision, err := AssessReplacement(
		current,
		candidate,
	)
	if err != nil {
		return ActivationResult{}, fmt.Errorf(
			"assess transport CRL replacement: %w",
			err,
		)
	}

	if !decision.Activate {
		return ActivationResult{
			Activated: false,
			Reason:    decision.Reason,
		}, nil
	}

	candidatePEM, err := EncodeCanonicalPEM(
		candidateDER,
	)
	if err != nil {
		return ActivationResult{}, err
	}

	candidateDigest := sha256.Sum256(
		candidateDER,
	)

	candidateSHA256 := hex.EncodeToString(
		candidateDigest[:],
	)

	currentDER := append(
		[]byte(nil),
		current.Raw...,
	)

	currentDigest := sha256.Sum256(
		currentDER,
	)

	currentSHA256 := hex.EncodeToString(
		currentDigest[:],
	)

	stagePath :=
		activePath +
			".fi-new-" +
			transactionID

	backupPath :=
		activePath +
			".fi-backup-" +
			transactionID

	failedPath :=
		activePath +
			".fi-failed-" +
			transactionID

	result := ActivationResult{
		Activated:  false,
		BackupPath: backupPath,
		FailedPath: failedPath,
		Reason:     decision.Reason,
	}

	if err := requireActivationDestinationAbsent(
		"stage",
		stagePath,
	); err != nil {
		return ActivationResult{}, err
	}

	if err := requireActivationDestinationAbsent(
		"backup",
		backupPath,
	); err != nil {
		return ActivationResult{}, err
	}

	if err := requireActivationDestinationAbsent(
		"failed",
		failedPath,
	); err != nil {
		return ActivationResult{}, err
	}

	if err := writeActivationStage(
		stagePath,
		candidatePEM,
	); err != nil {
		return ActivationResult{}, err
	}

	stageExists := true

	defer func() {
		if stageExists {
			_ = os.Remove(
				stagePath,
			)
		}
	}()

	if err := dependencies.verify(
		stagePath,
		candidateDER,
		candidateSHA256,
	); err != nil {
		return ActivationResult{}, fmt.Errorf(
			"verify staged transport CRL: %w",
			err,
		)
	}

	if dependencies.beforeFinalCheck != nil {
		if err := dependencies.beforeFinalCheck(); err != nil {
			return ActivationResult{}, fmt.Errorf(
				"transport CRL activation pre-replacement hook: %w",
				err,
			)
		}
	}

	currentBeforeReplace, err :=
		receivertrust.LoadCRL(
			activePath,
		)
	if err != nil {
		return ActivationResult{}, fmt.Errorf(
			"re-read active transport CRL immediately before replacement: %w",
			err,
		)
	}

	if !bytes.Equal(
		currentBeforeReplace.Raw,
		currentDER,
	) {
		return ActivationResult{}, errors.New(
			"active transport CRL changed after replacement assessment; candidate activation refused",
		)
	}

	if err := validateCurrentActivationBaseline(
		currentBeforeReplace,
		issuer,
		at,
	); err != nil {
		return ActivationResult{}, fmt.Errorf(
			"revalidate active transport CRL immediately before replacement: %w",
			err,
		)
	}

	decisionBeforeReplace, err :=
		AssessReplacement(
			currentBeforeReplace,
			candidate,
		)
	if err != nil {
		return ActivationResult{}, fmt.Errorf(
			"reassess transport CRL replacement immediately before activation: %w",
			err,
		)
	}

	if !decisionBeforeReplace.Activate {
		return ActivationResult{
			Activated: false,
			Reason:    decisionBeforeReplace.Reason,
		}, nil
	}

	if err := dependencies.replace(
		activePath,
		stagePath,
		backupPath,
	); err != nil {
		return ActivationResult{}, fmt.Errorf(
			"atomically activate candidate transport CRL: %w",
			err,
		)
	}

	stageExists = false

	if err := dependencies.verify(
		activePath,
		candidateDER,
		candidateSHA256,
	); err != nil {
		activationErr := fmt.Errorf(
			"verify activated candidate transport CRL: %w",
			err,
		)

		if rollbackErr := dependencies.replace(
			activePath,
			backupPath,
			failedPath,
		); rollbackErr != nil {
			return result, errors.Join(
				activationErr,
				fmt.Errorf(
					"restore previous transport CRL after activation verification failure: %w",
					rollbackErr,
				),
			)
		}

		if restoreErr := dependencies.verify(
			activePath,
			currentDER,
			currentSHA256,
		); restoreErr != nil {
			return result, errors.Join(
				activationErr,
				fmt.Errorf(
					"verify restored previous transport CRL: %w",
					restoreErr,
				),
			)
		}

		return result, fmt.Errorf(
			"candidate transport CRL failed post-activation verification; previous CRL restored and failed candidate preserved at %s: %w",
			failedPath,
			err,
		)
	}

	result.Activated = true
	result.FailedPath = ""

	return result, nil
}

func validateActivationTransactionID(
	value string,
) (string, error) {
	value = strings.TrimSpace(
		value,
	)

	if value == "" {
		return "", errors.New(
			"transport CRL activation transaction ID is required",
		)
	}

	for _, current := range value {
		if current >= 'a' &&
			current <= 'z' {
			continue
		}

		if current >= 'A' &&
			current <= 'Z' {
			continue
		}

		if current >= '0' &&
			current <= '9' {
			continue
		}

		switch current {
		case '-', '_':
			continue

		default:
			return "", fmt.Errorf(
				"transport CRL activation transaction ID contains unsupported character %q",
				current,
			)
		}
	}

	return value, nil
}

func validateCurrentActivationBaseline(
	current *x509.RevocationList,
	issuer *x509.Certificate,
	at time.Time,
) error {
	if current == nil {
		return errors.New(
			"active transport CRL is required",
		)
	}

	if issuer == nil {
		return errors.New(
			"transport CRL issuer certificate is required",
		)
	}

	if at.IsZero() {
		return errors.New(
			"transport CRL activation time is required",
		)
	}

	if !bytes.Equal(
		current.RawIssuer,
		issuer.RawSubject,
	) {
		return errors.New(
			"active transport CRL issuer does not match pinned issuer",
		)
	}

	if err := current.CheckSignatureFrom(
		issuer,
	); err != nil {
		return fmt.Errorf(
			"active transport CRL signature validation failed: %w",
			err,
		)
	}

	if current.ThisUpdate.IsZero() {
		return errors.New(
			"active transport CRL thisUpdate is missing",
		)
	}

	if current.ThisUpdate.After(
		at,
	) {
		return fmt.Errorf(
			"active transport CRL is not yet valid: thisUpdate=%s",
			current.ThisUpdate.UTC().Format(
				time.RFC3339,
			),
		)
	}

	// Deliberately do not require NextUpdate to be later than "at".
	// An authentic expired active CRL must remain replaceable by a
	// newer valid CRL. Its signature, issuer, chronology metadata,
	// and base-CRL status still must be trustworthy.
	if current.NextUpdate.IsZero() {
		return errors.New(
			"active transport CRL nextUpdate is missing",
		)
	}

	if err := RejectDeltaCRL(
		current,
	); err != nil {
		return fmt.Errorf(
			"active transport CRL is not an FI-supported base CRL: %w",
			err,
		)
	}

	return nil
}
func requireActivationDestinationAbsent(
	name string,
	path string,
) error {
	_, err := os.Lstat(
		path,
	)

	if err == nil {
		return fmt.Errorf(
			"transport CRL activation %s path already exists: %s",
			name,
			path,
		)
	}

	if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		return fmt.Errorf(
			"inspect transport CRL activation %s path %s: %w",
			name,
			path,
			err,
		)
	}

	return nil
}

func writeActivationStage(
	path string,
	value []byte,
) error {
	file, err := os.OpenFile(
		path,
		os.O_WRONLY|
			os.O_CREATE|
			os.O_EXCL,
		0600,
	)
	if err != nil {
		return fmt.Errorf(
			"create transport CRL activation stage %s: %w",
			path,
			err,
		)
	}

	remove := true

	defer func() {
		_ = file.Close()

		if remove {
			_ = os.Remove(
				path,
			)
		}
	}()

	if _, err := file.Write(
		value,
	); err != nil {
		return fmt.Errorf(
			"write transport CRL activation stage %s: %w",
			path,
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"flush transport CRL activation stage %s: %w",
			path,
			err,
		)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close transport CRL activation stage %s: %w",
			path,
			err,
		)
	}

	remove = false

	return nil
}
