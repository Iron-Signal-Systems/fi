// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

const (
	fiBatchSigningTemplateName    = "FI-Batch-Signing"
	fiTransportClientTemplateName = "FI-Transport-Client"
)

type pkiEnrollmentContract struct {
	ExpectedDNS  string
	TemplateName string
	TemplateOID  string
}

type pkiEnrollmentInvoker func(
	templateName string,
) error

type pkiEnrollmentMutation struct {
	Certificate    localMachinePKICertificate
	Key            cngKeyLocator
	NewMachineKeys []machineCNGKeyState
	Owned          bool
}

func buildOwnedPKIEnrollmentMutation(
	certificate localMachinePKICertificate,
	addedKeys []machineCNGKeyState,
) (
	pkiEnrollmentMutation,
	error,
) {
	mutation := pkiEnrollmentMutation{
		Certificate: certificate,
		NewMachineKeys: append(
			[]machineCNGKeyState(nil),
			addedKeys...,
		),
	}

	locator, err :=
		localMachineCNGKeyLocatorForCertificateSHA256(
			certificate.CertificateSHA256,
		)
	if err != nil {
		return mutation, err
	}

	mutation.Key = locator

	_, found, err :=
		findAddedMachineCNGKeyForLocator(
			locator,
			addedKeys,
		)
	if err != nil {
		return mutation, err
	}

	if !found {
		return mutation, fmt.Errorf(
			"certificate SHA256=%s references CNG key %q, but that exact machine key was not absent before enrollment and newly present afterward; transaction ownership is not established",
			certificate.CertificateSHA256,
			locator.KeyName,
		)
	}

	mutation.Owned = true

	if len(addedKeys) != 1 {
		return mutation, fmt.Errorf(
			"exact certificate/key ownership is established for SHA256=%s key=%q, but %d total machine CNG keys appeared during enrollment; additional key state is not claimed by this transaction",
			certificate.CertificateSHA256,
			locator.KeyName,
			len(addedKeys),
		)
	}

	return mutation, nil
}

func enrollMachineCertificateTemplateTracked(
	contract pkiEnrollmentContract,
) (
	pkiEnrollmentMutation,
	error,
) {
	return enrollMachineCertificateTemplateTrackedWithInvoker(
		contract,
		enrollMachineCertificateTemplate,
	)
}

func enrollMachineCertificateTemplateTrackedWithInvoker(
	contract pkiEnrollmentContract,
	enroll pkiEnrollmentInvoker,
) (
	pkiEnrollmentMutation,
	error,
) {
	if err := validatePKIEnrollmentContract(
		contract,
	); err != nil {
		return pkiEnrollmentMutation{}, err
	}

	if enroll == nil {
		return pkiEnrollmentMutation{}, errors.New(
			"certificate enrollment invoker is required",
		)
	}

	beforeCertificates, err :=
		snapshotLocalMachinePKICertificates(
			contract.TemplateOID,
		)
	if err != nil {
		return pkiEnrollmentMutation{}, fmt.Errorf(
			"snapshot LocalMachine\\MY before %s enrollment: %w",
			contract.TemplateName,
			err,
		)
	}

	beforeKeys, err :=
		snapshotFIMachineCNGKeys()
	if err != nil {
		return pkiEnrollmentMutation{}, fmt.Errorf(
			"snapshot FI machine CNG keys before %s enrollment: %w",
			contract.TemplateName,
			err,
		)
	}

	enrollErr := enroll(
		contract.TemplateName,
	)

	afterCertificates, certificateRediscoveryErr :=
		snapshotLocalMachinePKICertificates(
			contract.TemplateOID,
		)

	afterKeys, keyRediscoveryErr :=
		snapshotFIMachineCNGKeys()

	var addedKeys []machineCNGKeyState

	if keyRediscoveryErr == nil {
		addedKeys = machineCNGKeyStateDifference(
			beforeKeys,
			afterKeys,
		)
	}

	diagnosticMutation := pkiEnrollmentMutation{
		NewMachineKeys: append(
			[]machineCNGKeyState(nil),
			addedKeys...,
		),
	}

	if certificateRediscoveryErr != nil ||
		keyRediscoveryErr != nil {
		switch {
		case certificateRediscoveryErr != nil &&
			keyRediscoveryErr != nil:
			return diagnosticMutation, fmt.Errorf(
				"%s enrollment completed with enrollment_error=%v; post-enrollment certificate rediscovery failed: %v; post-enrollment CNG key rediscovery failed: %v",
				contract.TemplateName,
				enrollErr,
				certificateRediscoveryErr,
				keyRediscoveryErr,
			)

		case certificateRediscoveryErr != nil:
			return diagnosticMutation, fmt.Errorf(
				"%s enrollment completed with enrollment_error=%v; post-enrollment certificate rediscovery failed: %v; new_machine_keys=%d",
				contract.TemplateName,
				enrollErr,
				certificateRediscoveryErr,
				len(addedKeys),
			)

		default:
			return diagnosticMutation, fmt.Errorf(
				"%s enrollment completed with enrollment_error=%v; post-enrollment CNG key rediscovery failed: %v",
				contract.TemplateName,
				enrollErr,
				keyRediscoveryErr,
			)
		}
	}

	addedCertificates := certificateStateDifference(
		beforeCertificates,
		afterCertificates,
	)

	if enrollErr != nil {
		switch len(addedCertificates) {
		case 0:
			return diagnosticMutation, fmt.Errorf(
				"%s enrollment failed without installing a new certificate; new_machine_keys=%d: %w",
				contract.TemplateName,
				len(addedKeys),
				enrollErr,
			)

		case 1:
			mutation, ownershipErr :=
				buildOwnedPKIEnrollmentMutation(
					addedCertificates[0],
					addedKeys,
				)

			if ownershipErr != nil {
				return mutation, fmt.Errorf(
					"%s enrollment returned an error and exactly one new certificate was installed, but exact certificate/key ownership could not be established: %v; enrollment error: %w",
					contract.TemplateName,
					ownershipErr,
					enrollErr,
				)
			}

			return mutation, fmt.Errorf(
				"%s enrollment returned an error but exact ownership is established for certificate SHA256=%s CNG key=%q: %w",
				contract.TemplateName,
				mutation.Certificate.CertificateSHA256,
				mutation.Key.KeyName,
				enrollErr,
			)

		default:
			return diagnosticMutation, fmt.Errorf(
				"%s enrollment returned an error and %d new matching certificates appeared; transaction ownership is ambiguous and automatic rollback is refused; new_machine_keys=%d: %w",
				contract.TemplateName,
				len(addedCertificates),
				len(addedKeys),
				enrollErr,
			)
		}
	}

	switch len(addedCertificates) {
	case 0:
		return diagnosticMutation, fmt.Errorf(
			"%s enrollment returned success but no new certificate matching template OID %s was installed; new_machine_keys=%d",
			contract.TemplateName,
			contract.TemplateOID,
			len(addedKeys),
		)

	case 1:
		mutation, err :=
			buildOwnedPKIEnrollmentMutation(
				addedCertificates[0],
				addedKeys,
			)
		if err != nil {
			return mutation, fmt.Errorf(
				"%s certificate/key ownership verification failed for SHA256=%s: %w",
				contract.TemplateName,
				addedCertificates[0].CertificateSHA256,
				err,
			)
		}

		if err := verifyTrackedPKIEnrollment(
			mutation.Certificate,
			contract,
		); err != nil {
			return mutation, fmt.Errorf(
				"%s post-enrollment verification failed for SHA256=%s: %w",
				contract.TemplateName,
				mutation.Certificate.CertificateSHA256,
				err,
			)
		}

		return mutation, nil

	default:
		return diagnosticMutation, fmt.Errorf(
			"%s enrollment returned success but %d new matching certificates appeared; transaction ownership is ambiguous and automatic rollback is refused; new_machine_keys=%d",
			contract.TemplateName,
			len(addedCertificates),
			len(addedKeys),
		)
	}
}

func validatePKIEnrollmentContract(
	contract pkiEnrollmentContract,
) error {
	if strings.TrimSpace(
		contract.TemplateName,
	) == "" {
		return errors.New(
			"certificate template name is required",
		)
	}

	switch strings.TrimSpace(
		contract.TemplateName,
	) {
	case fiTransportClientTemplateName,
		fiBatchSigningTemplateName:
	default:
		return fmt.Errorf(
			"unsupported FI certificate template %q",
			contract.TemplateName,
		)
	}

	if strings.TrimSpace(
		contract.TemplateOID,
	) == "" {
		return errors.New(
			"certificate template OID is required",
		)
	}

	if strings.TrimSpace(
		contract.ExpectedDNS,
	) == "" {
		return errors.New(
			"expected certificate DNS identity is required",
		)
	}

	return nil
}

func verifyTrackedPKIEnrollment(
	certificate localMachinePKICertificate,
	contract pkiEnrollmentContract,
) error {
	if err := verifyTrackedPKICertificateContract(
		certificate,
		contract,
	); err != nil {
		return err
	}

	if err := verifyLocalMachineCNGPrivateKeyContract(
		certificate.CertificateSHA256,
	); err != nil {
		return err
	}

	if err := verifyLocalMachineCertificateTrust(
		certificate.CertificateSHA256,
	); err != nil {
		return err
	}

	return nil
}

func verifyTrackedPKICertificateContract(
	certificate localMachinePKICertificate,
	contract pkiEnrollmentContract,
) error {
	if !strings.EqualFold(
		certificate.TemplateOID,
		contract.TemplateOID,
	) {
		return fmt.Errorf(
			"template OID expected=%s observed=%s",
			contract.TemplateOID,
			certificate.TemplateOID,
		)
	}

	if !strings.EqualFold(
		certificate.CommonName,
		contract.ExpectedDNS,
	) {
		return fmt.Errorf(
			"certificate common name expected=%s observed=%s",
			contract.ExpectedDNS,
			certificate.CommonName,
		)
	}

	if len(certificate.DNSNames) != 1 ||
		!strings.EqualFold(
			certificate.DNSNames[0],
			contract.ExpectedDNS,
		) {
		return fmt.Errorf(
			"certificate SAN DNS expected exactly [%s] observed=%v",
			contract.ExpectedDNS,
			certificate.DNSNames,
		)
	}

	if strings.TrimSpace(
		certificate.CertificateSHA256,
	) == "" {
		return errors.New(
			"certificate SHA-256 is unavailable",
		)
	}

	if certificate.PublicKeyAlgorithm != x509.RSA {
		return fmt.Errorf(
			"certificate public-key algorithm expected=RSA observed=%v",
			certificate.PublicKeyAlgorithm,
		)
	}

	if certificate.PublicKeyBits < 3072 {
		return fmt.Errorf(
			"certificate RSA key length=%d expected at least 3072",
			certificate.PublicKeyBits,
		)
	}

	switch strings.TrimSpace(
		contract.TemplateName,
	) {
	case fiTransportClientTemplateName:
		expectedKeyUsage :=
			x509.KeyUsageDigitalSignature |
				x509.KeyUsageKeyEncipherment

		if certificate.KeyUsage != expectedKeyUsage {
			return fmt.Errorf(
				"transport certificate key usage observed=0x%X expected=0x%X",
				uint32(certificate.KeyUsage),
				uint32(expectedKeyUsage),
			)
		}

		if !certificate.ExtendedKeyUsagePresent {
			return errors.New(
				"transport certificate is missing the Extended Key Usage extension",
			)
		}

		if len(certificate.ExtKeyUsage) != 1 ||
			certificate.ExtKeyUsage[0] !=
				x509.ExtKeyUsageClientAuth ||
			len(certificate.UnknownExtKeyUsage) != 0 {
			return fmt.Errorf(
				"transport certificate EKU expected exactly Client Authentication; observed_known=%v observed_unknown=%v",
				certificate.ExtKeyUsage,
				certificate.UnknownExtKeyUsage,
			)
		}

	case fiBatchSigningTemplateName:
		if certificate.KeyUsage !=
			x509.KeyUsageDigitalSignature {
			return fmt.Errorf(
				"batch-signing certificate key usage observed=0x%X expected=0x%X",
				uint32(certificate.KeyUsage),
				uint32(
					x509.KeyUsageDigitalSignature,
				),
			)
		}

		if certificate.ExtendedKeyUsagePresent {
			return fmt.Errorf(
				"batch-signing certificate must not contain an Extended Key Usage extension; observed_known=%v observed_unknown=%v",
				certificate.ExtKeyUsage,
				certificate.UnknownExtKeyUsage,
			)
		}

	default:
		return fmt.Errorf(
			"unsupported FI certificate template %q",
			contract.TemplateName,
		)
	}

	return nil
}
