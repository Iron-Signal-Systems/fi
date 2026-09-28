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

type pkiEnrollmentMutation struct {
	Certificate localMachinePKICertificate
	Owned       bool
}

func enrollMachineCertificateTemplateTracked(
	contract pkiEnrollmentContract,
) (
	pkiEnrollmentMutation,
	error,
) {
	if err := validatePKIEnrollmentContract(
		contract,
	); err != nil {
		return pkiEnrollmentMutation{}, err
	}

	before, err := snapshotLocalMachinePKICertificates(
		contract.TemplateOID,
	)
	if err != nil {
		return pkiEnrollmentMutation{}, fmt.Errorf(
			"snapshot LocalMachine\\MY before %s enrollment: %w",
			contract.TemplateName,
			err,
		)
	}

	enrollErr := enrollMachineCertificateTemplate(
		contract.TemplateName,
	)

	after, rediscoverErr := snapshotLocalMachinePKICertificates(
		contract.TemplateOID,
	)
	if rediscoverErr != nil {
		if enrollErr != nil {
			return pkiEnrollmentMutation{}, fmt.Errorf(
				"%s enrollment failed: %v; post-enrollment rediscovery also failed: %w",
				contract.TemplateName,
				enrollErr,
				rediscoverErr,
			)
		}

		return pkiEnrollmentMutation{}, fmt.Errorf(
			"rediscover LocalMachine\\MY after %s enrollment: %w",
			contract.TemplateName,
			rediscoverErr,
		)
	}

	added := certificateStateDifference(
		before,
		after,
	)

	if enrollErr != nil {
		switch len(added) {
		case 0:
			return pkiEnrollmentMutation{}, fmt.Errorf(
				"%s enrollment failed without installing a new certificate: %w",
				contract.TemplateName,
				enrollErr,
			)

		case 1:
			mutation := pkiEnrollmentMutation{
				Certificate: added[0],
				Owned:       true,
			}

			return mutation, fmt.Errorf(
				"%s enrollment returned an error but exactly one new certificate was installed; transaction ownership is established for SHA256=%s: %w",
				contract.TemplateName,
				added[0].CertificateSHA256,
				enrollErr,
			)

		default:
			return pkiEnrollmentMutation{}, fmt.Errorf(
				"%s enrollment returned an error and %d new matching certificates appeared; transaction ownership is ambiguous and automatic rollback is refused: %w",
				contract.TemplateName,
				len(added),
				enrollErr,
			)
		}
	}

	switch len(added) {
	case 0:
		return pkiEnrollmentMutation{}, fmt.Errorf(
			"%s enrollment returned success but no new certificate matching template OID %s was installed",
			contract.TemplateName,
			contract.TemplateOID,
		)

	case 1:
		mutation := pkiEnrollmentMutation{
			Certificate: added[0],
			Owned:       true,
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
		return pkiEnrollmentMutation{}, fmt.Errorf(
			"%s enrollment returned success but %d new matching certificates appeared; transaction ownership is ambiguous and automatic rollback is refused",
			contract.TemplateName,
			len(added),
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
