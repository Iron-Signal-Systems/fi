// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportpackage

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

const (
	MaxBatchSignatureBytes             = 16 * 1024
	MaxBatchSigningCertificateDERBytes = 128 * 1024
	SignedBatchVersion                 = "fi-signed-batch/0.1"
)

// SignedBatch binds one validated Phase 2 transport descriptor to the exact FI
// Batch Signing certificate and signature used by the source.
//
// SignedBatch is an in-memory package contract. Wire framing is deliberately
// separate so framing changes cannot silently redefine the signed identity.
type SignedBatch struct {
	Version                    string
	Descriptor                 transportbatch.Descriptor
	Signature                  []byte
	BatchSigningCertificateDER []byte
}

// BatchSigningCertificate parses and validates the certificate carried by the
// signed batch package. Full chain, revocation, and enrollment authorization
// remain receiver trust responsibilities.
func (value SignedBatch) BatchSigningCertificate() (*x509.Certificate, error) {
	if len(value.BatchSigningCertificateDER) == 0 {
		return nil, errors.New("batch-signing certificate DER is required")
	}
	if len(value.BatchSigningCertificateDER) > MaxBatchSigningCertificateDERBytes {
		return nil, fmt.Errorf(
			"batch-signing certificate DER exceeds %d bytes",
			MaxBatchSigningCertificateDERBytes,
		)
	}

	certificate, err := x509.ParseCertificate(value.BatchSigningCertificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse batch-signing certificate DER: %w", err)
	}

	if err := validateBatchSigningCertificateRole(value.Descriptor, certificate); err != nil {
		return nil, err
	}

	return certificate, nil
}

// NewSignedBatch constructs one signed Phase 2 batch package from a validated
// transport descriptor, the source Batch Signing certificate, and its private
// key signer.
//
// The supplied certificate is re-parsed from its DER bytes before use so
// mutable in-memory certificate fields cannot diverge from the certificate that
// will actually travel with the package.
func NewSignedBatch(
	descriptor transportbatch.Descriptor,
	certificate *x509.Certificate,
	signer crypto.Signer,
) (SignedBatch, error) {
	if err := descriptor.Validate(); err != nil {
		return SignedBatch{}, fmt.Errorf("validate transport descriptor: %w", err)
	}
	if certificate == nil {
		return SignedBatch{}, errors.New("batch-signing certificate is required")
	}
	if len(certificate.Raw) == 0 {
		return SignedBatch{}, errors.New("batch-signing certificate DER is required")
	}
	if len(certificate.Raw) > MaxBatchSigningCertificateDERBytes {
		return SignedBatch{}, fmt.Errorf(
			"batch-signing certificate DER exceeds %d bytes",
			MaxBatchSigningCertificateDERBytes,
		)
	}
	if signer == nil {
		return SignedBatch{}, errors.New("batch signer is required")
	}

	parsedCertificate, err := x509.ParseCertificate(certificate.Raw)
	if err != nil {
		return SignedBatch{}, fmt.Errorf("parse batch-signing certificate DER: %w", err)
	}
	if err := validateBatchSigningCertificateRole(descriptor, parsedCertificate); err != nil {
		return SignedBatch{}, err
	}
	if err := validateSignerMatchesCertificate(signer, parsedCertificate); err != nil {
		return SignedBatch{}, err
	}

	signature, err := transporttrust.SignBatchDescriptor(descriptor, signer)
	if err != nil {
		return SignedBatch{}, err
	}
	if len(signature) > MaxBatchSignatureBytes {
		return SignedBatch{}, fmt.Errorf(
			"batch signature exceeds %d bytes",
			MaxBatchSignatureBytes,
		)
	}

	value := SignedBatch{
		Version:                    SignedBatchVersion,
		Descriptor:                 descriptor,
		Signature:                  append([]byte(nil), signature...),
		BatchSigningCertificateDER: append([]byte(nil), parsedCertificate.Raw...),
	}

	if err := value.Validate(); err != nil {
		return SignedBatch{}, fmt.Errorf("validate signed batch package: %w", err)
	}

	return value, nil
}

// Validate verifies the bounded structural contract of one signed batch
// package. Cryptographic chain, revocation, enrollment, and signature
// authorization are performed by the receiver trust verifier.
func (value SignedBatch) Validate() error {
	if value.Version != SignedBatchVersion {
		return fmt.Errorf(
			"signed batch version must be %q, got %q",
			SignedBatchVersion,
			value.Version,
		)
	}

	if err := value.Descriptor.Validate(); err != nil {
		return fmt.Errorf("validate transport descriptor: %w", err)
	}

	if len(value.Signature) == 0 {
		return errors.New("batch signature is required")
	}
	if len(value.Signature) > MaxBatchSignatureBytes {
		return fmt.Errorf(
			"batch signature exceeds %d bytes",
			MaxBatchSignatureBytes,
		)
	}

	if _, err := value.BatchSigningCertificate(); err != nil {
		return err
	}

	return nil
}

func validateBatchSigningCertificateRole(
	descriptor transportbatch.Descriptor,
	certificate *x509.Certificate,
) error {
	if certificate.IsCA {
		return errors.New("batch-signing certificate must not be a CA")
	}
	if len(certificate.Subject.OrganizationalUnit) != 1 {
		return fmt.Errorf(
			"batch-signing certificate must contain exactly one organizational unit, got %d",
			len(certificate.Subject.OrganizationalUnit),
		)
	}
	if certificate.Subject.OrganizationalUnit[0] !=
		transporttrust.BatchSigningOrganizationalUnit {
		return fmt.Errorf(
			"batch-signing certificate organizational unit must be %q, got %q",
			transporttrust.BatchSigningOrganizationalUnit,
			certificate.Subject.OrganizationalUnit[0],
		)
	}
	if !strings.EqualFold(certificate.Subject.CommonName, descriptor.SourceID) {
		return fmt.Errorf(
			"batch-signing certificate common name %q does not match source ID %q",
			certificate.Subject.CommonName,
			descriptor.SourceID,
		)
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New(
			"batch-signing certificate does not permit digital signatures",
		)
	}
	if publicKey, ok := certificate.PublicKey.(*rsa.PublicKey); !ok || publicKey == nil {
		return fmt.Errorf(
			"batch-signing certificate public key must be RSA for %s",
			transporttrust.BatchSignatureAlgorithm,
		)
	}

	return nil
}

func validateSignerMatchesCertificate(
	signer crypto.Signer,
	certificate *x509.Certificate,
) error {
	certificateKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || certificateKey == nil {
		return errors.New("batch-signing certificate RSA public key is required")
	}

	signerKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok || signerKey == nil {
		return fmt.Errorf(
			"batch signer public key must be RSA for %s",
			transporttrust.BatchSignatureAlgorithm,
		)
	}

	if certificateKey.E != signerKey.E || certificateKey.N.Cmp(signerKey.N) != 0 {
		return errors.New(
			"batch signer public key does not match batch-signing certificate",
		)
	}

	return nil
}
