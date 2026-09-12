// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
)

const BatchSignatureAlgorithm = "rsa-pss-sha256"

// VerifyBatchSigningCertificate verifies the cryptographic and configured FI
// authorization requirements for one presented batch-signing certificate.
//
// The leaf must:
//   - be a non-CA certificate;
//   - be signed by the expected FI Batch Signing Issuing CA;
//   - chain through that issuer to the FI root;
//   - permit digital signatures;
//   - contain exactly the FI Batch Signing organizational unit;
//   - not be revoked by the current FI Batch Signing CRL; and
//   - map to the explicitly configured FI source batch-signing identity.
func VerifyBatchSigningCertificate(
	leaf *x509.Certificate,
	root *x509.Certificate,
	issuer *x509.Certificate,
	crl *x509.RevocationList,
	source SourceAuthorization,
	currentTime time.Time,
) (AuthorizationOutcome, error) {
	if leaf == nil {
		return "", errors.New("batch-signing certificate is required")
	}

	if root == nil {
		return "", errors.New("root certificate is required")
	}

	if issuer == nil {
		return "", errors.New("batch-signing issuing certificate is required")
	}

	if crl == nil {
		return "", errors.New("batch-signing CRL is required")
	}

	if currentTime.IsZero() {
		return "", errors.New("current time is required")
	}

	if leaf.IsCA {
		return "", errors.New("batch-signing certificate must not be a CA")
	}

	if len(leaf.Subject.OrganizationalUnit) != 1 {
		return "", fmt.Errorf(
			"batch-signing certificate must contain exactly one organizational unit, got %d",
			len(leaf.Subject.OrganizationalUnit),
		)
	}

	if leaf.Subject.OrganizationalUnit[0] != BatchSigningOrganizationalUnit {
		return AuthorizationIdentityMismatch, fmt.Errorf(
			"batch-signing certificate organizational unit must be %q, got %q",
			BatchSigningOrganizationalUnit,
			leaf.Subject.OrganizationalUnit[0],
		)
	}

	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return "", fmt.Errorf(
			"batch-signing certificate is not signed by expected FI batch-signing issuer: %w",
			err,
		)
	}

	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return "", errors.New(
			"batch-signing certificate does not permit digital signatures",
		)
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return "", fmt.Errorf(
			"batch-signing CRL signature validation failed: %w",
			err,
		)
	}

	if crl.ThisUpdate.After(currentTime) {
		return "", fmt.Errorf(
			"batch-signing CRL is not yet valid: thisUpdate=%s",
			crl.ThisUpdate.UTC().Format(time.RFC3339),
		)
	}

	if crl.NextUpdate.IsZero() {
		return "", errors.New("batch-signing CRL nextUpdate is required")
	}

	if !crl.NextUpdate.After(currentTime) {
		return "", fmt.Errorf(
			"batch-signing CRL is expired: nextUpdate=%s",
			crl.NextUpdate.UTC().Format(time.RFC3339),
		)
	}

	if certificateIsRevoked(leaf, crl) {
		return "", fmt.Errorf(
			"batch-signing certificate serial %s is revoked",
			leaf.SerialNumber.Text(16),
		)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}); err != nil {
		return "", fmt.Errorf(
			"batch-signing certificate chain validation failed: %w",
			err,
		)
	}

	identity, err := IdentityFromCertificate(leaf, issuer)
	if err != nil {
		return "", fmt.Errorf(
			"derive batch-signing certificate identity: %w",
			err,
		)
	}

	outcome, err := AuthorizeSource(
		source,
		CertificateUseBatchSigning,
		identity,
	)
	if err != nil {
		return "", fmt.Errorf("authorize FI source batch-signing identity: %w", err)
	}

	if outcome != AuthorizationAuthorized {
		return outcome, fmt.Errorf(
			"FI source batch-signing authorization rejected: %s",
			outcome,
		)
	}

	return outcome, nil
}

// VerifySignedBatch verifies one signed FI transport batch descriptor against
// the explicitly enrolled source batch-signing identity.
//
// Version 0.1 uses one fixed signature algorithm: RSA-PSS with SHA-256 and a
// salt length equal to the SHA-256 digest length. Algorithm negotiation is not
// part of this contract; a future algorithm change requires a protocol revision.
func VerifySignedBatch(
	descriptor transportbatch.Descriptor,
	signature []byte,
	leaf *x509.Certificate,
	root *x509.Certificate,
	issuer *x509.Certificate,
	crl *x509.RevocationList,
	source SourceAuthorization,
	currentTime time.Time,
) (AuthorizationOutcome, error) {
	input, err := descriptor.SignatureInput()
	if err != nil {
		return "", fmt.Errorf("construct batch signature input: %w", err)
	}

	if descriptor.SourceID != source.SourceID {
		return AuthorizationIdentityMismatch, fmt.Errorf(
			"batch descriptor source ID %q does not match enrolled source ID %q",
			descriptor.SourceID,
			source.SourceID,
		)
	}

	if len(signature) == 0 {
		return "", errors.New("batch signature is required")
	}

	outcome, err := VerifyBatchSigningCertificate(
		leaf,
		root,
		issuer,
		crl,
		source,
		currentTime,
	)
	if err != nil {
		return outcome, err
	}

	publicKey, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf(
			"batch-signing certificate public key must be RSA for %s",
			BatchSignatureAlgorithm,
		)
	}

	digest := sha256.Sum256(input)
	if err := rsa.VerifyPSS(
		publicKey,
		crypto.SHA256,
		digest[:],
		signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	); err != nil {
		return "", fmt.Errorf(
			"batch signature verification failed using %s: %w",
			BatchSignatureAlgorithm,
			err,
		)
	}

	return outcome, nil
}
