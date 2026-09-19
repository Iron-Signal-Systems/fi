// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

const (
	CanonicalVersion        = "fi-generation-canonical/0.1"
	DescriptorVersion       = "fi-generation-descriptor/0.1"
	SignedGenerationVersion = "fi-signed-generation/0.1"

	generationSignatureDomain = "FI-GENERATION-SIGNATURE-V1"

	maxGenerationCertificateDERBytes = 128 * 1024
	maxGenerationSignatureBytes      = 16 * 1024
	maxGenerationStreamingBytes      = uint64(1<<63 - 1)
)

// Descriptor binds one exact FI frozen-generation representation to one source
// and generation identity.
//
// The descriptor intentionally contains transport facts only. It does not
// interpret collector manifests, batch identities, record counts or other
// batch semantics.
type Descriptor struct {
	Version string `json:"version"`

	SourceID     string `json:"source_id"`
	GenerationID string `json:"generation_id"`

	CanonicalVersion string `json:"canonical_version"`
	DataEncoding     string `json:"data_encoding"`

	ArtifactCount uint64 `json:"artifact_count"`
	SourceBytes   uint64 `json:"source_bytes"`

	CanonicalBytes  uint64 `json:"canonical_bytes"`
	CanonicalSHA256 string `json:"canonical_sha256"`

	EncodedDataBytes  uint64 `json:"encoded_data_bytes"`
	EncodedDataSHA256 string `json:"encoded_data_sha256"`
}

// SignedGeneration contains the generation descriptor, the FI Batch Signing
// certificate and an RSA-PSS signature over the generation-specific signature
// domain.
//
// The existing FI Batch Signing PKI role is reused, but generation signatures
// use a distinct cryptographic domain from batch and recovery signatures.
type SignedGeneration struct {
	Version string `json:"version"`

	Descriptor Descriptor `json:"descriptor"`

	Signature []byte `json:"signature"`

	BatchSigningCertificateDER []byte `json:"batch_signing_certificate_der"`
}

func (descriptor Descriptor) SignatureInput() ([]byte, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}

	canonicalDigest, _ :=
		hex.DecodeString(
			descriptor.CanonicalSHA256,
		)

	encodedDigest, _ :=
		hex.DecodeString(
			descriptor.EncodedDataSHA256,
		)

	value :=
		make(
			[]byte,
			0,
			256+
				len(descriptor.SourceID)+
				len(descriptor.GenerationID)+
				len(descriptor.CanonicalVersion)+
				len(descriptor.DataEncoding),
		)

	value =
		append(
			value,
			generationSignatureDomain...,
		)

	value =
		append(
			value,
			0,
		)

	value =
		appendLengthPrefixed(
			value,
			descriptor.Version,
		)

	value =
		appendLengthPrefixed(
			value,
			descriptor.SourceID,
		)

	value =
		appendLengthPrefixed(
			value,
			descriptor.GenerationID,
		)

	value =
		appendLengthPrefixed(
			value,
			descriptor.CanonicalVersion,
		)

	value =
		appendLengthPrefixed(
			value,
			descriptor.DataEncoding,
		)

	value =
		binary.BigEndian.AppendUint64(
			value,
			descriptor.ArtifactCount,
		)

	value =
		binary.BigEndian.AppendUint64(
			value,
			descriptor.SourceBytes,
		)

	value =
		binary.BigEndian.AppendUint64(
			value,
			descriptor.CanonicalBytes,
		)

	value =
		binary.BigEndian.AppendUint64(
			value,
			descriptor.EncodedDataBytes,
		)

	value =
		append(
			value,
			canonicalDigest...,
		)

	value =
		append(
			value,
			encodedDigest...,
		)

	return value, nil
}

func (descriptor Descriptor) Validate() error {
	if descriptor.Version != DescriptorVersion {
		return fmt.Errorf(
			"generation descriptor version must be %q, got %q",
			DescriptorVersion,
			descriptor.Version,
		)
	}

	if err :=
		validateTextIdentity(
			"source ID",
			descriptor.SourceID,
		); err != nil {
		return err
	}

	if err :=
		validateTextIdentity(
			"generation ID",
			descriptor.GenerationID,
		); err != nil {
		return err
	}

	if strings.ContainsAny(
		descriptor.GenerationID,
		"/\\",
	) {
		return errors.New(
			"generation ID must not contain path separators",
		)
	}

	if descriptor.CanonicalVersion !=
		CanonicalVersion {
		return fmt.Errorf(
			"generation canonical version must be %q, got %q",
			CanonicalVersion,
			descriptor.CanonicalVersion,
		)
	}

	if descriptor.DataEncoding !=
		transportencoding.DataEncodingZstd {
		return fmt.Errorf(
			"generation data encoding must be %q, got %q",
			transportencoding.DataEncodingZstd,
			descriptor.DataEncoding,
		)
	}

	if descriptor.ArtifactCount == 0 {
		return errors.New(
			"generation artifact count must be greater than zero",
		)
	}

	if descriptor.SourceBytes >
		maxGenerationStreamingBytes {
		return errors.New(
			"generation source byte count exceeds supported streaming bounds",
		)
	}

	if descriptor.CanonicalBytes == 0 ||
		descriptor.CanonicalBytes >
			maxGenerationStreamingBytes {
		return errors.New(
			"generation canonical byte count is outside supported streaming bounds",
		)
	}

	if descriptor.EncodedDataBytes == 0 ||
		descriptor.EncodedDataBytes >
			maxGenerationStreamingBytes {
		return errors.New(
			"generation encoded byte count is outside supported streaming bounds",
		)
	}

	if err :=
		validateSHA256(
			"canonical SHA-256",
			descriptor.CanonicalSHA256,
		); err != nil {
		return err
	}

	if err :=
		validateSHA256(
			"encoded SHA-256",
			descriptor.EncodedDataSHA256,
		); err != nil {
		return err
	}

	return nil
}

func NewSignedGeneration(
	descriptor Descriptor,
	certificate *x509.Certificate,
	signer crypto.Signer,
) (SignedGeneration, error) {
	if err :=
		descriptor.Validate(); err != nil {
		return SignedGeneration{},
			fmt.Errorf(
				"validate generation descriptor: %w",
				err,
			)
	}

	if certificate == nil ||
		len(certificate.Raw) == 0 {
		return SignedGeneration{},
			errors.New(
				"batch-signing certificate DER is required",
			)
	}

	if len(certificate.Raw) >
		maxGenerationCertificateDERBytes {
		return SignedGeneration{},
			fmt.Errorf(
				"batch-signing certificate DER exceeds %d bytes",
				maxGenerationCertificateDERBytes,
			)
	}

	if signer == nil {
		return SignedGeneration{},
			errors.New(
				"generation signer is required",
			)
	}

	parsed, err :=
		x509.ParseCertificate(
			certificate.Raw,
		)
	if err != nil {
		return SignedGeneration{},
			fmt.Errorf(
				"parse batch-signing certificate DER: %w",
				err,
			)
	}

	if err :=
		validateGenerationCertificateRole(
			descriptor,
			parsed,
		); err != nil {
		return SignedGeneration{}, err
	}

	certificateKey, ok :=
		parsed.PublicKey.(*rsa.PublicKey)

	if !ok ||
		certificateKey == nil {
		return SignedGeneration{},
			errors.New(
				"batch-signing certificate RSA public key is required",
			)
	}

	signerKey, ok :=
		signer.Public().(*rsa.PublicKey)

	if !ok ||
		signerKey == nil ||
		signerKey.E != certificateKey.E ||
		signerKey.N.Cmp(
			certificateKey.N,
		) != 0 {
		return SignedGeneration{},
			errors.New(
				"generation signer public key does not match batch-signing certificate",
			)
	}

	input, err :=
		descriptor.SignatureInput()
	if err != nil {
		return SignedGeneration{}, err
	}

	digest :=
		sha256.Sum256(
			input,
		)

	options :=
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}

	signature, err :=
		signer.Sign(
			rand.Reader,
			digest[:],
			options,
		)
	if err != nil {
		return SignedGeneration{},
			fmt.Errorf(
				"sign FI generation descriptor using %s: %w",
				transporttrust.BatchSignatureAlgorithm,
				err,
			)
	}

	if len(signature) == 0 ||
		len(signature) >
			maxGenerationSignatureBytes {
		return SignedGeneration{},
			errors.New(
				"generation signature length is invalid",
			)
	}

	if err :=
		rsa.VerifyPSS(
			certificateKey,
			crypto.SHA256,
			digest[:],
			signature,
			options,
		); err != nil {
		return SignedGeneration{},
			fmt.Errorf(
				"verify newly-created FI generation signature: %w",
				err,
			)
	}

	value :=
		SignedGeneration{
			Version:    SignedGenerationVersion,
			Descriptor: descriptor,

			Signature: append(
				[]byte(nil),
				signature...,
			),

			BatchSigningCertificateDER: append(
				[]byte(nil),
				parsed.Raw...,
			),
		}

	if err :=
		value.Validate(); err != nil {
		return SignedGeneration{}, err
	}

	return value, nil
}

func (value SignedGeneration) Validate() error {
	if value.Version !=
		SignedGenerationVersion {
		return fmt.Errorf(
			"signed generation version must be %q, got %q",
			SignedGenerationVersion,
			value.Version,
		)
	}

	if err :=
		value.Descriptor.Validate(); err != nil {
		return fmt.Errorf(
			"validate signed generation descriptor: %w",
			err,
		)
	}

	if len(value.Signature) == 0 ||
		len(value.Signature) >
			maxGenerationSignatureBytes {
		return errors.New(
			"signed generation signature length is invalid",
		)
	}

	if len(value.BatchSigningCertificateDER) == 0 ||
		len(value.BatchSigningCertificateDER) >
			maxGenerationCertificateDERBytes {
		return errors.New(
			"signed generation certificate DER length is invalid",
		)
	}

	certificate, err :=
		x509.ParseCertificate(
			value.BatchSigningCertificateDER,
		)
	if err != nil {
		return fmt.Errorf(
			"parse signed generation certificate DER: %w",
			err,
		)
	}

	return validateGenerationCertificateRole(
		value.Descriptor,
		certificate,
	)
}

func (
	value SignedGeneration,
) BatchSigningCertificate() (
	*x509.Certificate,
	error,
) {
	if err :=
		value.Validate(); err != nil {
		return nil, err
	}

	certificate, err :=
		x509.ParseCertificate(
			value.BatchSigningCertificateDER,
		)
	if err != nil {
		return nil,
			fmt.Errorf(
				"parse signed generation certificate DER: %w",
				err,
			)
	}

	return certificate, nil
}

func VerifySignedGenerationSignature(
	value SignedGeneration,
	publicKey *rsa.PublicKey,
) error {
	if err :=
		value.Validate(); err != nil {
		return err
	}

	if publicKey == nil {
		return errors.New(
			"generation RSA public key is required",
		)
	}

	input, err :=
		value.Descriptor.SignatureInput()
	if err != nil {
		return err
	}

	digest :=
		sha256.Sum256(
			input,
		)

	if err :=
		rsa.VerifyPSS(
			publicKey,
			crypto.SHA256,
			digest[:],
			value.Signature,
			&rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,

				Hash: crypto.SHA256,
			},
		); err != nil {
		return fmt.Errorf(
			"generation signature verification failed using %s: %w",
			transporttrust.BatchSignatureAlgorithm,
			err,
		)
	}

	return nil
}

func appendLengthPrefixed(
	value []byte,
	field string,
) []byte {
	value =
		binary.BigEndian.AppendUint32(
			value,
			uint32(len(field)),
		)

	return append(
		value,
		field...,
	)
}

func validateGenerationCertificateRole(
	descriptor Descriptor,
	certificate *x509.Certificate,
) error {
	if certificate == nil {
		return errors.New(
			"batch-signing certificate is required",
		)
	}

	if certificate.IsCA {
		return errors.New(
			"batch-signing certificate must not be a CA",
		)
	}

	if len(
		certificate.Subject.OrganizationalUnit,
	) != 1 ||
		certificate.Subject.OrganizationalUnit[0] !=
			transporttrust.BatchSigningOrganizationalUnit {
		return fmt.Errorf(
			"batch-signing certificate organizational unit must be exactly %q",
			transporttrust.BatchSigningOrganizationalUnit,
		)
	}

	if !strings.EqualFold(
		certificate.Subject.CommonName,
		descriptor.SourceID,
	) {
		return fmt.Errorf(
			"batch-signing certificate common name %q does not match source ID %q",
			certificate.Subject.CommonName,
			descriptor.SourceID,
		)
	}

	if certificate.KeyUsage&
		x509.KeyUsageDigitalSignature == 0 {
		return errors.New(
			"batch-signing certificate does not permit digital signatures",
		)
	}

	publicKey, ok :=
		certificate.PublicKey.(*rsa.PublicKey)

	if !ok ||
		publicKey == nil {
		return fmt.Errorf(
			"batch-signing certificate public key must be RSA for %s",
			transporttrust.BatchSignatureAlgorithm,
		)
	}

	return nil
}

func validateSHA256(
	name string,
	value string,
) error {
	if len(value) != 64 ||
		value != strings.ToLower(
			value,
		) {
		return fmt.Errorf(
			"%s must contain exactly 64 lowercase hexadecimal characters",
			name,
		)
	}

	decoded, err :=
		hex.DecodeString(
			value,
		)

	if err != nil ||
		len(decoded) != 32 {
		return fmt.Errorf(
			"%s must contain exactly 64 lowercase hexadecimal characters",
			name,
		)
	}

	return nil
}

func validateTextIdentity(
	name string,
	value string,
) error {
	if strings.TrimSpace(
		value,
	) == "" {
		return fmt.Errorf(
			"%s is required",
			name,
		)
	}

	if !utf8.ValidString(
		value,
	) {
		return fmt.Errorf(
			"%s is not valid UTF-8",
			name,
		)
	}

	if len(value) > 4096 {
		return fmt.Errorf(
			"%s exceeds 4096 bytes",
			name,
		)
	}

	if strings.ContainsAny(
		value,
		"\x00\r\n",
	) {
		return fmt.Errorf(
			"%s contains prohibited control characters",
			name,
		)
	}

	return nil
}
