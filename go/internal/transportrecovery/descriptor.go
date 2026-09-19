// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportrecovery

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
	DescriptorVersion              = "fi-recovery-bundle/0.1"
	SignedRecoveryVersion          = "fi-signed-recovery/0.1"
	recoverySignatureDomain        = "FI-RECOVERY-SIGNATURE-V1"
	maxRecoverySignatureBytes      = 16 * 1024
	maxRecoveryCertificateDERBytes = 128 * 1024
)

// Descriptor binds one exact ordered set of published FI Phase 1 batches to one
// encoded recovery representation. Original member identities remain
// independently described by the signed member index.
type Descriptor struct {
	Version           string `json:"version"`
	SourceID          string `json:"source_id"`
	RecoveryID        string `json:"recovery_id"`
	MemberCount       uint64 `json:"member_count"`
	RecordCount       uint64 `json:"record_count"`
	CanonicalBytes    uint64 `json:"canonical_bytes"`
	CanonicalSHA256   string `json:"canonical_sha256"`
	DataEncoding      string `json:"data_encoding"`
	EncodedDataBytes  uint64 `json:"encoded_data_bytes"`
	EncodedDataSHA256 string `json:"encoded_data_sha256"`
	IndexSHA256       string `json:"index_sha256"`
	FirstBatchID      string `json:"first_batch_id"`
	LastBatchID       string `json:"last_batch_id"`
}

// SignedRecovery contains the recovery descriptor, its FI Batch Signing
// certificate and the RSA-PSS signature over the recovery-specific signature
// input. The existing batch-signing PKI role is reused; the signed domain is not.
type SignedRecovery struct {
	Version                    string     `json:"version"`
	Descriptor                 Descriptor `json:"descriptor"`
	Signature                  []byte     `json:"signature"`
	BatchSigningCertificateDER []byte     `json:"batch_signing_certificate_der"`
}

func (descriptor Descriptor) SignatureInput() ([]byte, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}

	canonicalDigest, _ := hex.DecodeString(descriptor.CanonicalSHA256)
	encodedDigest, _ := hex.DecodeString(descriptor.EncodedDataSHA256)
	indexDigest, _ := hex.DecodeString(descriptor.IndexSHA256)

	value := make([]byte, 0, 256+len(descriptor.SourceID)+len(descriptor.RecoveryID)+len(descriptor.FirstBatchID)+len(descriptor.LastBatchID)+len(descriptor.DataEncoding))
	value = append(value, recoverySignatureDomain...)
	value = append(value, 0)
	value = appendLengthPrefixed(value, descriptor.Version)
	value = appendLengthPrefixed(value, descriptor.SourceID)
	value = appendLengthPrefixed(value, descriptor.RecoveryID)
	value = appendLengthPrefixed(value, descriptor.DataEncoding)
	value = appendLengthPrefixed(value, descriptor.FirstBatchID)
	value = appendLengthPrefixed(value, descriptor.LastBatchID)
	value = binary.BigEndian.AppendUint64(value, descriptor.MemberCount)
	value = binary.BigEndian.AppendUint64(value, descriptor.RecordCount)
	value = binary.BigEndian.AppendUint64(value, descriptor.CanonicalBytes)
	value = binary.BigEndian.AppendUint64(value, descriptor.EncodedDataBytes)
	value = append(value, canonicalDigest...)
	value = append(value, encodedDigest...)
	value = append(value, indexDigest...)
	return value, nil
}

func (descriptor Descriptor) Validate() error {
	if descriptor.Version != DescriptorVersion {
		return fmt.Errorf("recovery descriptor version must be %q, got %q", DescriptorVersion, descriptor.Version)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "source ID", value: descriptor.SourceID},
		{name: "recovery ID", value: descriptor.RecoveryID},
		{name: "first batch ID", value: descriptor.FirstBatchID},
		{name: "last batch ID", value: descriptor.LastBatchID},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
		if !utf8.ValidString(field.value) {
			return fmt.Errorf("%s is not valid UTF-8", field.name)
		}
		if len(field.value) > 4096 {
			return fmt.Errorf("%s exceeds 4096 bytes", field.name)
		}
		if strings.ContainsAny(field.value, "\x00\r\n") {
			return fmt.Errorf("%s contains prohibited control characters", field.name)
		}
	}
	if descriptor.FirstBatchID > descriptor.LastBatchID {
		return errors.New("recovery descriptor batch range is not oldest-first")
	}
	if descriptor.MemberCount == 0 || descriptor.MemberCount > maxRecoveryMembers {
		return fmt.Errorf("recovery descriptor member count must be between 1 and %d", maxRecoveryMembers)
	}
	if descriptor.RecordCount == 0 {
		return errors.New("recovery record count must be greater than zero")
	}
	if descriptor.CanonicalBytes == 0 || descriptor.CanonicalBytes > maxSignedStreamingBytes {
		return errors.New("recovery canonical byte count is outside supported streaming bounds")
	}
	if descriptor.DataEncoding != transportencoding.DataEncodingZstd {
		return fmt.Errorf("recovery data encoding must be %q, got %q", transportencoding.DataEncodingZstd, descriptor.DataEncoding)
	}
	if descriptor.EncodedDataBytes == 0 || descriptor.EncodedDataBytes > maxSignedStreamingBytes {
		return errors.New("recovery encoded byte count is outside supported streaming bounds")
	}
	if err := validateSHA256("canonical SHA-256", descriptor.CanonicalSHA256); err != nil {
		return err
	}
	if err := validateSHA256("encoded SHA-256", descriptor.EncodedDataSHA256); err != nil {
		return err
	}
	if err := validateSHA256("member index SHA-256", descriptor.IndexSHA256); err != nil {
		return err
	}
	return nil
}

func NewSignedRecovery(descriptor Descriptor, certificate *x509.Certificate, signer crypto.Signer) (SignedRecovery, error) {
	if err := descriptor.Validate(); err != nil {
		return SignedRecovery{}, fmt.Errorf("validate recovery descriptor: %w", err)
	}
	if certificate == nil || len(certificate.Raw) == 0 {
		return SignedRecovery{}, errors.New("batch-signing certificate DER is required")
	}
	if len(certificate.Raw) > maxRecoveryCertificateDERBytes {
		return SignedRecovery{}, fmt.Errorf("batch-signing certificate DER exceeds %d bytes", maxRecoveryCertificateDERBytes)
	}
	if signer == nil {
		return SignedRecovery{}, errors.New("batch signer is required")
	}

	parsed, err := x509.ParseCertificate(certificate.Raw)
	if err != nil {
		return SignedRecovery{}, fmt.Errorf("parse batch-signing certificate DER: %w", err)
	}
	if err := validateRecoveryCertificateRole(descriptor, parsed); err != nil {
		return SignedRecovery{}, err
	}
	certificateKey, ok := parsed.PublicKey.(*rsa.PublicKey)
	if !ok || certificateKey == nil {
		return SignedRecovery{}, errors.New("batch-signing certificate RSA public key is required")
	}
	signerKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok || signerKey == nil || signerKey.E != certificateKey.E || signerKey.N.Cmp(certificateKey.N) != 0 {
		return SignedRecovery{}, errors.New("batch signer public key does not match batch-signing certificate")
	}

	input, err := descriptor.SignatureInput()
	if err != nil {
		return SignedRecovery{}, err
	}
	digest := sha256.Sum256(input)
	options := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, err := signer.Sign(rand.Reader, digest[:], options)
	if err != nil {
		return SignedRecovery{}, fmt.Errorf("sign FI recovery descriptor using %s: %w", transporttrust.BatchSignatureAlgorithm, err)
	}
	if len(signature) == 0 || len(signature) > maxRecoverySignatureBytes {
		return SignedRecovery{}, errors.New("recovery signature length is invalid")
	}
	if err := rsa.VerifyPSS(certificateKey, crypto.SHA256, digest[:], signature, options); err != nil {
		return SignedRecovery{}, fmt.Errorf("verify newly-created FI recovery signature: %w", err)
	}

	value := SignedRecovery{
		Version:                    SignedRecoveryVersion,
		Descriptor:                 descriptor,
		Signature:                  append([]byte(nil), signature...),
		BatchSigningCertificateDER: append([]byte(nil), parsed.Raw...),
	}
	if err := value.Validate(); err != nil {
		return SignedRecovery{}, err
	}
	return value, nil
}

func (value SignedRecovery) Validate() error {
	if value.Version != SignedRecoveryVersion {
		return fmt.Errorf("signed recovery version must be %q, got %q", SignedRecoveryVersion, value.Version)
	}
	if err := value.Descriptor.Validate(); err != nil {
		return fmt.Errorf("validate signed recovery descriptor: %w", err)
	}
	if len(value.Signature) == 0 || len(value.Signature) > maxRecoverySignatureBytes {
		return errors.New("signed recovery signature length is invalid")
	}
	if len(value.BatchSigningCertificateDER) == 0 || len(value.BatchSigningCertificateDER) > maxRecoveryCertificateDERBytes {
		return errors.New("signed recovery certificate DER length is invalid")
	}
	certificate, err := x509.ParseCertificate(value.BatchSigningCertificateDER)
	if err != nil {
		return fmt.Errorf("parse signed recovery certificate DER: %w", err)
	}
	return validateRecoveryCertificateRole(value.Descriptor, certificate)
}

func (value SignedRecovery) BatchSigningCertificate() (*x509.Certificate, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(value.BatchSigningCertificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse signed recovery certificate DER: %w", err)
	}
	return certificate, nil
}

func VerifySignedRecoverySignature(value SignedRecovery, publicKey *rsa.PublicKey) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if publicKey == nil {
		return errors.New("recovery RSA public key is required")
	}
	input, err := value.Descriptor.SignatureInput()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(input)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], value.Signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}); err != nil {
		return fmt.Errorf("recovery signature verification failed using %s: %w", transporttrust.BatchSignatureAlgorithm, err)
	}
	return nil
}

func appendLengthPrefixed(value []byte, field string) []byte {
	value = binary.BigEndian.AppendUint32(value, uint32(len(field)))
	return append(value, field...)
}

func validateRecoveryCertificateRole(descriptor Descriptor, certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("batch-signing certificate is required")
	}
	if certificate.IsCA {
		return errors.New("batch-signing certificate must not be a CA")
	}
	if len(certificate.Subject.OrganizationalUnit) != 1 || certificate.Subject.OrganizationalUnit[0] != transporttrust.BatchSigningOrganizationalUnit {
		return fmt.Errorf("batch-signing certificate organizational unit must be exactly %q", transporttrust.BatchSigningOrganizationalUnit)
	}
	if !strings.EqualFold(certificate.Subject.CommonName, descriptor.SourceID) {
		return fmt.Errorf("batch-signing certificate common name %q does not match source ID %q", certificate.Subject.CommonName, descriptor.SourceID)
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("batch-signing certificate does not permit digital signatures")
	}
	if publicKey, ok := certificate.PublicKey.(*rsa.PublicKey); !ok || publicKey == nil {
		return fmt.Errorf("batch-signing certificate public key must be RSA for %s", transporttrust.BatchSignatureAlgorithm)
	}
	return nil
}

func validateSHA256(name, value string) error {
	if len(value) != 64 || value != strings.ToLower(value) {
		return fmt.Errorf("%s must contain exactly 64 lowercase hexadecimal characters", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s must contain exactly 64 lowercase hexadecimal characters", name)
	}
	return nil
}
