// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const generationRetiredDirectoryPrefix = ".fi-generation-retired-"

// GenerationRetirementAuthorization is produced only after a complete
// recorded/already_recorded acknowledgement matches the exact generation
// transfer sent by this source.
//
// The zero value does not authorize retirement.
type GenerationRetirementAuthorization struct {
	acknowledgement transportgeneration.Acknowledgement
	transfer        transportgeneration.TransferResult
}

// GenerationRetirementDisposition describes the durable source-side namespace
// transition performed after exact receiver recording has been authorized.
type GenerationRetirementDisposition string

const (
	GenerationRetirementDispositionAlreadyRetired GenerationRetirementDisposition = "ALREADY_RETIRED"
	GenerationRetirementDispositionRetired        GenerationRetirementDisposition = "RETIRED"
)

// GenerationRetirementResult identifies the durable retirement tombstone that
// replaced one active sealed generation after an exact recorded acknowledgement.
//
// The tombstone intentionally remains on disk in this slice. It is outside the
// active generation queue and is safe to reap later under a separate verified
// cleanup contract. Keeping namespace retirement separate from byte reclamation
// makes the acknowledgement boundary crash-safe.
type GenerationRetirementResult struct {
	Disposition    GenerationRetirementDisposition
	GenerationID   string
	RetiredPath    string
	SourceID       string
	TransferSHA256 string
}

// GenerationTransportTransactionResult captures the exact generation facts
// reached by one offer -> decision -> transfer -> acknowledgement -> retirement
// transaction.
type GenerationTransportTransactionResult struct {
	Acknowledgement transportgeneration.Acknowledgement
	Decision        transportgeneration.Decision
	Offer           transportgeneration.Offer
	Retirement      GenerationRetirementResult
	Transfer        transportgeneration.TransferResult
}

// Acknowledgement returns the exact generation acknowledgement that produced
// this retirement authorization.
func (value GenerationRetirementAuthorization) Acknowledgement() (transportgeneration.Acknowledgement, error) {
	if err := validateGenerationRetirementAuthorization(value); err != nil {
		return transportgeneration.Acknowledgement{}, err
	}

	return value.acknowledgement, nil
}

// VerifyGenerationAcknowledgement reads one generation acknowledgement and
// binds it to the exact transfer result produced while streaming FIGT0001.
func VerifyGenerationAcknowledgement(
	reader io.Reader,
	transfer transportgeneration.TransferResult,
) (GenerationRetirementAuthorization, error) {
	if reader == nil {
		return GenerationRetirementAuthorization{}, errors.New("FI generation acknowledgement reader is required")
	}

	if err := validateGenerationTransferResult(transfer); err != nil {
		return GenerationRetirementAuthorization{}, err
	}

	acknowledgement, err := transportgeneration.ReadAcknowledgement(reader)
	if err != nil {
		return GenerationRetirementAuthorization{}, fmt.Errorf("read FI generation acknowledgement: %w", err)
	}

	if err := transportgeneration.AcknowledgementMatches(acknowledgement, transfer); err != nil {
		return GenerationRetirementAuthorization{}, fmt.Errorf("match FI generation acknowledgement to exact transfer: %w", err)
	}

	return GenerationRetirementAuthorization{
		acknowledgement: acknowledgement,
		transfer:        transfer,
	}, nil
}

// SendAndRetireTransportGeneration executes the source side of the generation
// protocol against one already-published immutable generation.
//
// Retirement is impossible until the receiver has returned a complete
// recorded/already_recorded acknowledgement matching the exact FIGT transfer.
// Transport failures before that point leave the generation active and
// retryable as the same durable object.
func SendAndRetireTransportGeneration(
	stream io.ReadWriter,
	generation TransportGeneration,
) (GenerationTransportTransactionResult, error) {
	if stream == nil {
		return GenerationTransportTransactionResult{}, errors.New("FI generation transport stream is required")
	}

	offer, err := transportgeneration.OfferFromPublished(generation.Published)
	if err != nil {
		return GenerationTransportTransactionResult{}, fmt.Errorf("construct FI generation offer: %w", err)
	}

	if offer.Descriptor.SourceID != generation.Published.Signed.Descriptor.SourceID ||
		offer.Descriptor.GenerationID != generation.GenerationID {
		return GenerationTransportTransactionResult{}, errors.New("FI generation offer identity does not match queued generation")
	}

	result := GenerationTransportTransactionResult{Offer: offer}

	if err := transportgeneration.WriteOffer(stream, offer); err != nil {
		wrapped := fmt.Errorf("send FI generation offer: %w", err)
		if retryableTransportWriteError(err) {
			return result, fmt.Errorf("%w: %w", ErrRetryableTransport, wrapped)
		}
		return result, wrapped
	}

	decision, err := transportgeneration.ReadDecision(stream)
	if err != nil {
		wrapped := fmt.Errorf("read FI generation decision: %w", err)
		if retryableAcknowledgementReadError(err) {
			return result, fmt.Errorf("%w: %w", ErrRetryableTransport, wrapped)
		}
		return result, wrapped
	}
	result.Decision = decision

	if err := transportgeneration.DecisionMatchesOffer(decision, offer); err != nil {
		return result, fmt.Errorf("validate FI generation decision: %w", err)
	}

	if !decision.Accepted {
		return result, fmt.Errorf("receiver rejected FI generation: %s", decision.Reason)
	}

	transfer, err := SendTransportGeneration(stream, generation)
	if err != nil {
		wrapped := fmt.Errorf("send exact FI generation transfer: %w", err)
		if retryableTransportWriteError(err) {
			return result, fmt.Errorf("%w: %w", ErrRetryableTransport, wrapped)
		}
		return result, wrapped
	}
	result.Transfer = transfer

	authorization, err := VerifyGenerationAcknowledgement(stream, transfer)
	if err != nil {
		wrapped := fmt.Errorf("verify FI generation recorded acknowledgement: %w", err)
		if retryableAcknowledgementReadError(err) {
			return result, fmt.Errorf("%w: %w", ErrRetryableTransport, wrapped)
		}
		return result, wrapped
	}

	acknowledgement, err := authorization.Acknowledgement()
	if err != nil {
		return result, err
	}
	result.Acknowledgement = acknowledgement

	retirement, err := RetireTransportGeneration(generation, authorization)
	result.Retirement = retirement
	if err != nil {
		return result, fmt.Errorf("retire acknowledged FI transport generation: %w", err)
	}

	return result, nil
}

// RetireTransportGeneration durably removes one acknowledged generation from
// the active queue by renaming its directory to a deterministic retirement
// tombstone in the same stage root.
//
// Byte reclamation is intentionally separate. A crash after the durable rename
// cannot make the generation active again, and cleanup can later verify/reap the
// tombstone without weakening the acknowledgement boundary.
func RetireTransportGeneration(
	generation TransportGeneration,
	authorization GenerationRetirementAuthorization,
) (GenerationRetirementResult, error) {
	acknowledgement, err := authorization.Acknowledgement()
	if err != nil {
		return GenerationRetirementResult{}, err
	}

	transfer := authorization.transfer
	if err := validateGenerationForRetirement(generation, transfer, acknowledgement); err != nil {
		return GenerationRetirementResult{}, err
	}

	retiredPath := filepath.Join(
		filepath.Dir(generation.GenerationDir),
		generationRetirementObjectName(transfer),
	)

	result := GenerationRetirementResult{
		Disposition:    GenerationRetirementDispositionRetired,
		GenerationID:   generation.GenerationID,
		RetiredPath:    retiredPath,
		SourceID:       transfer.Descriptor.SourceID,
		TransferSHA256: transfer.TransferSHA256,
	}

	finalInfo, finalErr := os.Lstat(generation.GenerationDir)
	retiredInfo, retiredErr := os.Lstat(retiredPath)

	switch {
	case finalErr == nil && retiredErr == nil:
		return GenerationRetirementResult{}, errors.New("FI generation retirement found both active and retired namespace objects")

	case finalErr == nil:
		if finalInfo.Mode()&os.ModeSymlink != 0 || !finalInfo.IsDir() {
			return GenerationRetirementResult{}, errors.New("FI active generation retirement path must name a real directory")
		}

		current, loadErr := transportgeneration.LoadSealedGeneration(generation.GenerationDir)
		if loadErr != nil {
			return GenerationRetirementResult{}, fmt.Errorf("reload FI generation before retirement: %w", loadErr)
		}

		if !sameTransportGenerationSignedIdentity(current.Signed, generation.Published.Signed) {
			return GenerationRetirementResult{}, errors.New("FI generation signed identity changed before retirement")
		}

		if err := verifyGenerationMetadataIdentity(current.MetadataPath, transfer); err != nil {
			return GenerationRetirementResult{}, err
		}

		if err := publishGenerationDirectory(generation.GenerationDir, retiredPath); err != nil {
			return GenerationRetirementResult{}, fmt.Errorf("publish FI generation retirement tombstone: %w", err)
		}

		return result, nil

	case errors.Is(finalErr, os.ErrNotExist) && retiredErr == nil:
		if retiredInfo.Mode()&os.ModeSymlink != 0 || !retiredInfo.IsDir() {
			return GenerationRetirementResult{}, errors.New("FI generation retirement tombstone must name a real directory")
		}

		if err := verifyRetiredGenerationTombstone(retiredPath, generation, transfer); err != nil {
			return GenerationRetirementResult{}, err
		}

		result.Disposition = GenerationRetirementDispositionAlreadyRetired
		return result, nil

	case errors.Is(finalErr, os.ErrNotExist) && errors.Is(retiredErr, os.ErrNotExist):
		return GenerationRetirementResult{}, errors.New("FI generation retirement found neither active generation nor retirement tombstone")

	case finalErr != nil && !errors.Is(finalErr, os.ErrNotExist):
		return GenerationRetirementResult{}, fmt.Errorf("inspect FI active generation before retirement: %w", finalErr)

	default:
		return GenerationRetirementResult{}, fmt.Errorf("inspect FI generation retirement tombstone: %w", retiredErr)
	}
}

func validateGenerationForRetirement(
	generation TransportGeneration,
	transfer transportgeneration.TransferResult,
	acknowledgement transportgeneration.Acknowledgement,
) error {
	if generation.GenerationDir == "" || generation.GenerationID == "" {
		return errors.New("FI transport generation identity is required for retirement")
	}

	if !filepath.IsAbs(generation.GenerationDir) {
		return errors.New("FI transport generation directory must be absolute for retirement")
	}

	if filepath.Base(filepath.Clean(generation.GenerationDir)) != generationDirectoryPrefix+generation.GenerationID {
		return errors.New("FI transport generation directory identity is inconsistent before retirement")
	}

	if generation.Published.DirectoryPath != generation.GenerationDir ||
		generation.Published.Signed.Descriptor.GenerationID != generation.GenerationID {
		return errors.New("FI transport generation published identity is inconsistent before retirement")
	}

	if err := validateGenerationTransferResult(transfer); err != nil {
		return err
	}

	if transfer.Descriptor != generation.Published.Signed.Descriptor {
		return errors.New("FI generation transfer descriptor does not match queued generation before retirement")
	}

	if err := transportgeneration.AcknowledgementMatches(acknowledgement, transfer); err != nil {
		return fmt.Errorf("validate FI generation retirement acknowledgement: %w", err)
	}

	return nil
}

func validateGenerationRetirementAuthorization(value GenerationRetirementAuthorization) error {
	if err := validateGenerationTransferResult(value.transfer); err != nil {
		return errors.New("invalid FI generation retirement authorization transfer")
	}

	if err := transportgeneration.AcknowledgementMatches(value.acknowledgement, value.transfer); err != nil {
		return errors.New("invalid FI generation retirement authorization acknowledgement")
	}

	return nil
}

func validateGenerationTransferResult(value transportgeneration.TransferResult) error {
	if err := value.Descriptor.Validate(); err != nil {
		return fmt.Errorf("validate FI generation transfer descriptor: %w", err)
	}

	if value.MetadataBytes == 0 || value.PayloadBytes == 0 || value.TransferBytes == 0 {
		return errors.New("FI generation transfer byte counts must be greater than zero")
	}

	if value.PayloadBytes != value.Descriptor.EncodedDataBytes {
		return errors.New("FI generation transfer payload byte count does not match descriptor")
	}

	if value.PayloadSHA256 != value.Descriptor.EncodedDataSHA256 {
		return errors.New("FI generation transfer payload SHA-256 does not match descriptor")
	}

	for label, digest := range map[string]string{
		"metadata": value.MetadataSHA256,
		"payload":  value.PayloadSHA256,
		"transfer": value.TransferSHA256,
	} {
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != sha256.Size || digest != hex.EncodeToString(raw) {
			return fmt.Errorf("FI generation %s SHA-256 is invalid", label)
		}
	}

	expected := uint64(20)
	if value.MetadataBytes > ^uint64(0)-expected {
		return errors.New("FI generation transfer byte count overflow")
	}
	expected += value.MetadataBytes
	if value.PayloadBytes > ^uint64(0)-expected {
		return errors.New("FI generation transfer byte count overflow")
	}
	expected += value.PayloadBytes
	if value.TransferBytes != expected {
		return errors.New("FI generation transfer byte count is inconsistent")
	}

	return nil
}

func verifyGenerationMetadataIdentity(path string, transfer transportgeneration.TransferResult) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("FI generation metadata must remain a real regular file before retirement")
	}
	if uint64(info.Size()) != transfer.MetadataBytes {
		return errors.New("FI generation metadata byte count changed before retirement")
	}

	value, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(value)
	if hex.EncodeToString(digest[:]) != transfer.MetadataSHA256 {
		return errors.New("FI generation metadata SHA-256 changed before retirement")
	}
	return nil
}

func verifyRetiredGenerationTombstone(
	path string,
	generation TransportGeneration,
	transfer transportgeneration.TransferResult,
) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 2 {
		return errors.New("FI generation retirement tombstone must contain exactly two artifacts")
	}

	metadataPath := filepath.Join(path, transportgeneration.SignedGenerationMetadataName)
	payloadPath := filepath.Join(path, transportgeneration.SealedGenerationPayloadName)

	metadata, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("read retired FI generation metadata: %w", err)
	}
	if uint64(len(metadata)) != transfer.MetadataBytes {
		return errors.New("retired FI generation metadata byte count does not match acknowledged transfer")
	}
	metadataDigest := sha256.Sum256(metadata)
	if hex.EncodeToString(metadataDigest[:]) != transfer.MetadataSHA256 {
		return errors.New("retired FI generation metadata SHA-256 does not match acknowledged transfer")
	}

	signed, err := transportgeneration.UnmarshalSignedGeneration(metadata)
	if err != nil {
		return err
	}
	if !sameTransportGenerationSignedIdentity(signed, generation.Published.Signed) {
		return errors.New("retired FI generation signed identity does not match acknowledged generation")
	}

	payloadInfo, err := os.Lstat(payloadPath)
	if err != nil {
		return err
	}
	if payloadInfo.Mode()&os.ModeSymlink != 0 || !payloadInfo.Mode().IsRegular() || payloadInfo.Size() <= 0 || uint64(payloadInfo.Size()) != transfer.PayloadBytes {
		return errors.New("retired FI generation payload structure does not match acknowledged transfer")
	}

	payload, err := os.Open(payloadPath)
	if err != nil {
		return err
	}
	defer payload.Close()

	payloadHasher := sha256.New()
	if _, err := io.Copy(payloadHasher, payload); err != nil {
		return err
	}
	if hex.EncodeToString(payloadHasher.Sum(nil)) != transfer.PayloadSHA256 {
		return errors.New("retired FI generation payload SHA-256 does not match acknowledged transfer")
	}

	return nil
}

func sameTransportGenerationSignedIdentity(a, b transportgeneration.SignedGeneration) bool {
	return a.Version == b.Version &&
		a.Descriptor == b.Descriptor &&
		bytes.Equal(a.Signature, b.Signature) &&
		bytes.Equal(a.BatchSigningCertificateDER, b.BatchSigningCertificateDER)
}

func generationRetirementObjectName(transfer transportgeneration.TransferResult) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("FI-GENERATION-RETIREMENT-V1\x00"))
	_, _ = hasher.Write([]byte(transfer.Descriptor.SourceID))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(transfer.Descriptor.GenerationID))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(transfer.TransferSHA256))

	return generationRetiredDirectoryPrefix + hex.EncodeToString(hasher.Sum(nil))
}
