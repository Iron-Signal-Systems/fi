// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportrecovery

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

const (
	recoveryCustodyCompareBuffer  = 64 * 1024
	recoveryCustodyIdentityDomain = "FI-RECOVERY-CUSTODY-IDENTITY-V1"
)

var ErrRecoveryCustodyConflict = errors.New("FI recovery identity conflicts with existing durable custody bytes")

type CustodyConfig struct {
	BatchCRL          *x509.RevocationList
	BatchIssuer       *x509.Certificate
	CurrentTime       time.Time
	MaxCanonicalBytes uint64
	MaxEncodedBytes   uint64
	MaxMembers        uint64
	Root              *x509.Certificate
	RootDir           string
	Source            transporttrust.SourceAuthorization
}

type CustodyDisposition string

const (
	CustodyDispositionDuplicate CustodyDisposition = "DUPLICATE"
	CustodyDispositionNew       CustodyDisposition = "NEW"
)

type CustodyResult struct {
	Descriptor  Descriptor
	Disposition CustodyDisposition
	FrameBytes  uint64
	FramePath   string
	FrameSHA256 string
	Index       Index
}

func ReceiveToDurableCustody(reader io.Reader, config CustodyConfig) (CustodyResult, error) {
	if reader == nil {
		return CustodyResult{}, errors.New("recovery reader is required")
	}
	if err := validateCustodyConfig(config); err != nil {
		return CustodyResult{}, err
	}

	provisional, err := os.CreateTemp(config.RootDir, ".fi-recovery-custody-*.open")
	if err != nil {
		return CustodyResult{}, fmt.Errorf("create provisional FI recovery custody object: %w", err)
	}
	provisionalPath := provisional.Name()
	provisionalOpen := true
	keep := true
	defer func() {
		if provisionalOpen {
			_ = provisional.Close()
		}
		if keep {
			_ = os.Remove(provisionalPath)
		}
	}()

	frameHasher := sha256.New()
	frameCounter := &countWriter{}
	tee := io.TeeReader(reader, io.MultiWriter(provisional, frameHasher, frameCounter))

	header, err := ReadBundleHeader(tee)
	if err != nil {
		return CustodyResult{}, fmt.Errorf("read FI recovery bundle header: %w", err)
	}
	descriptor := header.Signed.Descriptor
	if descriptor.SourceID != config.Source.SourceID {
		return CustodyResult{}, fmt.Errorf("recovery source ID %q does not match enrolled source %q", descriptor.SourceID, config.Source.SourceID)
	}
	if descriptor.MemberCount > config.MaxMembers {
		return CustodyResult{}, fmt.Errorf("recovery member count %d exceeds receiver limit %d", descriptor.MemberCount, config.MaxMembers)
	}
	if descriptor.CanonicalBytes > config.MaxCanonicalBytes {
		return CustodyResult{}, fmt.Errorf("recovery canonical bytes %d exceed receiver limit %d", descriptor.CanonicalBytes, config.MaxCanonicalBytes)
	}
	if descriptor.EncodedDataBytes > config.MaxEncodedBytes || header.EncodedDataBytes > config.MaxEncodedBytes {
		return CustodyResult{}, fmt.Errorf("recovery encoded bytes %d exceed receiver limit %d", descriptor.EncodedDataBytes, config.MaxEncodedBytes)
	}

	certificate, err := header.Signed.BatchSigningCertificate()
	if err != nil {
		return CustodyResult{}, err
	}
	outcome, err := transporttrust.VerifyBatchSigningCertificate(
		certificate,
		config.Root,
		config.BatchIssuer,
		config.BatchCRL,
		config.Source,
		config.CurrentTime,
	)
	if err != nil {
		return CustodyResult{}, fmt.Errorf("authorize recovery batch-signing certificate: %w", err)
	}
	if outcome != transporttrust.AuthorizationAuthorized {
		return CustodyResult{}, fmt.Errorf("recovery batch-signing authorization rejected: %s", outcome)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey == nil {
		return CustodyResult{}, errors.New("recovery batch-signing RSA public key is required")
	}
	if err := VerifySignedRecoverySignature(header.Signed, publicKey); err != nil {
		return CustodyResult{}, err
	}

	indexBytes := make([]byte, int(header.IndexBytes))
	if _, err := io.ReadFull(tee, indexBytes); err != nil {
		return CustodyResult{}, fmt.Errorf("read FI recovery member index: %w", err)
	}
	indexSHA, _ := IndexSHA256(indexBytes)
	if indexSHA != descriptor.IndexSHA256 {
		return CustodyResult{}, errors.New("FI recovery member index SHA-256 mismatch")
	}
	index, err := UnmarshalIndex(indexBytes)
	if err != nil {
		return CustodyResult{}, err
	}
	if uint64(len(index.Members)) != descriptor.MemberCount || index.Members[0].BatchID != descriptor.FirstBatchID || index.Members[len(index.Members)-1].BatchID != descriptor.LastBatchID {
		return CustodyResult{}, errors.New("FI recovery member index range does not match signed descriptor")
	}
	canonicalBytes, err := index.CanonicalBytes()
	if err != nil || canonicalBytes != descriptor.CanonicalBytes {
		return CustodyResult{}, errors.New("FI recovery canonical byte count does not match signed index")
	}
	recordCount, err := index.RecordCount()
	if err != nil || recordCount != descriptor.RecordCount {
		return CustodyResult{}, errors.New("FI recovery record count does not match signed index")
	}

	limited := &io.LimitedReader{R: tee, N: int64(header.EncodedDataBytes)}
	encodedHasher := sha256.New()
	decoder, err := transportencoding.NewZstdDecoder(io.TeeReader(limited, encodedHasher))
	if err != nil {
		return CustodyResult{}, err
	}

	canonicalHasher := sha256.New()
	var consumedCanonical uint64
	for position, member := range index.Members {
		manifestRaw := make([]byte, int(member.ManifestBytes))
		if _, err := io.ReadFull(decoder, manifestRaw); err != nil {
			decoder.Close()
			return CustodyResult{}, fmt.Errorf("read recovery member %d manifest: %w", position, err)
		}
		if _, err := canonicalHasher.Write(manifestRaw); err != nil {
			decoder.Close()
			return CustodyResult{}, err
		}
		consumedCanonical += member.ManifestBytes
		if _, err := ValidateManifestBytes(manifestRaw, member); err != nil {
			decoder.Close()
			return CustodyResult{}, fmt.Errorf("validate recovery member %d manifest: %w", position, err)
		}

		dataHasher := sha256.New()
		dataWriter := io.MultiWriter(dataHasher, canonicalHasher)
		records, err := copyJSONLExactly(dataWriter, decoder, member.DataBytes)
		if err != nil {
			decoder.Close()
			return CustodyResult{}, fmt.Errorf("validate recovery member %d data: %w", position, err)
		}
		if records != member.RecordCount {
			decoder.Close()
			return CustodyResult{}, fmt.Errorf("recovery member %d record count %d does not match signed count %d", position, records, member.RecordCount)
		}
		if hex.EncodeToString(dataHasher.Sum(nil)) != member.DataSHA256 {
			decoder.Close()
			return CustodyResult{}, fmt.Errorf("recovery member %d data SHA-256 mismatch", position)
		}
		consumedCanonical += member.DataBytes
	}
	var extra [1]byte
	n, extraErr := decoder.Read(extra[:])
	decoder.Close()
	if n != 0 || !errors.Is(extraErr, io.EOF) {
		return CustodyResult{}, errors.New("FI recovery decoded payload contains bytes beyond signed member set")
	}
	if limited.N != 0 {
		return CustodyResult{}, errors.New("FI recovery encoded payload contains unread bytes")
	}
	if consumedCanonical != descriptor.CanonicalBytes || hex.EncodeToString(canonicalHasher.Sum(nil)) != descriptor.CanonicalSHA256 {
		return CustodyResult{}, errors.New("FI recovery aggregate canonical payload does not match signed descriptor")
	}
	if hex.EncodeToString(encodedHasher.Sum(nil)) != descriptor.EncodedDataSHA256 {
		return CustodyResult{}, errors.New("FI recovery encoded payload SHA-256 does not match signed descriptor")
	}

	if err := provisional.Chmod(0o400); err != nil {
		return CustodyResult{}, fmt.Errorf("make provisional FI recovery custody object read-only: %w", err)
	}
	if err := provisional.Sync(); err != nil {
		return CustodyResult{}, fmt.Errorf("sync provisional FI recovery custody object: %w", err)
	}
	if err := provisional.Close(); err != nil {
		provisionalOpen = false
		return CustodyResult{}, fmt.Errorf("close provisional FI recovery custody object: %w", err)
	}
	provisionalOpen = false

	info, err := os.Stat(provisionalPath)
	if err != nil || info.Size() <= 0 || uint64(info.Size()) != frameCounter.bytes {
		return CustodyResult{}, errors.New("provisional FI recovery custody object size mismatch")
	}
	frameSHA := hex.EncodeToString(frameHasher.Sum(nil))
	finalPath := filepath.Join(config.RootDir, recoveryCustodyObjectName(descriptor.SourceID, descriptor.RecoveryID))
	if err := os.Link(provisionalPath, finalPath); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return CustodyResult{}, fmt.Errorf("publish FI recovery durable custody object: %w", err)
		}
		exact, compareErr := recoveryFilesExactlyEqual(finalPath, provisionalPath, info.Size())
		if compareErr != nil {
			return CustodyResult{}, compareErr
		}
		if removeErr := os.Remove(provisionalPath); removeErr != nil {
			return CustodyResult{}, removeErr
		}
		keep = false
		if syncErr := syncRecoveryCustodyDirectory(config.RootDir); syncErr != nil {
			return CustodyResult{}, syncErr
		}
		if !exact {
			return CustodyResult{}, fmt.Errorf("%w: source=%q recovery=%q", ErrRecoveryCustodyConflict, descriptor.SourceID, descriptor.RecoveryID)
		}
		return CustodyResult{Descriptor: descriptor, Disposition: CustodyDispositionDuplicate, FrameBytes: frameCounter.bytes, FramePath: finalPath, FrameSHA256: frameSHA, Index: index}, nil
	}

	if err := os.Remove(provisionalPath); err != nil {
		_ = os.Remove(finalPath)
		return CustodyResult{}, err
	}
	keep = false
	if err := syncRecoveryCustodyDirectory(config.RootDir); err != nil {
		return CustodyResult{}, err
	}
	return CustodyResult{Descriptor: descriptor, Disposition: CustodyDispositionNew, FrameBytes: frameCounter.bytes, FramePath: finalPath, FrameSHA256: frameSHA, Index: index}, nil
}

func AcknowledgementFromCustody(result CustodyResult) (Acknowledgement, error) {
	if err := result.Descriptor.Validate(); err != nil {
		return Acknowledgement{}, err
	}
	if result.FrameBytes == 0 || validateSHA256("frame SHA-256", result.FrameSHA256) != nil {
		return Acknowledgement{}, errors.New("FI recovery custody exact frame facts are invalid")
	}
	outcome := AcknowledgementDurableNew
	if result.Disposition == CustodyDispositionDuplicate {
		outcome = AcknowledgementDurableDuplicate
	} else if result.Disposition != CustodyDispositionNew {
		return Acknowledgement{}, errors.New("unsupported FI recovery custody disposition")
	}
	descriptor := result.Descriptor
	ack := Acknowledgement{
		Version:           "fi-recovery-ack/0.1",
		Outcome:           outcome,
		SourceID:          descriptor.SourceID,
		RecoveryID:        descriptor.RecoveryID,
		MemberCount:       descriptor.MemberCount,
		CanonicalBytes:    descriptor.CanonicalBytes,
		CanonicalSHA256:   descriptor.CanonicalSHA256,
		EncodedDataBytes:  descriptor.EncodedDataBytes,
		EncodedDataSHA256: descriptor.EncodedDataSHA256,
		IndexSHA256:       descriptor.IndexSHA256,
		FirstBatchID:      descriptor.FirstBatchID,
		LastBatchID:       descriptor.LastBatchID,
		FrameBytes:        result.FrameBytes,
		FrameSHA256:       result.FrameSHA256,
	}
	return ack, ack.Validate()
}

func validateCustodyConfig(config CustodyConfig) error {
	if config.BatchCRL == nil || config.BatchIssuer == nil || config.Root == nil {
		return errors.New("FI recovery batch-signing trust material is required")
	}
	if config.CurrentTime.IsZero() {
		return errors.New("FI recovery current time is required")
	}
	if config.MaxCanonicalBytes == 0 || config.MaxEncodedBytes == 0 || config.MaxMembers == 0 {
		return errors.New("FI recovery receiver limits must be enabled")
	}
	if config.MaxMembers > maxRecoveryMembers || config.MaxCanonicalBytes > maxSignedStreamingBytes || config.MaxEncodedBytes > maxSignedStreamingBytes {
		return errors.New("FI recovery receiver limits exceed structural safety bounds")
	}
	if config.Source.SourceID == "" {
		return errors.New("FI recovery source authorization is required")
	}
	if config.RootDir == "" || !filepath.IsAbs(config.RootDir) {
		return errors.New("FI recovery custody root directory must be absolute")
	}
	clean := filepath.Clean(config.RootDir)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return fmt.Errorf("resolve FI recovery custody root: %w", err)
	}
	if filepath.Clean(resolved) != clean {
		return errors.New("FI recovery custody root path must not traverse symlinks")
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("FI recovery custody root must be a real non-group/other-writable directory")
	}
	return nil
}

func copyJSONLExactly(writer io.Writer, reader io.Reader, byteCount uint64) (uint64, error) {
	if byteCount == 0 || byteCount > maxSignedStreamingBytes {
		return 0, errors.New("JSONL byte count is outside recovery bounds")
	}
	remaining := byteCount
	buffer := make([]byte, 128*1024)
	var records uint64
	var last byte
	for remaining > 0 {
		chunk := uint64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		n, err := io.ReadFull(reader, buffer[:int(chunk)])
		if err != nil {
			return 0, err
		}
		part := buffer[:n]
		if _, err := writer.Write(part); err != nil {
			return 0, err
		}
		records += uint64(bytes.Count(part, []byte{'\n'}))
		last = part[len(part)-1]
		remaining -= uint64(n)
	}
	if last != '\n' {
		return 0, errors.New("recovery member JSONL is missing final newline")
	}
	return records, nil
}

func recoveryCustodyObjectName(sourceID, recoveryID string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(recoveryCustodyIdentityDomain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(sourceID)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(sourceID))
	binary.BigEndian.PutUint64(length[:], uint64(len(recoveryID)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(recoveryID))
	return "recovery-" + hex.EncodeToString(hasher.Sum(nil)) + ".firb"
}

func recoveryFilesExactlyEqual(firstPath, secondPath string, expectedSize int64) (bool, error) {
	firstInfo, err := os.Lstat(firstPath)
	if err != nil {
		return false, err
	}
	if !firstInfo.Mode().IsRegular() || firstInfo.Mode().Perm() != 0o400 || firstInfo.Size() != expectedSize {
		return false, nil
	}
	first, err := os.Open(firstPath)
	if err != nil {
		return false, err
	}
	defer first.Close()
	openedFirst, err := first.Stat()
	if err != nil || !os.SameFile(firstInfo, openedFirst) {
		return false, errors.New("existing FI recovery custody object changed while being opened")
	}

	secondInfo, err := os.Lstat(secondPath)
	if err != nil {
		return false, err
	}
	if !secondInfo.Mode().IsRegular() || secondInfo.Size() != expectedSize {
		return false, nil
	}
	second, err := os.Open(secondPath)
	if err != nil {
		return false, err
	}
	defer second.Close()
	openedSecond, err := second.Stat()
	if err != nil || !os.SameFile(secondInfo, openedSecond) {
		return false, errors.New("provisional FI recovery custody object changed while being opened")
	}

	firstBuffer := make([]byte, recoveryCustodyCompareBuffer)
	secondBuffer := make([]byte, recoveryCustodyCompareBuffer)
	remaining := expectedSize
	for remaining > 0 {
		chunk := int64(len(firstBuffer))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := io.ReadFull(first, firstBuffer[:int(chunk)]); err != nil {
			return false, err
		}
		if _, err := io.ReadFull(second, secondBuffer[:int(chunk)]); err != nil {
			return false, err
		}
		if !bytes.Equal(firstBuffer[:int(chunk)], secondBuffer[:int(chunk)]) {
			return false, nil
		}
		remaining -= chunk
	}
	currentFirst, err := os.Lstat(firstPath)
	if err != nil || !os.SameFile(openedFirst, currentFirst) || currentFirst.Mode().Perm() != 0o400 || currentFirst.Size() != expectedSize {
		return false, errors.New("existing FI recovery custody object changed during comparison")
	}
	currentSecond, err := os.Lstat(secondPath)
	if err != nil || !os.SameFile(openedSecond, currentSecond) || currentSecond.Size() != expectedSize {
		return false, errors.New("provisional FI recovery custody object changed during comparison")
	}
	return true, nil
}

func syncRecoveryCustodyDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
