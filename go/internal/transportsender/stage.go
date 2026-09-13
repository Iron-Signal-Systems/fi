// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"crypto"
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

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportwire"
)

const (
	maxOutboundCopyDataBytes    = uint64(1<<63 - 1)
	outboundFrameIdentityDomain = "FI-SOURCE-OUTBOUND-IDENTITY-V1"
)

var ErrOutboundSigningIdentityRequired = errors.New(
	"FI outbound batch-signing identity is required",
)

// OutboundFrameConfig defines the source material needed to create or recover
// one durable exact transport frame before any network send is attempted.
//
// BatchSigningCertificate and BatchSigner are required only when no staged frame
// already exists. An exact retry therefore does not re-sign the batch.
type OutboundFrameConfig struct {
	BatchSigner             crypto.Signer
	BatchSigningCertificate *x509.Certificate
	ManifestPath            string
	SourceID                string
	StageDir                string
}

// OutboundFrameDisposition describes whether this call created the durable
// outbound frame or recovered the already-staged exact frame for retry.
type OutboundFrameDisposition string

const (
	OutboundFrameDispositionExisting OutboundFrameDisposition = "EXISTING"
	OutboundFrameDispositionNew      OutboundFrameDisposition = "NEW"
)

// OutboundFrame identifies one exact, durable source-side FI wire frame.
// Sent is the source-side acknowledgement expectation for these exact bytes.
type OutboundFrame struct {
	Disposition OutboundFrameDisposition
	FramePath   string
	Sent        SentFrame
}

// PrepareOutboundFrame creates one exact FI wire frame from a verified,
// published Phase 1 batch and durably stages it before transport.
//
// If the deterministic stage object already exists, FI validates and reuses its
// exact bytes instead of signing again. This is required because RSA-PSS is
// randomized: reconstructing the same descriptor can produce a different valid
// signature and therefore a different wire frame. Lost-ack retries must replay
// the original staged frame byte-for-byte.
func PrepareOutboundFrame(config OutboundFrameConfig) (OutboundFrame, error) {
	if err := validateOutboundFrameConfig(config); err != nil {
		return OutboundFrame{}, err
	}

	descriptor, err := transportbatch.DescriptorFromPublishedManifest(
		config.SourceID,
		config.ManifestPath,
	)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"construct FI descriptor for outbound staging: %w",
			err,
		)
	}

	finalPath := filepath.Join(
		config.StageDir,
		outboundFrameObjectName(descriptor.SourceID, descriptor.BatchID),
	)
	exists, err := inspectOutboundFramePath(finalPath)
	if err != nil {
		return OutboundFrame{}, err
	}
	if exists {
		sent, err := validateStagedOutboundFrame(finalPath, descriptor)
		if err != nil {
			return OutboundFrame{}, fmt.Errorf(
				"validate existing FI outbound frame: %w",
				err,
			)
		}
		return OutboundFrame{
			Disposition: OutboundFrameDispositionExisting,
			FramePath:   finalPath,
			Sent:        sent,
		}, nil
	}

	if config.BatchSigningCertificate == nil {
		return OutboundFrame{}, fmt.Errorf(
			"%w: batch-signing certificate is required to create a new outbound frame",
			ErrOutboundSigningIdentityRequired,
		)
	}
	if config.BatchSigner == nil {
		return OutboundFrame{}, fmt.Errorf(
			"%w: batch signer is required to create a new outbound frame",
			ErrOutboundSigningIdentityRequired,
		)
	}

	manifest, err := os.ReadFile(config.ManifestPath)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"read published FI manifest for outbound frame: %w",
			err,
		)
	}
	manifestDigest := sha256.Sum256(manifest)
	if hex.EncodeToString(manifestDigest[:]) != descriptor.ManifestSHA256 {
		return OutboundFrame{}, errors.New(
			"published FI manifest changed after descriptor construction",
		)
	}

	dataPath, err := outboundPublishedDataPath(config.ManifestPath, descriptor.BatchID)
	if err != nil {
		return OutboundFrame{}, err
	}
	data, err := openOutboundData(dataPath)
	if err != nil {
		return OutboundFrame{}, err
	}
	defer data.Close()

	signedBatch, err := transportpackage.NewSignedBatch(
		descriptor,
		config.BatchSigningCertificate,
		config.BatchSigner,
	)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf("sign FI outbound batch: %w", err)
	}

	provisional, err := os.CreateTemp(config.StageDir, ".fi-outbound-*.open")
	if err != nil {
		return OutboundFrame{}, fmt.Errorf("create provisional FI outbound frame: %w", err)
	}
	provisionalPath := provisional.Name()
	provisionalOpen := true
	keepProvisional := true
	defer func() {
		if provisionalOpen {
			_ = provisional.Close()
		}
		if keepProvisional {
			_ = os.Remove(provisionalPath)
		}
	}()

	if err := transportwire.WriteHeader(provisional, signedBatch, manifest); err != nil {
		return OutboundFrame{}, fmt.Errorf("write FI outbound frame header: %w", err)
	}
	if err := writeOutboundFull(provisional, manifest); err != nil {
		return OutboundFrame{}, fmt.Errorf("write FI outbound manifest payload: %w", err)
	}

	if descriptor.DataBytes > maxOutboundCopyDataBytes {
		return OutboundFrame{}, fmt.Errorf(
			"FI outbound data byte count %d exceeds supported streaming range",
			descriptor.DataBytes,
		)
	}
	dataHasher := sha256.New()
	written, err := io.CopyN(
		io.MultiWriter(provisional, dataHasher),
		data,
		int64(descriptor.DataBytes),
	)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf("write FI outbound data payload: %w", err)
	}
	if uint64(written) != descriptor.DataBytes {
		return OutboundFrame{}, fmt.Errorf(
			"write FI outbound data payload: wrote %d bytes, want %d",
			written,
			descriptor.DataBytes,
		)
	}
	if err := ensureOutboundDataEOF(data); err != nil {
		return OutboundFrame{}, err
	}
	if hex.EncodeToString(dataHasher.Sum(nil)) != descriptor.DataSHA256 {
		return OutboundFrame{}, errors.New(
			"published FI data changed while outbound frame was being staged",
		)
	}

	if err := provisional.Chmod(0o400); err != nil {
		return OutboundFrame{}, fmt.Errorf("make provisional FI outbound frame read-only: %w", err)
	}
	if err := provisional.Sync(); err != nil {
		return OutboundFrame{}, fmt.Errorf("sync provisional FI outbound frame: %w", err)
	}
	if err := provisional.Close(); err != nil {
		provisionalOpen = false
		return OutboundFrame{}, fmt.Errorf("close provisional FI outbound frame: %w", err)
	}
	provisionalOpen = false

	provisionalSent, err := validateStagedOutboundFrame(provisionalPath, descriptor)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"validate provisional FI outbound frame: %w",
			err,
		)
	}

	published, err := publishOutboundFrame(provisionalPath, finalPath)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf("publish FI outbound frame: %w", err)
	}
	if published {
		keepProvisional = false
		return OutboundFrame{
			Disposition: OutboundFrameDispositionNew,
			FramePath:   finalPath,
			Sent:        provisionalSent,
		}, nil
	}

	// Another concurrent preparer won the no-replace publication race. Its
	// complete frame is now authoritative for retries of this batch identity.
	existingSent, err := validateStagedOutboundFrame(finalPath, descriptor)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"validate concurrently published FI outbound frame: %w",
			err,
		)
	}
	if err := os.Remove(provisionalPath); err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"remove superseded provisional FI outbound frame: %w",
			err,
		)
	}
	keepProvisional = false

	return OutboundFrame{
		Disposition: OutboundFrameDispositionExisting,
		FramePath:   finalPath,
		Sent:        existingSent,
	}, nil
}

func ensureOutboundDataEOF(file *os.File) error {
	extra, err := io.CopyN(io.Discard, file, 1)
	if extra != 0 {
		return errors.New("published FI data exceeds signed descriptor byte count")
	}
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("published FI data did not terminate at signed byte count")
		}
		return fmt.Errorf("check published FI data end: %w", err)
	}
	return nil
}

func inspectOutboundFramePath(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect FI outbound frame: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("FI outbound frame path must name a regular file")
	}
	if info.Mode().Perm()&0o222 != 0 {
		return false, fmt.Errorf(
			"FI outbound frame must be read-only before reuse: mode=%04o",
			info.Mode().Perm(),
		)
	}
	return true, nil
}

func openOutboundData(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect published FI data for outbound frame: %w", err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("published FI data for outbound frame must be a regular file")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open published FI data for outbound frame: %w", err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened published FI data for outbound frame: %w", err)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return nil, errors.New("published FI data changed while being opened for outbound staging")
	}
	return file, nil
}

func outboundFrameObjectName(sourceID string, batchID string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(outboundFrameIdentityDomain))

	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(sourceID)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(sourceID))
	binary.BigEndian.PutUint64(length[:], uint64(len(batchID)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(batchID))

	return "outbound-" + hex.EncodeToString(hasher.Sum(nil)) + ".fiwb"
}

func outboundPublishedDataPath(manifestPath string, batchID string) (string, error) {
	expectedData := "batch-" + batchID + ".jsonl"
	if filepath.Base(expectedData) != expectedData {
		return "", errors.New("FI batch ID cannot map to an outbound data filename")
	}
	return filepath.Join(filepath.Dir(manifestPath), expectedData), nil
}

func validateOutboundFrameConfig(config OutboundFrameConfig) error {
	if config.SourceID == "" {
		return errors.New("FI outbound source ID is required")
	}
	if config.ManifestPath == "" {
		return errors.New("published FI manifest path is required")
	}
	if !filepath.IsAbs(config.ManifestPath) {
		return errors.New("published FI manifest path must be absolute")
	}
	if config.StageDir == "" {
		return errors.New("FI outbound stage directory is required")
	}
	if !filepath.IsAbs(config.StageDir) {
		return errors.New("FI outbound stage directory must be absolute")
	}

	if err := validateOutboundStageDirectoryPath(config.StageDir); err != nil {
		return err
	}
	info, err := os.Lstat(config.StageDir)
	if err != nil {
		return fmt.Errorf("inspect FI outbound stage directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI outbound stage path must be a real directory")
	}
	return nil
}

func validateStagedOutboundFrame(
	path string,
	expected transportbatch.Descriptor,
) (SentFrame, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return SentFrame{}, err
	}
	if !pathInfo.Mode().IsRegular() {
		return SentFrame{}, errors.New("staged FI outbound frame must be a regular file")
	}
	if pathInfo.Mode().Perm()&0o222 != 0 {
		return SentFrame{}, errors.New("staged FI outbound frame must be read-only")
	}
	if pathInfo.Size() <= 0 {
		return SentFrame{}, errors.New("staged FI outbound frame is empty")
	}

	file, err := os.Open(path)
	if err != nil {
		return SentFrame{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return SentFrame{}, err
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return SentFrame{}, errors.New("staged FI outbound frame changed while being opened")
	}

	frameHasher := sha256.New()
	counter := &outboundCountWriter{}
	reader := io.TeeReader(file, io.MultiWriter(frameHasher, counter))
	header, err := transportwire.ReadHeader(reader)
	if err != nil {
		return SentFrame{}, fmt.Errorf("read staged FI outbound frame header: %w", err)
	}
	if header.SignedBatch.Descriptor != expected {
		return SentFrame{}, errors.New("staged FI outbound descriptor does not match published batch")
	}
	if err := verifyStagedOutboundSignature(header.SignedBatch); err != nil {
		return SentFrame{}, err
	}

	manifest := make([]byte, int(header.ManifestBytes))
	if _, err := io.ReadFull(reader, manifest); err != nil {
		return SentFrame{}, fmt.Errorf("read staged FI outbound manifest: %w", err)
	}
	manifestDigest := sha256.Sum256(manifest)
	if hex.EncodeToString(manifestDigest[:]) != expected.ManifestSHA256 {
		return SentFrame{}, errors.New("staged FI outbound manifest SHA-256 mismatch")
	}

	if expected.DataBytes > maxOutboundCopyDataBytes {
		return SentFrame{}, errors.New("staged FI outbound data byte count exceeds supported range")
	}
	dataHasher := sha256.New()
	written, err := io.CopyN(dataHasher, reader, int64(expected.DataBytes))
	if err != nil {
		return SentFrame{}, fmt.Errorf("read staged FI outbound data: %w", err)
	}
	if uint64(written) != expected.DataBytes {
		return SentFrame{}, errors.New("staged FI outbound data byte count mismatch")
	}
	if hex.EncodeToString(dataHasher.Sum(nil)) != expected.DataSHA256 {
		return SentFrame{}, errors.New("staged FI outbound data SHA-256 mismatch")
	}

	var trailing [1]byte
	n, err := reader.Read(trailing[:])
	if n != 0 {
		return SentFrame{}, errors.New("staged FI outbound frame contains trailing bytes")
	}
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return SentFrame{}, errors.New("staged FI outbound frame did not terminate at expected boundary")
		}
		return SentFrame{}, fmt.Errorf("check staged FI outbound frame end: %w", err)
	}

	afterOpen, err := file.Stat()
	if err != nil {
		return SentFrame{}, err
	}
	if !os.SameFile(openedInfo, afterOpen) || afterOpen.Size() != pathInfo.Size() {
		return SentFrame{}, errors.New("staged FI outbound frame changed during validation")
	}
	afterPath, err := os.Lstat(path)
	if err != nil {
		return SentFrame{}, err
	}
	if !os.SameFile(afterOpen, afterPath) || afterPath.Mode().Perm()&0o222 != 0 {
		return SentFrame{}, errors.New("staged FI outbound frame path changed during validation")
	}
	if counter.bytes != uint64(pathInfo.Size()) {
		return SentFrame{}, errors.New("staged FI outbound frame size changed during validation")
	}

	return SentFrame{
		Descriptor:  expected,
		FrameBytes:  counter.bytes,
		FrameSHA256: hex.EncodeToString(frameHasher.Sum(nil)),
	}, nil
}

type outboundCountWriter struct {
	bytes uint64
}

func (writer *outboundCountWriter) Write(value []byte) (int, error) {
	writer.bytes += uint64(len(value))
	return len(value), nil
}

func verifyStagedOutboundSignature(value transportpackage.SignedBatch) error {
	certificate, err := value.BatchSigningCertificate()
	if err != nil {
		return fmt.Errorf("parse staged FI batch-signing certificate: %w", err)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey == nil {
		return errors.New("staged FI batch-signing certificate RSA public key is required")
	}
	input, err := value.Descriptor.SignatureInput()
	if err != nil {
		return fmt.Errorf("construct staged FI batch signature input: %w", err)
	}
	digest := sha256.Sum256(input)
	if err := rsa.VerifyPSS(
		publicKey,
		crypto.SHA256,
		digest[:],
		value.Signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	); err != nil {
		return fmt.Errorf("staged FI batch signature verification failed: %w", err)
	}
	return nil
}

func writeOutboundFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
