// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportrecovery

import (
	"bytes"
	"crypto"
	"crypto/rand"
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
	"sort"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
)

const recoveryFrameIdentityDomain = "FI-RECOVERY-OUTBOUND-IDENTITY-V1"

var ErrEncodedLimitExceeded = errors.New("FI recovery encoded payload exceeds negotiated receiver limit")

type PrepareConfig struct {
	BatchSigner             crypto.Signer
	BatchSigningCertificate *x509.Certificate
	Index                   Index
	MaxEncodedBytes         uint64
	RecoveryID              string
	SourceID                string
	SourcesFrozen           bool
	StageDir                string
}

type PreparedFrame struct {
	Descriptor  Descriptor
	FrameBytes  uint64
	FramePath   string
	FrameSHA256 string
	Index       Index
	IndexBytes  []byte
}

func NewRecoveryID() (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random[:]), nil
}

func PrepareFrame(config PrepareConfig) (PreparedFrame, error) {
	if err := validatePrepareConfig(config); err != nil {
		return PreparedFrame{}, err
	}
	indexBytes, err := MarshalIndex(config.Index)
	if err != nil {
		return PreparedFrame{}, err
	}
	indexSHA, _ := IndexSHA256(indexBytes)
	finalPath := filepath.Join(config.StageDir, recoveryFrameObjectName(config.SourceID, config.RecoveryID))

	if exists, err := inspectReadOnlyRegular(finalPath); err != nil {
		return PreparedFrame{}, err
	} else if exists {
		prepared, err := LoadPreparedFrame(finalPath)
		if err != nil {
			return PreparedFrame{}, err
		}
		if prepared.Descriptor.SourceID != config.SourceID || prepared.Descriptor.RecoveryID != config.RecoveryID || prepared.Descriptor.IndexSHA256 != indexSHA {
			return PreparedFrame{}, errors.New("existing staged recovery frame does not match requested recovery identity/index")
		}
		return prepared, nil
	}

	encoded, err := os.CreateTemp(config.StageDir, ".fi-recovery-encoded-*.open")
	if err != nil {
		return PreparedFrame{}, fmt.Errorf("create provisional FI recovery encoded payload: %w", err)
	}
	encodedPath := encoded.Name()
	encodedOpen := true
	defer func() {
		if encodedOpen {
			_ = encoded.Close()
		}
		_ = os.Remove(encodedPath)
	}()

	canonicalHasher := sha256.New()
	encodedHasher := sha256.New()
	encodedCounter := &countWriter{}
	encoder, err := transportencoding.NewZstdEncoder(io.MultiWriter(encoded, encodedHasher, encodedCounter))
	if err != nil {
		return PreparedFrame{}, err
	}

	var canonicalBytes uint64
	var recordCount uint64
	var streamErr error

	if config.SourcesFrozen {
		canonicalBytes, recordCount, streamErr = streamFrozenCanonicalMembers(
			encoder,
			canonicalHasher,
			config.Index,
		)
	} else {
		canonicalBytes, recordCount, streamErr = streamCanonicalMembers(
			encoder,
			canonicalHasher,
			config.Index,
		)
	}

	closeErr := encoder.Close()
	if streamErr != nil {
		return PreparedFrame{}, streamErr
	}
	if closeErr != nil {
		return PreparedFrame{}, fmt.Errorf("finalize FI recovery zstd payload: %w", closeErr)
	}
	if encodedCounter.bytes == 0 {
		return PreparedFrame{}, errors.New("FI recovery encoded payload is empty")
	}
	if config.MaxEncodedBytes > 0 && encodedCounter.bytes > config.MaxEncodedBytes {
		return PreparedFrame{}, fmt.Errorf("%w: encoded=%d max=%d", ErrEncodedLimitExceeded, encodedCounter.bytes, config.MaxEncodedBytes)
	}
	if encodedCounter.bytes > maxSignedStreamingBytes {
		return PreparedFrame{}, errors.New("FI recovery encoded payload exceeds supported streaming range")
	}
	if err := encoded.Sync(); err != nil {
		return PreparedFrame{}, fmt.Errorf("sync provisional FI recovery encoded payload: %w", err)
	}
	if _, err := encoded.Seek(0, io.SeekStart); err != nil {
		return PreparedFrame{}, fmt.Errorf("rewind FI recovery encoded payload: %w", err)
	}

	descriptor := Descriptor{
		Version:           DescriptorVersion,
		SourceID:          config.SourceID,
		RecoveryID:        config.RecoveryID,
		MemberCount:       uint64(len(config.Index.Members)),
		RecordCount:       recordCount,
		CanonicalBytes:    canonicalBytes,
		CanonicalSHA256:   hex.EncodeToString(canonicalHasher.Sum(nil)),
		DataEncoding:      transportencoding.DataEncodingZstd,
		EncodedDataBytes:  encodedCounter.bytes,
		EncodedDataSHA256: hex.EncodeToString(encodedHasher.Sum(nil)),
		IndexSHA256:       indexSHA,
		FirstBatchID:      config.Index.Members[0].BatchID,
		LastBatchID:       config.Index.Members[len(config.Index.Members)-1].BatchID,
	}
	if err := descriptor.Validate(); err != nil {
		return PreparedFrame{}, err
	}
	signed, err := NewSignedRecovery(descriptor, config.BatchSigningCertificate, config.BatchSigner)
	if err != nil {
		return PreparedFrame{}, err
	}

	provisional, err := os.CreateTemp(config.StageDir, ".fi-recovery-frame-*.open")
	if err != nil {
		return PreparedFrame{}, fmt.Errorf("create provisional FI recovery frame: %w", err)
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
	counter := &countWriter{}
	writer := io.MultiWriter(provisional, frameHasher, counter)
	if err := WriteBundleHeader(writer, signed, uint64(len(indexBytes)), descriptor.EncodedDataBytes); err != nil {
		return PreparedFrame{}, err
	}
	if _, err := writer.Write(indexBytes); err != nil {
		return PreparedFrame{}, fmt.Errorf("write FI recovery member index: %w", err)
	}
	written, err := io.CopyN(writer, encoded, int64(descriptor.EncodedDataBytes))
	if err != nil {
		return PreparedFrame{}, fmt.Errorf("write FI recovery encoded payload: %w", err)
	}
	if uint64(written) != descriptor.EncodedDataBytes {
		return PreparedFrame{}, errors.New("FI recovery encoded payload short write")
	}
	var trailing [1]byte
	if n, readErr := encoded.Read(trailing[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		return PreparedFrame{}, errors.New("FI recovery encoded payload contains unexpected trailing bytes")
	}
	if err := provisional.Chmod(0o400); err != nil {
		return PreparedFrame{}, fmt.Errorf("make provisional FI recovery frame read-only: %w", err)
	}
	if err := provisional.Sync(); err != nil {
		return PreparedFrame{}, fmt.Errorf("sync provisional FI recovery frame: %w", err)
	}
	if err := provisional.Close(); err != nil {
		provisionalOpen = false
		return PreparedFrame{}, fmt.Errorf("close provisional FI recovery frame: %w", err)
	}
	provisionalOpen = false

	published, err := publishRecoveryFrame(provisionalPath, finalPath)
	if err != nil {
		return PreparedFrame{}, fmt.Errorf("publish FI recovery frame: %w", err)
	}
	if published {
		keep = false
	} else {
		_ = os.Remove(provisionalPath)
		keep = false
	}

	prepared, err := LoadPreparedFrame(finalPath)
	if err != nil {
		return PreparedFrame{}, err
	}
	if prepared.Descriptor != descriptor || prepared.FrameBytes != counter.bytes || prepared.FrameSHA256 != hex.EncodeToString(frameHasher.Sum(nil)) {
		if published {
			return PreparedFrame{}, errors.New("published FI recovery frame changed after durable staging")
		}
		if prepared.Descriptor.SourceID != descriptor.SourceID || prepared.Descriptor.RecoveryID != descriptor.RecoveryID || prepared.Descriptor.IndexSHA256 != descriptor.IndexSHA256 {
			return PreparedFrame{}, errors.New("concurrently staged FI recovery frame conflicts with recovery identity")
		}
	}
	return prepared, nil
}

func LoadPreparedFrame(path string) (PreparedFrame, error) {
	if path == "" || !filepath.IsAbs(path) {
		return PreparedFrame{}, errors.New("staged FI recovery frame path must be absolute")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return PreparedFrame{}, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o222 != 0 || pathInfo.Size() <= 0 {
		return PreparedFrame{}, errors.New("staged FI recovery frame must be a non-empty read-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return PreparedFrame{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, opened) {
		return PreparedFrame{}, errors.New("staged FI recovery frame changed while opening")
	}

	hasher := sha256.New()
	counter := &countWriter{}
	reader := io.TeeReader(file, io.MultiWriter(hasher, counter))
	header, err := ReadBundleHeader(reader)
	if err != nil {
		return PreparedFrame{}, err
	}
	certificate, err := header.Signed.BatchSigningCertificate()
	if err != nil {
		return PreparedFrame{}, fmt.Errorf("parse staged FI recovery signing certificate: %w", err)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey == nil {
		return PreparedFrame{}, errors.New("staged FI recovery signing certificate RSA public key is required")
	}
	if err := VerifySignedRecoverySignature(header.Signed, publicKey); err != nil {
		return PreparedFrame{}, fmt.Errorf("verify staged FI recovery signature: %w", err)
	}
	descriptor := header.Signed.Descriptor
	expectedName := recoveryFrameObjectName(descriptor.SourceID, descriptor.RecoveryID)
	if filepath.Base(filepath.Clean(path)) != expectedName {
		return PreparedFrame{}, fmt.Errorf("staged FI recovery frame filename must be %q", expectedName)
	}
	indexBytes := make([]byte, int(header.IndexBytes))
	if _, err := io.ReadFull(reader, indexBytes); err != nil {
		return PreparedFrame{}, fmt.Errorf("read staged FI recovery index: %w", err)
	}
	indexSHA, _ := IndexSHA256(indexBytes)
	if indexSHA != header.Signed.Descriptor.IndexSHA256 {
		return PreparedFrame{}, errors.New("staged FI recovery index SHA-256 mismatch")
	}
	index, err := UnmarshalIndex(indexBytes)
	if err != nil {
		return PreparedFrame{}, err
	}
	if uint64(len(index.Members)) != descriptor.MemberCount || index.Members[0].BatchID != descriptor.FirstBatchID || index.Members[len(index.Members)-1].BatchID != descriptor.LastBatchID {
		return PreparedFrame{}, errors.New("staged FI recovery index facts do not match descriptor")
	}
	canonicalBytes, err := index.CanonicalBytes()
	if err != nil || canonicalBytes != descriptor.CanonicalBytes {
		return PreparedFrame{}, errors.New("staged FI recovery canonical byte count does not match member index")
	}
	recordCount, err := index.RecordCount()
	if err != nil || recordCount != descriptor.RecordCount {
		return PreparedFrame{}, errors.New("staged FI recovery record count does not match member index")
	}
	encodedHasher := sha256.New()
	written, err := io.CopyN(encodedHasher, reader, int64(header.EncodedDataBytes))
	if err != nil || uint64(written) != header.EncodedDataBytes {
		return PreparedFrame{}, errors.New("staged FI recovery encoded payload is truncated")
	}
	if hex.EncodeToString(encodedHasher.Sum(nil)) != header.Signed.Descriptor.EncodedDataSHA256 {
		return PreparedFrame{}, errors.New("staged FI recovery encoded SHA-256 mismatch")
	}
	var trailing [1]byte
	if n, readErr := reader.Read(trailing[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		return PreparedFrame{}, errors.New("staged FI recovery frame contains trailing bytes")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || after.Size() != pathInfo.Size() || after.Mode().Perm()&0o222 != 0 {
		return PreparedFrame{}, errors.New("staged FI recovery frame changed during validation")
	}
	if counter.bytes != uint64(pathInfo.Size()) {
		return PreparedFrame{}, errors.New("staged FI recovery frame byte count changed during validation")
	}

	return PreparedFrame{
		Descriptor:  header.Signed.Descriptor,
		FrameBytes:  counter.bytes,
		FramePath:   path,
		FrameSHA256: hex.EncodeToString(hasher.Sum(nil)),
		Index:       index,
		IndexBytes:  append([]byte(nil), indexBytes...),
	}, nil
}

func FindStagedFrame(stageDir string) (PreparedFrame, bool, error) {
	if err := validateStageDir(stageDir); err != nil {
		return PreparedFrame{}, false, err
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return PreparedFrame{}, false, err
	}
	paths := make([]string, 0, 1)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "recovery-") || !strings.HasSuffix(entry.Name(), ".firb") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return PreparedFrame{}, false, errors.New("FI recovery stage contains a recovery symlink")
		}
		paths = append(paths, filepath.Join(stageDir, entry.Name()))
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return PreparedFrame{}, false, nil
	}
	if len(paths) > 1 {
		return PreparedFrame{}, false, errors.New("FI recovery stage contains more than one unretired recovery frame")
	}
	prepared, err := LoadPreparedFrame(paths[0])
	if err != nil {
		return PreparedFrame{}, false, err
	}
	return prepared, true, nil
}

func SendPreparedFrame(writer io.Writer, prepared PreparedFrame) error {
	if writer == nil {
		return errors.New("FI recovery transport writer is required")
	}
	current, err := LoadPreparedFrame(prepared.FramePath)
	if err != nil {
		return err
	}
	if current.Descriptor != prepared.Descriptor || current.FrameBytes != prepared.FrameBytes || current.FrameSHA256 != prepared.FrameSHA256 {
		return errors.New("staged FI recovery frame facts changed before send")
	}
	file, err := os.Open(prepared.FramePath)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.CopyN(io.MultiWriter(writer, hasher), file, int64(prepared.FrameBytes))
	if err != nil || uint64(written) != prepared.FrameBytes {
		return fmt.Errorf("stream staged FI recovery frame: %w", err)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != prepared.FrameSHA256 {
		return errors.New("sent FI recovery frame SHA-256 does not match staged frame")
	}
	return nil
}

func RemovePreparedFrame(prepared PreparedFrame) error {
	initial, err := os.Lstat(prepared.FramePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if !initial.Mode().IsRegular() || initial.Mode().Perm()&0o222 != 0 {
		return errors.New("FI recovery staged frame must remain a read-only regular file before cleanup")
	}
	current, err := LoadPreparedFrame(prepared.FramePath)
	if err != nil {
		return err
	}
	if current.Descriptor != prepared.Descriptor || current.FrameSHA256 != prepared.FrameSHA256 || current.FrameBytes != prepared.FrameBytes {
		return errors.New("FI recovery staged frame changed before cleanup")
	}
	after, err := os.Lstat(prepared.FramePath)
	if err != nil {
		return err
	}
	if !os.SameFile(initial, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0o222 != 0 || uint64(after.Size()) != prepared.FrameBytes {
		return errors.New("FI recovery staged frame path changed before cleanup")
	}
	return removeRecoveryFrame(prepared.FramePath)
}

func streamCanonicalMembers(writer io.Writer, canonicalHasher io.Writer, index Index) (uint64, uint64, error) {
	if err := index.Validate(); err != nil {
		return 0, 0, err
	}
	combined := io.MultiWriter(writer, canonicalHasher)
	var total uint64
	var records uint64
	for _, member := range index.Members {
		manifest, manifestInfo, err := openStableRecoverySource(member.ManifestPath, member.ManifestBytes)
		if err != nil {
			return 0, 0, err
		}
		manifestRaw, readErr := io.ReadAll(manifest)
		closeErr := manifest.Close()
		if readErr != nil {
			return 0, 0, readErr
		}
		if closeErr != nil {
			return 0, 0, closeErr
		}
		if uint64(len(manifestRaw)) != member.ManifestBytes {
			return 0, 0, errors.New("published FI manifest changed before recovery compression")
		}
		digest := sha256.Sum256(manifestRaw)
		if hex.EncodeToString(digest[:]) != member.ManifestSHA256 {
			return 0, 0, errors.New("published FI manifest hash changed before recovery compression")
		}
		if _, err := ValidateManifestBytes(manifestRaw, member); err != nil {
			return 0, 0, err
		}
		if err := requireStableRecoverySource(member.ManifestPath, manifestInfo, member.ManifestBytes); err != nil {
			return 0, 0, err
		}
		if _, err := combined.Write(manifestRaw); err != nil {
			return 0, 0, err
		}
		total += member.ManifestBytes

		data, dataInfo, err := openStableRecoverySource(member.DataPath, member.DataBytes)
		if err != nil {
			return 0, 0, err
		}
		dataHasher := sha256.New()
		memberRecords, copyErr := copyRecoveryJSONL(
			io.MultiWriter(combined, dataHasher),
			data,
			member.DataBytes,
		)
		var trailing [1]byte
		n, trailingErr := data.Read(trailing[:])
		closeErr = data.Close()
		if copyErr != nil {
			return 0, 0, copyErr
		}
		if n != 0 || !errors.Is(trailingErr, io.EOF) {
			return 0, 0, errors.New("published FI data exceeds signed recovery member byte count")
		}
		if closeErr != nil {
			return 0, 0, closeErr
		}
		if memberRecords != member.RecordCount {
			return 0, 0, fmt.Errorf(
				"published FI data record count %d does not match manifest count %d",
				memberRecords,
				member.RecordCount,
			)
		}
		if hex.EncodeToString(dataHasher.Sum(nil)) != member.DataSHA256 {
			return 0, 0, errors.New("published FI data hash changed during recovery compression")
		}
		if err := requireStableRecoverySource(member.DataPath, dataInfo, member.DataBytes); err != nil {
			return 0, 0, err
		}
		total += member.DataBytes
		if member.RecordCount > ^uint64(0)-records {
			return 0, 0, errors.New("recovery record count overflow")
		}
		records += member.RecordCount
	}
	return total, records, nil
}

func streamFrozenCanonicalMembers(
	writer io.Writer,
	canonicalHasher io.Writer,
	index Index,
) (uint64, uint64, error) {
	if err := index.Validate(); err != nil {
		return 0, 0, err
	}

	combined := io.MultiWriter(writer, canonicalHasher)

	var total uint64
	var records uint64

	for _, member := range index.Members {
		manifestRaw, err := os.ReadFile(member.ManifestPath)
		if err != nil {
			return 0, 0, fmt.Errorf(
				"read frozen FI manifest for generation compression: %w",
				err,
			)
		}

		if uint64(len(manifestRaw)) != member.ManifestBytes {
			return 0, 0, errors.New(
				"frozen FI manifest byte count changed before generation compression",
			)
		}

		manifestDigest := sha256.Sum256(manifestRaw)

		if hex.EncodeToString(manifestDigest[:]) != member.ManifestSHA256 {
			return 0, 0, errors.New(
				"frozen FI manifest hash changed before generation compression",
			)
		}

		if _, err := ValidateManifestBytes(manifestRaw, member); err != nil {
			return 0, 0, err
		}

		if _, err := combined.Write(manifestRaw); err != nil {
			return 0, 0, err
		}

		if member.ManifestBytes > ^uint64(0)-total {
			return 0, 0, errors.New(
				"FI generation canonical byte count overflow",
			)
		}

		total += member.ManifestBytes

		data, err := os.Open(member.DataPath)
		if err != nil {
			return 0, 0, fmt.Errorf(
				"open frozen FI data for generation compression: %w",
				err,
			)
		}

		dataHasher := sha256.New()

		memberRecords, copyErr := copyRecoveryJSONL(
			io.MultiWriter(
				combined,
				dataHasher,
			),
			data,
			member.DataBytes,
		)

		var trailing [1]byte

		n, trailingErr :=
			data.Read(trailing[:])

		closeErr :=
			data.Close()

		if copyErr != nil {
			return 0, 0, copyErr
		}

		if n != 0 || !errors.Is(trailingErr, io.EOF) {
			return 0, 0, errors.New(
				"frozen FI data exceeds signed generation member byte count",
			)
		}

		if closeErr != nil {
			return 0, 0, closeErr
		}

		if memberRecords != member.RecordCount {
			return 0, 0, fmt.Errorf(
				"frozen FI data record count %d does not match manifest count %d",
				memberRecords,
				member.RecordCount,
			)
		}

		if hex.EncodeToString(dataHasher.Sum(nil)) != member.DataSHA256 {
			return 0, 0, errors.New(
				"frozen FI data SHA-256 does not match manifest",
			)
		}

		if member.DataBytes > ^uint64(0)-total {
			return 0, 0, errors.New(
				"FI generation canonical byte count overflow",
			)
		}

		total += member.DataBytes

		if member.RecordCount > ^uint64(0)-records {
			return 0, 0, errors.New(
				"FI generation record count overflow",
			)
		}

		records += member.RecordCount
	}

	return total, records, nil
}
func copyRecoveryJSONL(writer io.Writer, reader io.Reader, byteCount uint64) (uint64, error) {
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
			return 0, fmt.Errorf("read published FI data for recovery: %w", err)
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
		return 0, errors.New("published FI data is missing final newline")
	}
	return records, nil
}

func openStableRecoverySource(path string, expectedBytes uint64) (*os.File, os.FileInfo, error) {
	initial, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect FI recovery source artifact: %w", err)
	}
	if !initial.Mode().IsRegular() || initial.Size() <= 0 || uint64(initial.Size()) != expectedBytes {
		return nil, nil, errors.New("FI recovery source artifact is not the expected regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open FI recovery source artifact: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !os.SameFile(initial, opened) || uint64(opened.Size()) != expectedBytes {
		_ = file.Close()
		return nil, nil, errors.New("FI recovery source artifact changed while being opened")
	}
	return file, opened, nil
}

func requireStableRecoverySource(path string, opened os.FileInfo, expectedBytes uint64) error {
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, current) || !current.Mode().IsRegular() || uint64(current.Size()) != expectedBytes {
		return errors.New("FI recovery source artifact changed during streaming")
	}
	return nil
}

func validatePrepareConfig(config PrepareConfig) error {
	if strings.TrimSpace(config.SourceID) == "" || strings.TrimSpace(config.RecoveryID) == "" {
		return errors.New("FI recovery source and recovery IDs are required")
	}
	if config.BatchSigningCertificate == nil || config.BatchSigner == nil {
		return errors.New("FI recovery batch-signing identity is required")
	}
	if config.MaxEncodedBytes == 0 || config.MaxEncodedBytes > maxSignedStreamingBytes {
		return errors.New("FI recovery negotiated encoded byte limit is outside supported bounds")
	}
	if err := config.Index.Validate(); err != nil {
		return err
	}
	if _, err := config.Index.CanonicalBytes(); err != nil {
		return err
	}
	if _, err := config.Index.RecordCount(); err != nil {
		return err
	}
	return validateStageDir(config.StageDir)
}

func validateStageDir(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("FI recovery stage directory must be absolute")
	}
	clean := filepath.Clean(path)
	if err := validateRecoveryStageDirectoryPath(clean); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("inspect FI recovery stage directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI recovery stage path must name a real directory")
	}
	return nil
}

func recoveryFrameObjectName(sourceID, recoveryID string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(recoveryFrameIdentityDomain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(sourceID)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(sourceID))
	binary.BigEndian.PutUint64(length[:], uint64(len(recoveryID)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(recoveryID))
	return "recovery-" + hex.EncodeToString(hasher.Sum(nil)) + ".firb"
}

func inspectReadOnlyRegular(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 {
		return false, errors.New("FI recovery staged path must name a read-only regular file")
	}
	return true, nil
}

type countWriter struct{ bytes uint64 }

func (writer *countWriter) Write(value []byte) (int, error) {
	writer.bytes += uint64(len(value))
	return len(value), nil
}
