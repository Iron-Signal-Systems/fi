// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	custodyCompareBufferBytes = 64 * 1024
	custodyIdentityDomain     = "FI-CUSTODY-IDENTITY-V1"
)

var ErrCustodyConflict = errors.New("FI batch identity conflicts with existing durable custody bytes")

// CustodyConfig defines the receiver storage boundary used after authenticated
// transport has reached the bounded batch-intake contract.
type CustodyConfig struct {
	Intake  IntakeConfig
	RootDir string
}

// CustodyDisposition describes how one validated FI frame satisfied durable
// receiver custody.
type CustodyDisposition string

const (
	CustodyDispositionDuplicate CustodyDisposition = "DUPLICATE"
	CustodyDispositionNew       CustodyDisposition = "NEW"
)

// DurableCustodyResult identifies one FI wire batch whose exact received frame
// has crossed the durable backend-custody boundary.
//
// NEW means this call published the deterministic custody object. DUPLICATE
// means the same identity already mapped to byte-for-byte identical durable
// custody. Both outcomes are safe inputs to a later acknowledgement contract.
// A conflicting existing object is never returned as success.
type DurableCustodyResult struct {
	BatchID        string
	DataBytes      uint64
	DataSHA256     string
	Disposition    CustodyDisposition
	FrameBytes     uint64
	FramePath      string
	FrameSHA256    string
	ManifestSHA256 string
	SourceID       string
}

// ReceiveToDurableCustody reads one framed FI batch, validates it using the
// receiver intake contract, and atomically publishes the exact bytes consumed
// from the wire as one read-only custody object.
//
// The source stream is tee'd directly into a provisional file while
// ReadValidatedBatch performs trust, signature, manifest, and data validation.
// No final custody name is created unless all validation succeeds and the
// provisional file itself has been fsynced.
//
// Publication uses a hard link from the provisional inode to the deterministic
// final identity path. os.Link never replaces an existing final object. If the
// identity already exists, FI compares the durable object and provisional frame
// byte-for-byte. An exact retry returns DUPLICATE; different bytes return
// ErrCustodyConflict. Existing custody is never overwritten.
func ReceiveToDurableCustody(
	reader io.Reader,
	config CustodyConfig,
) (DurableCustodyResult, error) {
	if reader == nil {
		return DurableCustodyResult{}, errors.New("batch reader is required")
	}
	if err := validateCustodyConfig(config); err != nil {
		return DurableCustodyResult{}, err
	}

	provisional, err := os.CreateTemp(
		config.RootDir,
		".fi-custody-*.open",
	)
	if err != nil {
		return DurableCustodyResult{}, fmt.Errorf(
			"create provisional FI custody object: %w",
			err,
		)
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

	frameHasher := sha256.New()
	tee := io.TeeReader(
		reader,
		io.MultiWriter(provisional, frameHasher),
	)

	intake, err := ReadValidatedBatch(
		tee,
		io.Discard,
		config.Intake,
	)
	if err != nil {
		return DurableCustodyResult{}, fmt.Errorf(
			"validate FI batch before durable custody: %w",
			err,
		)
	}

	if err := provisional.Chmod(0o400); err != nil {
		return DurableCustodyResult{}, fmt.Errorf(
			"make provisional FI custody object read-only: %w",
			err,
		)
	}
	if err := provisional.Sync(); err != nil {
		return DurableCustodyResult{}, fmt.Errorf(
			"sync provisional FI custody object: %w",
			err,
		)
	}
	if err := provisional.Close(); err != nil {
		provisionalOpen = false
		return DurableCustodyResult{}, fmt.Errorf(
			"close provisional FI custody object: %w",
			err,
		)
	}
	provisionalOpen = false

	info, err := os.Stat(provisionalPath)
	if err != nil {
		return DurableCustodyResult{}, fmt.Errorf(
			"stat provisional FI custody object: %w",
			err,
		)
	}
	if info.Size() <= 0 {
		return DurableCustodyResult{}, errors.New(
			"provisional FI custody object is empty",
		)
	}

	descriptor := intake.Header.SignedBatch.Descriptor
	finalPath := filepath.Join(
		config.RootDir,
		custodyObjectName(descriptor.SourceID, descriptor.BatchID),
	)
	frameSHA256 := hex.EncodeToString(frameHasher.Sum(nil))

	if err := os.Link(provisionalPath, finalPath); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return DurableCustodyResult{}, fmt.Errorf(
				"publish FI durable custody object: %w",
				err,
			)
		}

		exact, compareErr := existingCustodyMatches(
			finalPath,
			provisionalPath,
			info.Size(),
		)
		if compareErr != nil {
			return DurableCustodyResult{}, compareErr
		}

		if removeErr := os.Remove(provisionalPath); removeErr != nil {
			return DurableCustodyResult{}, fmt.Errorf(
				"remove duplicate/conflicting provisional FI custody object: %w",
				removeErr,
			)
		}
		keepProvisional = false

		if syncErr := syncCustodyDirectory(config.RootDir); syncErr != nil {
			return DurableCustodyResult{}, fmt.Errorf(
				"sync FI durable custody directory after identity collision: %w",
				syncErr,
			)
		}

		if !exact {
			return DurableCustodyResult{}, fmt.Errorf(
				"%w: source=%q batch=%q path=%s",
				ErrCustodyConflict,
				descriptor.SourceID,
				descriptor.BatchID,
				finalPath,
			)
		}

		return newDurableCustodyResult(
			intake,
			info,
			finalPath,
			frameSHA256,
			CustodyDispositionDuplicate,
		), nil
	}

	if err := os.Remove(provisionalPath); err != nil {
		_ = os.Remove(finalPath)
		return DurableCustodyResult{}, fmt.Errorf(
			"remove provisional FI custody name after publication: %w",
			err,
		)
	}
	keepProvisional = false

	if err := syncCustodyDirectory(config.RootDir); err != nil {
		return DurableCustodyResult{}, fmt.Errorf(
			"sync FI durable custody directory: %w",
			err,
		)
	}

	return newDurableCustodyResult(
		intake,
		info,
		finalPath,
		frameSHA256,
		CustodyDispositionNew,
	), nil
}

func custodyObjectName(sourceID string, batchID string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(custodyIdentityDomain))

	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(sourceID)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(sourceID))
	binary.BigEndian.PutUint64(length[:], uint64(len(batchID)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(batchID))

	return "batch-" + hex.EncodeToString(hasher.Sum(nil)) + ".fiwb"
}

func existingCustodyMatches(
	finalPath string,
	provisionalPath string,
	expectedSize int64,
) (bool, error) {
	pathInfo, err := os.Lstat(finalPath)
	if err != nil {
		return false, fmt.Errorf("inspect existing FI custody object: %w", err)
	}
	if !pathInfo.Mode().IsRegular() {
		return false, errors.New("existing FI custody object must be a regular file")
	}
	if pathInfo.Mode().Perm() != 0o400 {
		return false, fmt.Errorf(
			"existing FI custody object mode must be 0400, got %04o",
			pathInfo.Mode().Perm(),
		)
	}
	if pathInfo.Size() != expectedSize {
		return false, nil
	}

	existing, err := os.Open(finalPath)
	if err != nil {
		return false, fmt.Errorf("open existing FI custody object: %w", err)
	}
	defer existing.Close()

	openedInfo, err := existing.Stat()
	if err != nil {
		return false, fmt.Errorf("stat opened existing FI custody object: %w", err)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return false, errors.New("existing FI custody object changed while being opened")
	}

	provisional, err := os.Open(provisionalPath)
	if err != nil {
		return false, fmt.Errorf("open provisional FI custody object for comparison: %w", err)
	}
	defer provisional.Close()

	exact, err := filesExactlyEqual(existing, provisional, expectedSize)
	if err != nil {
		return false, err
	}

	afterInfo, err := os.Lstat(finalPath)
	if err != nil {
		return false, fmt.Errorf("reinspect existing FI custody object: %w", err)
	}
	if !os.SameFile(openedInfo, afterInfo) {
		return false, errors.New("existing FI custody object changed during comparison")
	}
	if afterInfo.Mode().Perm() != 0o400 {
		return false, errors.New("existing FI custody object mode changed during comparison")
	}
	if afterInfo.Size() != expectedSize {
		return false, errors.New("existing FI custody object size changed during comparison")
	}

	return exact, nil
}

func filesExactlyEqual(first *os.File, second *os.File, size int64) (bool, error) {
	firstBuffer := make([]byte, custodyCompareBufferBytes)
	secondBuffer := make([]byte, custodyCompareBufferBytes)
	remaining := size

	for remaining > 0 {
		chunk := int64(custodyCompareBufferBytes)
		if remaining < chunk {
			chunk = remaining
		}

		firstPart := firstBuffer[:int(chunk)]
		secondPart := secondBuffer[:int(chunk)]
		if _, err := io.ReadFull(first, firstPart); err != nil {
			return false, fmt.Errorf("read existing FI custody object for comparison: %w", err)
		}
		if _, err := io.ReadFull(second, secondPart); err != nil {
			return false, fmt.Errorf("read provisional FI custody object for comparison: %w", err)
		}
		if !bytes.Equal(firstPart, secondPart) {
			return false, nil
		}

		remaining -= chunk
	}

	return true, nil
}

func newDurableCustodyResult(
	intake IntakeResult,
	info os.FileInfo,
	finalPath string,
	frameSHA256 string,
	disposition CustodyDisposition,
) DurableCustodyResult {
	descriptor := intake.Header.SignedBatch.Descriptor
	return DurableCustodyResult{
		BatchID:        descriptor.BatchID,
		DataBytes:      intake.DataBytes,
		DataSHA256:     intake.DataSHA256,
		Disposition:    disposition,
		FrameBytes:     uint64(info.Size()),
		FramePath:      finalPath,
		FrameSHA256:    frameSHA256,
		ManifestSHA256: descriptor.ManifestSHA256,
		SourceID:       descriptor.SourceID,
	}
}

func syncCustodyDirectory(path string) error {
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

func validateCustodyConfig(config CustodyConfig) error {
	if config.RootDir == "" {
		return errors.New("durable custody root directory is required")
	}
	if !filepath.IsAbs(config.RootDir) {
		return errors.New("durable custody root directory must be absolute")
	}
	if err := validateIntakeConfig(config.Intake); err != nil {
		return fmt.Errorf("validate receiver intake config: %w", err)
	}

	resolvedRoot, err := filepath.EvalSymlinks(config.RootDir)
	if err != nil {
		return fmt.Errorf("resolve durable custody root directory: %w", err)
	}
	if filepath.Clean(resolvedRoot) != filepath.Clean(config.RootDir) {
		return errors.New(
			"durable custody root directory path must not traverse symlinks",
		)
	}

	info, err := os.Lstat(config.RootDir)
	if err != nil {
		return fmt.Errorf("inspect durable custody root directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("durable custody root directory must not be a symlink")
	}
	if !info.IsDir() {
		return errors.New("durable custody root path must be a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf(
			"durable custody root directory must not be group- or other-writable: mode=%04o",
			info.Mode().Perm(),
		)
	}

	return nil
}
