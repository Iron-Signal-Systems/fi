// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
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

const custodyIdentityDomain = "FI-CUSTODY-IDENTITY-V1"

var ErrCustodyAlreadyExists = errors.New("FI batch durable custody object already exists")

// CustodyConfig defines the receiver storage boundary used after authenticated
// transport has reached the bounded batch-intake contract.
type CustodyConfig struct {
	Intake  IntakeConfig
	RootDir string
}

// DurableCustodyResult identifies one FI wire batch whose exact received frame
// has crossed the durable backend-custody boundary.
//
// A successful return means the exact validated wire frame has been fsynced,
// published under a no-replace final name, and the containing directory has
// been fsynced. Only a later receipt/acknowledgement contract may communicate
// that custody state to the source.
type DurableCustodyResult struct {
	BatchID        string
	DataBytes      uint64
	DataSHA256     string
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
// final identity path. os.Link never replaces an existing final object. After
// the provisional name is removed, the custody root is fsynced. This makes a
// successful return the durable publication boundary without requiring a
// second copy or a second serialization of the received frame.
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

	if err := os.Link(provisionalPath, finalPath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return DurableCustodyResult{}, fmt.Errorf(
				"%w: %s",
				ErrCustodyAlreadyExists,
				finalPath,
			)
		}

		return DurableCustodyResult{}, fmt.Errorf(
			"publish FI durable custody object: %w",
			err,
		)
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

	return DurableCustodyResult{
		BatchID:        descriptor.BatchID,
		DataBytes:      intake.DataBytes,
		DataSHA256:     intake.DataSHA256,
		FrameBytes:     uint64(info.Size()),
		FramePath:      finalPath,
		FrameSHA256:    hex.EncodeToString(frameHasher.Sum(nil)),
		ManifestSHA256: descriptor.ManifestSHA256,
		SourceID:       descriptor.SourceID,
	}, nil
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
