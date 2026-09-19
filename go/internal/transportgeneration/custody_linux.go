// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportgeneration

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
	generationCustodyCompareBufferBytes = 64 * 1024

	generationCustodyIdentityDomain = "FI-GENERATION-CUSTODY-IDENTITY-V1"
)

var ErrGenerationCustodyConflict = errors.New(
	"FI generation identity conflicts with existing durable custody bytes",
)

type CustodyDisposition string

const (
	CustodyDispositionDuplicate CustodyDisposition = "DUPLICATE"

	CustodyDispositionExisting CustodyDisposition = "EXISTING"

	CustodyDispositionNew CustodyDisposition = "NEW"
)

type CustodyConfig struct {
	Receive ReceiveConfig

	RootDir string
}

// CustodyResult means the exact generation transfer has crossed the durable
// transport-custody boundary.
//
// This is NOT recorder completion and MUST NOT by itself cause the sender's
// generation to be retired.
type CustodyResult struct {
	Disposition CustodyDisposition

	Transfer TransferResult

	CustodyBytes  uint64
	CustodyPath   string
	CustodySHA256 string
}

// ReceiveToDurableCustody consumes one exact FIGT0001 transfer, validates it,
// and atomically publishes the exact bytes consumed from the authenticated
// transport stream.
//
// The incoming stream is tee'd directly into one provisional custody file while
// ReadValidatedTransfer performs generation signature/trust, encoded payload,
// decompression, and canonical-format validation.
//
// No final custody identity is published unless validation succeeds and the
// provisional file has been fsynced.
//
// Publication uses os.Link so an existing deterministic custody object can
// never be silently replaced. An exact retry returns DUPLICATE. Different bytes
// for the same source/generation identity fail closed with
// ErrGenerationCustodyConflict.
func ReceiveToDurableCustody(
	reader io.Reader,
	offer Offer,
	config CustodyConfig,
) (
	CustodyResult,
	error,
) {
	if reader == nil {
		return CustodyResult{},
			errors.New(
				"FI generation custody reader is required",
			)
	}

	if err :=
		validateGenerationCustodyConfig(
			config,
		); err != nil {
		return CustodyResult{}, err
	}

	provisional, err :=
		os.CreateTemp(
			config.RootDir,
			".fi-generation-custody-*.open",
		)
	if err != nil {
		return CustodyResult{},
			fmt.Errorf(
				"create provisional FI generation custody object: %w",
				err,
			)
	}

	provisionalPath :=
		provisional.Name()

	provisionalOpen :=
		true

	removeProvisional :=
		true

	defer func() {
		if provisionalOpen {
			_ =
				provisional.Close()
		}

		if removeProvisional {
			_ =
				os.Remove(
					provisionalPath,
				)
		}
	}()

	custodyHasher :=
		sha256.New()

	custodyCounter :=
		&generationCountWriter{}

	tee :=
		io.TeeReader(
			reader,
			io.MultiWriter(
				provisional,
				custodyHasher,
				custodyCounter,
			),
		)

	transfer, err :=
		ReadValidatedTransfer(
			tee,
			offer,
			config.Receive,
		)
	if err != nil {
		return CustodyResult{},
			fmt.Errorf(
				"validate FI generation before durable custody: %w",
				err,
			)
	}

	if custodyCounter.bytes !=
		transfer.TransferBytes {
		return CustodyResult{},
			errors.New(
				"FI generation provisional custody byte count does not match validated transfer",
			)
	}

	custodySHA :=
		hex.EncodeToString(
			custodyHasher.Sum(
				nil,
			),
		)

	if custodySHA !=
		transfer.TransferSHA256 {
		return CustodyResult{},
			errors.New(
				"FI generation provisional custody SHA-256 does not match validated transfer",
			)
	}

	if err :=
		provisional.Chmod(
			0o400,
		); err != nil {
		return CustodyResult{},
			fmt.Errorf(
				"make provisional FI generation custody object read-only: %w",
				err,
			)
	}

	if err :=
		provisional.Sync(); err != nil {
		return CustodyResult{},
			fmt.Errorf(
				"sync provisional FI generation custody object: %w",
				err,
			)
	}

	if err :=
		provisional.Close(); err != nil {
		provisionalOpen =
			false

		return CustodyResult{},
			fmt.Errorf(
				"close provisional FI generation custody object: %w",
				err,
			)
	}

	provisionalOpen =
		false

	info, err :=
		os.Stat(
			provisionalPath,
		)
	if err != nil {
		return CustodyResult{},
			fmt.Errorf(
				"stat provisional FI generation custody object: %w",
				err,
			)
	}

	if !info.Mode().IsRegular() ||
		info.Mode().Perm() !=
			0o400 {
		return CustodyResult{},
			errors.New(
				"provisional FI generation custody object must be a read-only regular file",
			)
	}

	if info.Size() <= 0 ||
		uint64(
			info.Size(),
		) !=
			transfer.TransferBytes {
		return CustodyResult{},
			errors.New(
				"provisional FI generation custody object size does not match validated transfer",
			)
	}

	finalPath :=
		filepath.Join(
			config.RootDir,
			generationCustodyObjectName(
				transfer.Descriptor.SourceID,
				transfer.Descriptor.GenerationID,
			),
		)

	if err :=
		os.Link(
			provisionalPath,
			finalPath,
		); err != nil {
		if !errors.Is(
			err,
			fs.ErrExist,
		) {
			return CustodyResult{},
				fmt.Errorf(
					"publish FI generation durable custody object: %w",
					err,
				)
		}

		exact, compareErr :=
			generationCustodyFilesExactlyEqual(
				finalPath,
				provisionalPath,
				info.Size(),
			)

		if compareErr != nil {
			return CustodyResult{},
				compareErr
		}

		if err :=
			os.Remove(
				provisionalPath,
			); err != nil {
			return CustodyResult{},
				fmt.Errorf(
					"remove duplicate/conflicting provisional FI generation custody object: %w",
					err,
				)
		}

		removeProvisional =
			false

		if err :=
			syncGenerationCustodyDirectory(
				config.RootDir,
			); err != nil {
			return CustodyResult{},
				fmt.Errorf(
					"sync FI generation custody directory after identity collision: %w",
					err,
				)
		}

		if !exact {
			return CustodyResult{},
				fmt.Errorf(
					"%w: source=%q generation=%q path=%s",
					ErrGenerationCustodyConflict,
					transfer.Descriptor.SourceID,
					transfer.Descriptor.GenerationID,
					finalPath,
				)
		}

		return newGenerationCustodyResult(
			transfer,
			finalPath,
			CustodyDispositionDuplicate,
		), nil
	}

	if err :=
		os.Remove(
			provisionalPath,
		); err != nil {
		_ =
			os.Remove(
				finalPath,
			)

		return CustodyResult{},
			fmt.Errorf(
				"remove provisional FI generation custody name after publication: %w",
				err,
			)
	}

	removeProvisional =
		false

	if err :=
		syncGenerationCustodyDirectory(
			config.RootDir,
		); err != nil {
		return CustodyResult{},
			fmt.Errorf(
				"sync FI generation durable custody directory: %w",
				err,
			)
	}

	return newGenerationCustodyResult(
		transfer,
		finalPath,
		CustodyDispositionNew,
	), nil
}

func generationCustodyObjectName(
	sourceID string,
	generationID string,
) string {
	hasher :=
		sha256.New()

	_,
		_ =
		hasher.Write(
			[]byte(
				generationCustodyIdentityDomain,
			),
		)

	var length [8]byte

	binary.BigEndian.PutUint64(
		length[:],
		uint64(
			len(sourceID),
		),
	)

	_,
		_ =
		hasher.Write(
			length[:],
		)

	_,
		_ =
		hasher.Write(
			[]byte(
				sourceID,
			),
		)

	binary.BigEndian.PutUint64(
		length[:],
		uint64(
			len(generationID),
		),
	)

	_,
		_ =
		hasher.Write(
			length[:],
		)

	_,
		_ =
		hasher.Write(
			[]byte(
				generationID,
			),
		)

	return "generation-" +
		hex.EncodeToString(
			hasher.Sum(
				nil,
			),
		) +
		".figt"
}

func generationCustodyFilesExactlyEqual(
	firstPath string,
	secondPath string,
	expectedSize int64,
) (
	bool,
	error,
) {
	firstInfo, err :=
		os.Lstat(
			firstPath,
		)
	if err != nil {
		return false,
			fmt.Errorf(
				"inspect existing FI generation custody object: %w",
				err,
			)
	}

	if !firstInfo.Mode().IsRegular() ||
		firstInfo.Mode().Perm() !=
			0o400 ||
		firstInfo.Size() !=
			expectedSize {
		return false, nil
	}

	first, err :=
		os.Open(
			firstPath,
		)
	if err != nil {
		return false, err
	}

	defer first.Close()

	openedFirst, err :=
		first.Stat()
	if err != nil ||
		!os.SameFile(
			firstInfo,
			openedFirst,
		) {
		return false,
			errors.New(
				"existing FI generation custody object changed while being opened",
			)
	}

	secondInfo, err :=
		os.Lstat(
			secondPath,
		)
	if err != nil {
		return false, err
	}

	if !secondInfo.Mode().IsRegular() ||
		secondInfo.Size() !=
			expectedSize {
		return false, nil
	}

	second, err :=
		os.Open(
			secondPath,
		)
	if err != nil {
		return false, err
	}

	defer second.Close()

	openedSecond, err :=
		second.Stat()
	if err != nil ||
		!os.SameFile(
			secondInfo,
			openedSecond,
		) {
		return false,
			errors.New(
				"provisional FI generation custody object changed while being opened",
			)
	}

	firstBuffer :=
		make(
			[]byte,
			generationCustodyCompareBufferBytes,
		)

	secondBuffer :=
		make(
			[]byte,
			generationCustodyCompareBufferBytes,
		)

	remaining :=
		expectedSize

	for remaining > 0 {
		chunk :=
			int64(
				len(
					firstBuffer,
				),
			)

		if remaining <
			chunk {
			chunk =
				remaining
		}

		if _,
			err :=
			io.ReadFull(
				first,
				firstBuffer[:int(chunk)],
			); err != nil {
			return false, err
		}

		if _,
			err :=
			io.ReadFull(
				second,
				secondBuffer[:int(chunk)],
			); err != nil {
			return false, err
		}

		if !bytes.Equal(
			firstBuffer[:int(chunk)],
			secondBuffer[:int(chunk)],
		) {
			return false, nil
		}

		remaining -=
			chunk
	}

	currentFirst, err :=
		os.Lstat(
			firstPath,
		)
	if err != nil ||
		!os.SameFile(
			openedFirst,
			currentFirst,
		) ||
		currentFirst.Mode().Perm() !=
			0o400 ||
		currentFirst.Size() !=
			expectedSize {
		return false,
			errors.New(
				"existing FI generation custody object changed during comparison",
			)
	}

	currentSecond, err :=
		os.Lstat(
			secondPath,
		)
	if err != nil ||
		!os.SameFile(
			openedSecond,
			currentSecond,
		) ||
		currentSecond.Size() !=
			expectedSize {
		return false,
			errors.New(
				"provisional FI generation custody object changed during comparison",
			)
	}

	return true, nil
}

func newGenerationCustodyResult(
	transfer TransferResult,
	finalPath string,
	disposition CustodyDisposition,
) CustodyResult {
	return CustodyResult{
		Disposition: disposition,

		Transfer: transfer,

		CustodyBytes: transfer.TransferBytes,

		CustodyPath: finalPath,

		CustodySHA256: transfer.TransferSHA256,
	}
}

func syncGenerationCustodyDirectory(
	path string,
) error {
	directory, err :=
		os.Open(
			path,
		)
	if err != nil {
		return err
	}

	if err :=
		directory.Sync(); err != nil {
		_ =
			directory.Close()

		return err
	}

	return directory.Close()
}

func validateGenerationCustodyConfig(
	config CustodyConfig,
) error {
	if config.RootDir == "" {
		return errors.New(
			"FI generation durable custody root directory is required",
		)
	}

	if !filepath.IsAbs(
		config.RootDir,
	) {
		return errors.New(
			"FI generation durable custody root directory must be absolute",
		)
	}

	if err :=
		validateReceiveConfig(
			config.Receive,
		); err != nil {
		return fmt.Errorf(
			"validate FI generation receiver config: %w",
			err,
		)
	}

	resolvedRoot, err :=
		filepath.EvalSymlinks(
			config.RootDir,
		)
	if err != nil {
		return fmt.Errorf(
			"resolve FI generation durable custody root directory: %w",
			err,
		)
	}

	if filepath.Clean(
		resolvedRoot,
	) !=
		filepath.Clean(
			config.RootDir,
		) {
		return errors.New(
			"FI generation durable custody root directory path must not traverse symlinks",
		)
	}

	info, err :=
		os.Lstat(
			config.RootDir,
		)
	if err != nil {
		return fmt.Errorf(
			"inspect FI generation durable custody root directory: %w",
			err,
		)
	}

	if info.Mode()&
		os.ModeSymlink != 0 {
		return errors.New(
			"FI generation durable custody root directory must not be a symlink",
		)
	}

	if !info.IsDir() {
		return errors.New(
			"FI generation durable custody root path must be a directory",
		)
	}

	if info.Mode().Perm()&
		0o022 != 0 {
		return fmt.Errorf(
			"FI generation durable custody root directory must not be group- or other-writable: mode=%04o",
			info.Mode().Perm(),
		)
	}

	return nil
}
