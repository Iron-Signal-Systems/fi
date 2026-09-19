// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package generationrecorder

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

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const recordedIdentityDomain = "FI-GENERATION-RECORDED-IDENTITY-V1"

var ErrRecordedGenerationConflict = errors.New(
	"FI generation identity conflicts with existing durable recorder receipt",
)

// DurableConfig defines the immutable backend recorder receipt boundary.
type DurableConfig struct {
	RootDir  string
	Semantic Config
}

// RecordedDisposition describes how one semantically validated generation
// satisfied the durable recorder receipt boundary.
type RecordedDisposition string

const (
	RecordedDispositionAlreadyRecorded RecordedDisposition = "ALREADY_RECORDED"
	RecordedDispositionNew             RecordedDisposition = "NEW"
)

// DurableResult identifies one generation that crossed the durable recorder
// receipt boundary.
//
// This result still does not transmit a protocol acknowledgement. That wiring
// remains a separate receiver transaction step.
type DurableResult struct {
	Disposition   RecordedDisposition
	Receipt       RecordedReceipt
	ReceiptBytes  uint64
	ReceiptPath   string
	ReceiptSHA256 string
	Semantic      Result
}

// RecordCanonicalDurably validates one exact decoded canonical generation,
// binds the semantic result to an already-validated transfer identity, and
// atomically publishes a read-only recorder receipt.
//
// The exact FIGT transfer remains authoritative in durable transport custody.
// No acknowledgement or sender-retirement action occurs here.
func RecordCanonicalDurably(
	reader io.Reader,
	transfer transportgeneration.TransferResult,
	config DurableConfig,
) (
	DurableResult,
	error,
) {
	if reader == nil {
		return DurableResult{},
			errors.New(
				"FI generation recorder canonical reader is required",
			)
	}

	if err :=
		validateDurableConfig(
			config,
		); err != nil {
		return DurableResult{}, err
	}

	if err :=
		validateTransferResult(
			transfer,
		); err != nil {
		return DurableResult{}, err
	}

	canonicalHasher :=
		sha256.New()

	canonicalCounter :=
		&recordingCountWriter{}

	canonicalReader :=
		io.TeeReader(
			reader,
			io.MultiWriter(
				canonicalHasher,
				canonicalCounter,
			),
		)

	semantic, err :=
		ValidateCanonical(
			canonicalReader,
			transfer.Descriptor,
			config.Semantic,
		)
	if err != nil {
		return DurableResult{}, err
	}

	var extra [1]byte

	n, extraErr :=
		canonicalReader.Read(
			extra[:],
		)

	if n != 0 ||
		!errors.Is(
			extraErr,
			io.EOF,
		) {
		return DurableResult{},
			errors.New(
				"FI generation recorder canonical stream contains trailing bytes or did not terminate cleanly",
			)
	}

	if canonicalCounter.bytes !=
		transfer.Descriptor.CanonicalBytes {
		return DurableResult{},
			fmt.Errorf(
				"FI generation recorder canonical byte count %d does not match signed descriptor %d",
				canonicalCounter.bytes,
				transfer.Descriptor.CanonicalBytes,
			)
	}

	canonicalSHA256 :=
		hex.EncodeToString(
			canonicalHasher.Sum(
				nil,
			),
		)

	if canonicalSHA256 !=
		transfer.Descriptor.CanonicalSHA256 {
		return DurableResult{},
			errors.New(
				"FI generation recorder canonical SHA-256 does not match signed descriptor",
			)
	}

	return publishRecordedSemanticResult(
		transfer,
		semantic,
		config,
	)
}

func publishRecordedSemanticResult(
	transfer transportgeneration.TransferResult,
	semantic Result,
	config DurableConfig,
) (
	DurableResult,
	error,
) {
	receipt, err :=
		recordedReceiptFromResult(
			transfer,
			semantic,
		)
	if err != nil {
		return DurableResult{}, err
	}

	raw, err :=
		MarshalRecordedReceipt(
			receipt,
		)
	if err != nil {
		return DurableResult{}, err
	}

	receiptDigest :=
		sha256.Sum256(
			raw,
		)

	receiptSHA256 :=
		hex.EncodeToString(
			receiptDigest[:],
		)

	finalPath :=
		filepath.Join(
			config.RootDir,
			recordedObjectName(
				receipt.Descriptor.SourceID,
				receipt.Descriptor.GenerationID,
			),
		)

	disposition, err :=
		publishRecordedReceipt(
			config.RootDir,
			finalPath,
			raw,
		)
	if err != nil {
		return DurableResult{}, err
	}

	return DurableResult{
		Disposition: disposition,

		Receipt: receipt,

		ReceiptBytes: uint64(
			len(raw),
		),

		ReceiptPath: finalPath,

		ReceiptSHA256: receiptSHA256,

		Semantic: semantic,
	}, nil
}

func compareRecordedReceipt(
	path string,
	expected []byte,
) (
	bool,
	error,
) {
	initial, err :=
		os.Lstat(
			path,
		)
	if err != nil {
		return false, err
	}

	if initial.Mode()&
		os.ModeSymlink != 0 ||
		!initial.Mode().IsRegular() ||
		initial.Mode().Perm() != 0o400 {
		return false,
			errors.New(
				"existing FI generation recorder receipt must be a read-only regular file",
			)
	}

	if initial.Size() !=
		int64(
			len(expected),
		) {
		return false, nil
	}

	file, err :=
		os.Open(
			path,
		)
	if err != nil {
		return false, err
	}

	opened, err :=
		file.Stat()
	if err != nil {
		_ = file.Close()
		return false, err
	}

	if !os.SameFile(
		initial,
		opened,
	) {
		_ = file.Close()
		return false,
			errors.New(
				"existing FI generation recorder receipt changed while being opened",
			)
	}

	actual :=
		make(
			[]byte,
			len(expected),
		)

	if _, err :=
		io.ReadFull(
			file,
			actual,
		); err != nil {
		_ = file.Close()
		return false, err
	}

	var extra [1]byte

	extraCount, extraErr :=
		file.Read(
			extra[:],
		)
	if extraCount != 0 ||
		!errors.Is(
			extraErr,
			io.EOF,
		) {
		_ = file.Close()
		return false,
			errors.New(
				"existing FI generation recorder receipt contains trailing bytes",
			)
	}

	if err :=
		file.Close(); err != nil {
		return false, err
	}

	final, err :=
		os.Lstat(
			path,
		)
	if err != nil {
		return false, err
	}

	if !os.SameFile(
		initial,
		final,
	) {
		return false,
			errors.New(
				"existing FI generation recorder receipt changed during comparison",
			)
	}

	return bytes.Equal(
		actual,
		expected,
	), nil
}

func publishRecordedReceipt(
	root string,
	finalPath string,
	raw []byte,
) (
	RecordedDisposition,
	error,
) {
	provisional, err :=
		os.CreateTemp(
			root,
			".fi-generation-recorded-*.open",
		)
	if err != nil {
		return "",
			fmt.Errorf(
				"create provisional FI generation recorder receipt: %w",
				err,
			)
	}

	provisionalPath :=
		provisional.Name()

	provisionalOpen :=
		true

	keepProvisional :=
		true

	defer func() {
		if provisionalOpen {
			_ = provisional.Close()
		}

		if keepProvisional {
			_ = os.Remove(
				provisionalPath,
			)
		}
	}()

	if err :=
		writeAllRecorded(
			provisional,
			raw,
		); err != nil {
		return "", err
	}

	if err :=
		provisional.Chmod(
			0o400,
		); err != nil {
		return "",
			fmt.Errorf(
				"make provisional FI generation recorder receipt read-only: %w",
				err,
			)
	}

	if err :=
		provisional.Sync(); err != nil {
		return "",
			fmt.Errorf(
				"sync provisional FI generation recorder receipt: %w",
				err,
			)
	}

	if err :=
		provisional.Close(); err != nil {
		provisionalOpen = false
		return "",
			fmt.Errorf(
				"close provisional FI generation recorder receipt: %w",
				err,
			)
	}

	provisionalOpen =
		false

	info, err :=
		os.Lstat(
			provisionalPath,
		)
	if err != nil {
		return "", err
	}

	if info.Mode()&
		os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o400 ||
		info.Size() !=
			int64(
				len(raw),
			) {
		return "",
			errors.New(
				"provisional FI generation recorder receipt failed publication invariants",
			)
	}

	if err :=
		os.Link(
			provisionalPath,
			finalPath,
		); err != nil {
		if !errors.Is(
			err,
			fs.ErrExist,
		) {
			return "",
				fmt.Errorf(
					"publish FI generation recorder receipt: %w",
					err,
				)
		}

		equal, compareErr :=
			compareRecordedReceipt(
				finalPath,
				raw,
			)

		if removeErr :=
			os.Remove(
				provisionalPath,
			); removeErr != nil {
			return "",
				fmt.Errorf(
					"remove duplicate/conflicting provisional FI generation recorder receipt: %w",
					removeErr,
				)
		}

		keepProvisional =
			false

		if syncErr :=
			syncRecordedDirectory(
				root,
			); syncErr != nil {
			return "", syncErr
		}

		if compareErr != nil {
			return "", compareErr
		}

		if !equal {
			return "",
				ErrRecordedGenerationConflict
		}

		return RecordedDispositionAlreadyRecorded,
			nil
	}

	if err :=
		os.Remove(
			provisionalPath,
		); err != nil {
		return "",
			fmt.Errorf(
				"remove provisional FI generation recorder receipt name after publication: %w",
				err,
			)
	}

	keepProvisional =
		false

	if err :=
		syncRecordedDirectory(
			root,
		); err != nil {
		return "", err
	}

	equal, err :=
		compareRecordedReceipt(
			finalPath,
			raw,
		)
	if err != nil {
		return "", err
	}

	if !equal {
		return "",
			errors.New(
				"published FI generation recorder receipt changed after durable publication",
			)
	}

	return RecordedDispositionNew,
		nil
}

func recordedObjectName(
	sourceID string,
	generationID string,
) string {
	hasher :=
		sha256.New()

	_, _ =
		hasher.Write(
			[]byte(
				recordedIdentityDomain,
			),
		)

	var length [8]byte

	binary.BigEndian.PutUint64(
		length[:],
		uint64(
			len(sourceID),
		),
	)

	_, _ =
		hasher.Write(
			length[:],
		)

	_, _ =
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

	_, _ =
		hasher.Write(
			length[:],
		)

	_, _ =
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
		".record.json"
}

type recordingCountWriter struct {
	bytes uint64
}

func (
	counter *recordingCountWriter,
) Write(
	value []byte,
) (
	int,
	error,
) {
	if uint64(
		len(value),
	) >
		^uint64(0)-
			counter.bytes {
		return 0,
			errors.New(
				"FI generation recorder canonical byte count overflow",
			)
	}

	counter.bytes +=
		uint64(
			len(value),
		)

	return len(value), nil
}

func syncRecordedDirectory(
	path string,
) error {
	directory, err :=
		os.Open(
			path,
		)
	if err != nil {
		return err
	}

	syncErr :=
		directory.Sync()

	closeErr :=
		directory.Close()

	return errors.Join(
		syncErr,
		closeErr,
	)
}

func validateDurableConfig(
	config DurableConfig,
) error {
	if err :=
		validateConfig(
			config.Semantic,
		); err != nil {
		return err
	}

	if config.RootDir == "" {
		return errors.New(
			"FI generation recorder root directory is required",
		)
	}

	if !filepath.IsAbs(
		config.RootDir,
	) {
		return errors.New(
			"FI generation recorder root directory must be absolute",
		)
	}

	clean :=
		filepath.Clean(
			config.RootDir,
		)

	resolved, err :=
		filepath.EvalSymlinks(
			clean,
		)
	if err != nil {
		return fmt.Errorf(
			"resolve FI generation recorder root directory: %w",
			err,
		)
	}

	if resolved != clean {
		return errors.New(
			"FI generation recorder root directory path must not traverse symlinks",
		)
	}

	info, err :=
		os.Lstat(
			clean,
		)
	if err != nil {
		return fmt.Errorf(
			"inspect FI generation recorder root directory: %w",
			err,
		)
	}

	if info.Mode()&
		os.ModeSymlink != 0 {
		return errors.New(
			"FI generation recorder root directory must not be a symlink",
		)
	}

	if !info.IsDir() {
		return errors.New(
			"FI generation recorder root path must be a directory",
		)
	}

	if info.Mode().Perm()&
		0o022 != 0 {
		return fmt.Errorf(
			"FI generation recorder root directory must not be group- or other-writable: mode=%04o",
			info.Mode().Perm(),
		)
	}

	return nil
}

func writeAllRecorded(
	writer io.Writer,
	value []byte,
) error {
	for len(value) > 0 {
		n, err :=
			writer.Write(
				value,
			)
		if err != nil {
			return err
		}

		if n <= 0 ||
			n > len(value) {
			return io.ErrShortWrite
		}

		value =
			value[n:]
	}

	return nil
}
