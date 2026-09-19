// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationsealer

import (
	"context"
	"crypto/sha256"
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
	"unicode/utf8"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
)

const (
	CanonicalVersion = "fi-generation-canonical/0.1"

	canonicalChunkBytes = 1024 * 1024
	canonicalMagic      = "FI-GENERATION-CANONICAL-V1\x00"
	sealedExtension     = ".figz"
)

type Config struct {
	FrozenDir             string
	GenerationID          string
	MaxReadBytesPerSecond uint64
	SealedDir             string
}

type Result struct {
	CanonicalBytes  uint64
	CanonicalSHA256 string
	Elapsed         time.Duration
	EncodedBytes    uint64
	EncodedSHA256   string
	FileCount       uint64
	GenerationID    string
	SealedPath      string
	SourceBytes     uint64
}

func Seal(ctx context.Context, config Config) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("generation sealer context is required")
	}

	if err := validateConfig(config); err != nil {
		return Result{}, err
	}

	started := time.Now()

	entries, err := os.ReadDir(config.FrozenDir)
	if err != nil {
		return Result{}, fmt.Errorf(
			"read frozen FI generation directory: %w",
			err,
		)
	}

	names := make([]string, 0, len(entries))

	for _, entry := range entries {
		name := entry.Name()

		if !validEntryName(name) {
			return Result{}, fmt.Errorf(
				"frozen FI generation contains invalid artifact name %q",
				name,
			)
		}

		mode := entry.Type()

		if mode&os.ModeSymlink != 0 {
			return Result{}, fmt.Errorf(
				"frozen FI generation contains symlink %q",
				name,
			)
		}

		if entry.IsDir() {
			return Result{}, fmt.Errorf(
				"frozen FI generation contains nested directory %q",
				name,
			)
		}

		if mode != 0 && !mode.IsRegular() {
			return Result{}, fmt.Errorf(
				"frozen FI generation contains unsupported artifact %q",
				name,
			)
		}

		names = append(names, name)
	}

	if len(names) == 0 {
		return Result{}, errors.New(
			"frozen FI generation contains no artifacts",
		)
	}

	sort.Strings(names)

	finalPath := filepath.Join(
		config.SealedDir,
		"generation-"+config.GenerationID+sealedExtension,
	)

	if _, err := os.Lstat(finalPath); err == nil {
		return Result{}, errors.New(
			"sealed FI generation already exists",
		)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Result{}, fmt.Errorf(
			"inspect sealed FI generation path: %w",
			err,
		)
	}

	encoded, err := os.CreateTemp(
		config.SealedDir,
		".generation-"+config.GenerationID+"-*.open",
	)
	if err != nil {
		return Result{}, fmt.Errorf(
			"create provisional sealed FI generation: %w",
			err,
		)
	}

	encodedPath := encoded.Name()
	encodedOpen := true
	keepEncoded := false

	defer func() {
		if encodedOpen {
			_ = encoded.Close()
		}

		if !keepEncoded {
			_ = os.Remove(encodedPath)
		}
	}()

	encodedHasher := sha256.New()
	encodedCounter := &countWriter{}

	encoder, err := transportencoding.NewZstdEncoder(
		io.MultiWriter(
			encoded,
			encodedHasher,
			encodedCounter,
		),
	)
	if err != nil {
		return Result{}, err
	}

	canonicalHasher := sha256.New()
	canonicalCounter := &countWriter{}

	canonicalWriter := io.MultiWriter(
		encoder,
		canonicalHasher,
		canonicalCounter,
	)

	if err := writeCanonicalHeader(
		canonicalWriter,
		uint64(len(names)),
	); err != nil {
		_ = encoder.Close()
		return Result{}, err
	}

	limiter := newReadLimiter(
		config.MaxReadBytesPerSecond,
	)

	buffer := make(
		[]byte,
		canonicalChunkBytes,
	)

	var sourceBytes uint64

	for _, name := range names {
		if err := ctx.Err(); err != nil {
			_ = encoder.Close()
			return Result{}, err
		}

		if err := writeCanonicalFileStart(
			canonicalWriter,
			name,
		); err != nil {
			_ = encoder.Close()
			return Result{}, err
		}

		path := filepath.Join(
			config.FrozenDir,
			name,
		)

		file, err := os.Open(path)
		if err != nil {
			_ = encoder.Close()
			return Result{}, fmt.Errorf(
				"open frozen FI artifact %q: %w",
				name,
				err,
			)
		}

		var fileBytes uint64

		for {
			n, readErr := io.ReadFull(
				file,
				buffer,
			)

			if n > 0 {
				if err := writeCanonicalChunk(
					canonicalWriter,
					buffer[:n],
				); err != nil {
					_ = file.Close()
					_ = encoder.Close()
					return Result{}, err
				}

				fileBytes += uint64(n)
				sourceBytes += uint64(n)

				if err := limiter.Wait(
					ctx,
					uint64(n),
				); err != nil {
					_ = file.Close()
					_ = encoder.Close()
					return Result{}, err
				}
			}

			if errors.Is(readErr, io.EOF) {
				break
			}

			if errors.Is(readErr, io.ErrUnexpectedEOF) {
				break
			}

			if readErr != nil {
				_ = file.Close()
				_ = encoder.Close()
				return Result{}, fmt.Errorf(
					"read frozen FI artifact %q: %w",
					name,
					readErr,
				)
			}
		}

		if err := file.Close(); err != nil {
			_ = encoder.Close()
			return Result{}, fmt.Errorf(
				"close frozen FI artifact %q: %w",
				name,
				err,
			)
		}

		if err := writeCanonicalFileEnd(
			canonicalWriter,
			fileBytes,
		); err != nil {
			_ = encoder.Close()
			return Result{}, err
		}
	}

	if err := encoder.Close(); err != nil {
		return Result{}, fmt.Errorf(
			"finish FI generation zstd stream: %w",
			err,
		)
	}

	if encodedCounter.bytes == 0 {
		return Result{}, errors.New(
			"sealed FI generation encoded zero bytes",
		)
	}

	if err := encoded.Sync(); err != nil {
		return Result{}, fmt.Errorf(
			"sync sealed FI generation: %w",
			err,
		)
	}

	if err := encoded.Close(); err != nil {
		return Result{}, fmt.Errorf(
			"close sealed FI generation: %w",
			err,
		)
	}

	encodedOpen = false

	if err := os.Rename(
		encodedPath,
		finalPath,
	); err != nil {
		return Result{}, fmt.Errorf(
			"publish sealed FI generation: %w",
			err,
		)
	}

	keepEncoded = true

	return Result{
		CanonicalBytes:  canonicalCounter.bytes,
		CanonicalSHA256: hex.EncodeToString(canonicalHasher.Sum(nil)),
		Elapsed:         time.Since(started),
		EncodedBytes:    encodedCounter.bytes,
		EncodedSHA256:   hex.EncodeToString(encodedHasher.Sum(nil)),
		FileCount:       uint64(len(names)),
		GenerationID:    config.GenerationID,
		SealedPath:      finalPath,
		SourceBytes:     sourceBytes,
	}, nil
}

func validateConfig(config Config) error {
	if strings.TrimSpace(config.GenerationID) == "" ||
		!utf8.ValidString(config.GenerationID) ||
		strings.ContainsAny(
			config.GenerationID,
			"/\\\x00\r\n",
		) {
		return errors.New(
			"FI generation ID is invalid",
		)
	}

	if config.FrozenDir == "" ||
		!filepath.IsAbs(config.FrozenDir) {
		return errors.New(
			"FI frozen generation directory must be absolute",
		)
	}

	if config.SealedDir == "" ||
		!filepath.IsAbs(config.SealedDir) {
		return errors.New(
			"FI sealed generation directory must be absolute",
		)
	}

	frozenInfo, err := os.Lstat(
		config.FrozenDir,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect frozen FI generation directory: %w",
			err,
		)
	}

	if frozenInfo.Mode()&os.ModeSymlink != 0 ||
		!frozenInfo.IsDir() {
		return errors.New(
			"FI frozen generation path must name a real directory",
		)
	}

	if err := os.MkdirAll(
		config.SealedDir,
		0o700,
	); err != nil {
		return fmt.Errorf(
			"create FI sealed generation directory: %w",
			err,
		)
	}

	sealedInfo, err := os.Lstat(
		config.SealedDir,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect FI sealed generation directory: %w",
			err,
		)
	}

	if sealedInfo.Mode()&os.ModeSymlink != 0 ||
		!sealedInfo.IsDir() {
		return errors.New(
			"FI sealed generation path must name a real directory",
		)
	}

	return nil
}

func validEntryName(name string) bool {
	return name != "" &&
		utf8.ValidString(name) &&
		filepath.Base(name) == name &&
		!strings.ContainsAny(
			name,
			"/\\\x00\r\n",
		)
}

func writeCanonicalHeader(
	writer io.Writer,
	fileCount uint64,
) error {
	if _, err := io.WriteString(
		writer,
		canonicalMagic,
	); err != nil {
		return err
	}

	var value [8]byte

	binary.BigEndian.PutUint64(
		value[:],
		fileCount,
	)

	_, err := writer.Write(
		value[:],
	)

	return err
}

func writeCanonicalFileStart(
	writer io.Writer,
	name string,
) error {
	if uint64(len(name)) > uint64(^uint32(0)) {
		return errors.New(
			"FI generation artifact name exceeds uint32",
		)
	}

	var length [4]byte

	binary.BigEndian.PutUint32(
		length[:],
		uint32(len(name)),
	)

	if _, err := writer.Write(
		length[:],
	); err != nil {
		return err
	}

	_, err := io.WriteString(
		writer,
		name,
	)

	return err
}

func writeCanonicalChunk(
	writer io.Writer,
	value []byte,
) error {
	if len(value) == 0 {
		return errors.New(
			"FI generation canonical chunk cannot be empty",
		)
	}

	var length [4]byte

	binary.BigEndian.PutUint32(
		length[:],
		uint32(len(value)),
	)

	if _, err := writer.Write(
		length[:],
	); err != nil {
		return err
	}

	_, err := writer.Write(value)

	return err
}

func writeCanonicalFileEnd(
	writer io.Writer,
	fileBytes uint64,
) error {
	var marker [4]byte

	if _, err := writer.Write(
		marker[:],
	); err != nil {
		return err
	}

	var length [8]byte

	binary.BigEndian.PutUint64(
		length[:],
		fileBytes,
	)

	_, err := writer.Write(
		length[:],
	)

	return err
}

type countWriter struct {
	bytes uint64
}

func (writer *countWriter) Write(
	value []byte,
) (int, error) {
	if uint64(len(value)) > ^uint64(0)-writer.bytes {
		return 0, errors.New(
			"FI generation byte counter overflow",
		)
	}

	writer.bytes += uint64(len(value))

	return len(value), nil
}

type readLimiter struct {
	bytes uint64
	limit uint64
	start time.Time
}

func newReadLimiter(
	limit uint64,
) *readLimiter {
	return &readLimiter{
		limit: limit,
		start: time.Now(),
	}
}

func (limiter *readLimiter) Wait(
	ctx context.Context,
	count uint64,
) error {
	if limiter.limit == 0 ||
		count == 0 {
		return nil
	}

	if count > ^uint64(0)-limiter.bytes {
		return errors.New(
			"FI generation read limiter byte counter overflow",
		)
	}

	limiter.bytes += count

	wholeSeconds :=
		limiter.bytes /
			limiter.limit

	remainder :=
		limiter.bytes %
			limiter.limit

	target :=
		time.Duration(wholeSeconds)*
			time.Second +
			time.Duration(
				(remainder*uint64(time.Second))/
					limiter.limit,
			)

	delay :=
		target -
			time.Since(limiter.start)

	if delay <= 0 {
		return nil
	}

	timer :=
		time.NewTimer(delay)

	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()

	case <-timer.C:
		return nil
	}
}
