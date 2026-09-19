// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportrecovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
)

// ValidatePreparedFrameCanonical independently decodes a durable staged frame
// and proves that its compressed payload reproduces the exact signed member set.
// A caller may use successful validation as the local durability boundary before
// retiring the corresponding raw published batches from the source spool.
func ValidatePreparedFrameCanonical(prepared PreparedFrame) error {
	current, err := LoadPreparedFrame(prepared.FramePath)
	if err != nil {
		return fmt.Errorf("load staged FI frame for canonical validation: %w", err)
	}
	if current.Descriptor != prepared.Descriptor ||
		current.FrameBytes != prepared.FrameBytes ||
		current.FrameSHA256 != prepared.FrameSHA256 {
		return errors.New("staged FI frame changed before canonical validation")
	}

	file, err := os.Open(current.FramePath)
	if err != nil {
		return fmt.Errorf("open staged FI frame for canonical validation: %w", err)
	}
	defer file.Close()

	header, err := ReadBundleHeader(file)
	if err != nil {
		return fmt.Errorf("read staged FI bundle header for canonical validation: %w", err)
	}
	if header.Signed.Descriptor != current.Descriptor {
		return errors.New("staged FI bundle descriptor changed before canonical validation")
	}

	indexBytes := make([]byte, int(header.IndexBytes))
	if _, err := io.ReadFull(file, indexBytes); err != nil {
		return fmt.Errorf("read staged FI member index for canonical validation: %w", err)
	}
	indexSHA256, err := IndexSHA256(indexBytes)
	if err != nil {
		return err
	}
	if indexSHA256 != current.Descriptor.IndexSHA256 || !bytes.Equal(indexBytes, current.IndexBytes) {
		return errors.New("staged FI member index changed before canonical validation")
	}

	limited := &io.LimitedReader{
		R: file,
		N: int64(header.EncodedDataBytes),
	}
	encodedHasher := sha256.New()
	decoder, err := transportencoding.NewZstdDecoder(
		io.TeeReader(limited, encodedHasher),
	)
	if err != nil {
		return fmt.Errorf("open staged FI zstd payload for canonical validation: %w", err)
	}

	canonicalHasher := sha256.New()
	var canonicalBytes uint64
	for position, member := range current.Index.Members {
		manifestRaw := make([]byte, int(member.ManifestBytes))
		if _, err := io.ReadFull(decoder, manifestRaw); err != nil {
			decoder.Close()
			return fmt.Errorf("read staged FI member %d manifest: %w", position, err)
		}
		if _, err := canonicalHasher.Write(manifestRaw); err != nil {
			decoder.Close()
			return err
		}
		canonicalBytes += member.ManifestBytes
		if _, err := ValidateManifestBytes(manifestRaw, member); err != nil {
			decoder.Close()
			return fmt.Errorf("validate staged FI member %d manifest: %w", position, err)
		}

		dataHasher := sha256.New()
		recordCount, err := copyCanonicalJSONLExactly(
			io.MultiWriter(dataHasher, canonicalHasher),
			decoder,
			member.DataBytes,
		)
		if err != nil {
			decoder.Close()
			return fmt.Errorf("validate staged FI member %d data: %w", position, err)
		}
		if recordCount != member.RecordCount {
			decoder.Close()
			return fmt.Errorf(
				"staged FI member %d record count %d does not match signed count %d",
				position,
				recordCount,
				member.RecordCount,
			)
		}
		if hex.EncodeToString(dataHasher.Sum(nil)) != member.DataSHA256 {
			decoder.Close()
			return fmt.Errorf("staged FI member %d data SHA-256 mismatch", position)
		}
		canonicalBytes += member.DataBytes
	}

	var extra [1]byte
	n, readErr := decoder.Read(extra[:])
	decoder.Close()
	if n != 0 || !errors.Is(readErr, io.EOF) {
		return errors.New("staged FI decoded payload contains bytes beyond signed member set")
	}
	if limited.N != 0 {
		return errors.New("staged FI encoded payload contains unread bytes")
	}
	if canonicalBytes != current.Descriptor.CanonicalBytes ||
		hex.EncodeToString(canonicalHasher.Sum(nil)) != current.Descriptor.CanonicalSHA256 {
		return errors.New("staged FI canonical payload does not match signed descriptor")
	}
	if hex.EncodeToString(encodedHasher.Sum(nil)) != current.Descriptor.EncodedDataSHA256 {
		return errors.New("staged FI encoded payload SHA-256 does not match signed descriptor")
	}

	var trailing [1]byte
	if n, trailingErr := file.Read(trailing[:]); n != 0 || !errors.Is(trailingErr, io.EOF) {
		return errors.New("staged FI frame contains bytes beyond signed encoded payload")
	}
	return nil
}

func copyCanonicalJSONLExactly(
	writer io.Writer,
	reader io.Reader,
	byteCount uint64,
) (uint64, error) {
	if byteCount == 0 || byteCount > maxSignedStreamingBytes {
		return 0, errors.New("JSONL byte count is outside FI transport bounds")
	}

	remaining := byteCount
	buffer := make([]byte, 128*1024)
	var recordCount uint64
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
		recordCount += uint64(bytes.Count(part, []byte{'\n'}))
		last = part[len(part)-1]
		remaining -= uint64(n)
	}
	if last != '\n' {
		return 0, errors.New("FI transport member JSONL is missing final newline")
	}
	return recordCount, nil
}
