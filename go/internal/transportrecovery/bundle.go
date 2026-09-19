// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportrecovery

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	BundleMagic             = "FIRB0001"
	maxSignedRecoveryHeader = uint64(512 << 10)
)

// BundleHeader is the bounded recovery frame header. IndexBytes and
// EncodedDataBytes delimit the exact two payload regions that follow.
type BundleHeader struct {
	Signed           SignedRecovery
	SignedBytes      uint64
	IndexBytes       uint64
	EncodedDataBytes uint64
}

func WriteBundleHeader(writer io.Writer, signed SignedRecovery, indexBytes, encodedBytes uint64) error {
	if writer == nil {
		return errors.New("recovery bundle writer is required")
	}
	if err := signed.Validate(); err != nil {
		return fmt.Errorf("validate signed recovery before framing: %w", err)
	}
	if indexBytes == 0 || indexBytes > maxRecoveryIndexBytes {
		return errors.New("recovery member index byte count is outside frame bounds")
	}
	if encodedBytes == 0 || encodedBytes > maxSignedStreamingBytes {
		return errors.New("recovery encoded byte count is outside frame bounds")
	}
	if signed.Descriptor.EncodedDataBytes != encodedBytes {
		return errors.New("recovery frame encoded byte count does not match signed descriptor")
	}

	header, err := json.Marshal(signed)
	if err != nil {
		return fmt.Errorf("marshal signed recovery header: %w", err)
	}
	if len(header) == 0 || uint64(len(header)) > maxSignedRecoveryHeader {
		return errors.New("signed recovery header size is outside bounds")
	}

	if _, err := io.WriteString(writer, BundleMagic); err != nil {
		return err
	}
	var lengths [20]byte
	binary.BigEndian.PutUint32(lengths[0:4], uint32(len(header)))
	binary.BigEndian.PutUint64(lengths[4:12], indexBytes)
	binary.BigEndian.PutUint64(lengths[12:20], encodedBytes)
	if _, err := writer.Write(lengths[:]); err != nil {
		return err
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	return nil
}

func ReadBundleHeader(reader io.Reader) (BundleHeader, error) {
	if reader == nil {
		return BundleHeader{}, errors.New("recovery bundle reader is required")
	}
	var magic [8]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		return BundleHeader{}, fmt.Errorf("read recovery bundle magic: %w", err)
	}
	if string(magic[:]) != BundleMagic {
		return BundleHeader{}, fmt.Errorf("recovery bundle magic must be %q", BundleMagic)
	}
	var lengths [20]byte
	if _, err := io.ReadFull(reader, lengths[:]); err != nil {
		return BundleHeader{}, fmt.Errorf("read recovery bundle lengths: %w", err)
	}
	signedBytes := uint64(binary.BigEndian.Uint32(lengths[0:4]))
	indexBytes := binary.BigEndian.Uint64(lengths[4:12])
	encodedBytes := binary.BigEndian.Uint64(lengths[12:20])
	if signedBytes == 0 || signedBytes > maxSignedRecoveryHeader {
		return BundleHeader{}, errors.New("signed recovery header byte count is outside bounds")
	}
	if indexBytes == 0 || indexBytes > maxRecoveryIndexBytes {
		return BundleHeader{}, errors.New("recovery index byte count is outside bounds")
	}
	if encodedBytes == 0 || encodedBytes > maxSignedStreamingBytes {
		return BundleHeader{}, errors.New("recovery encoded byte count is outside bounds")
	}

	raw := make([]byte, int(signedBytes))
	if _, err := io.ReadFull(reader, raw); err != nil {
		return BundleHeader{}, fmt.Errorf("read signed recovery header: %w", err)
	}
	decoder := json.NewDecoder(bytesReader(raw))
	decoder.DisallowUnknownFields()
	var signed SignedRecovery
	if err := decoder.Decode(&signed); err != nil {
		return BundleHeader{}, fmt.Errorf("decode signed recovery header: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return BundleHeader{}, errors.New("signed recovery header contains trailing JSON")
	}
	if err := signed.Validate(); err != nil {
		return BundleHeader{}, err
	}
	if signed.Descriptor.EncodedDataBytes != encodedBytes {
		return BundleHeader{}, errors.New("recovery frame encoded length does not match signed descriptor")
	}
	return BundleHeader{
		Signed:           signed,
		SignedBytes:      signedBytes,
		IndexBytes:       indexBytes,
		EncodedDataBytes: encodedBytes,
	}, nil
}

// tiny byte reader avoids importing bytes solely in callers that already use
// io.Reader contracts.
type sliceReader struct {
	value  []byte
	offset int
}

func bytesReader(value []byte) *sliceReader {
	return &sliceReader{value: value}
}

func (reader *sliceReader) Read(destination []byte) (int, error) {
	if reader.offset >= len(reader.value) {
		return 0, io.EOF
	}
	n := copy(destination, reader.value[reader.offset:])
	reader.offset += n
	return n, nil
}
