// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package objbroker

import (
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	ProtocolVersion = 1

	operationObserveObject uint16 = 1

	requestHeaderSize  = 24
	responseHeaderSize = 20

	maxRootBytes  = 32 * 1024
	maxErrorBytes = 4 * 1024

	// The observation payload limit is derived from the current NTFS collector
	// ceilings rather than chosen as an arbitrary transport size.
	//
	// Stream enumeration is the dominant term. The native FILE_STREAM_INFO
	// buffer is capped at 4 MiB. Twelve times that source buffer covers the
	// duplicated/base64 stream-name projections plus per-entry JSON structure.
	//
	// DACL/security and SACL descriptors are each capped at 128 KiB and reparse
	// data at 16 KiB. Four times their combined source size covers raw base64
	// plus interpreted projections.
	//
	// Four path fields can each reach the collector's 64K UTF-16-unit path
	// ceiling. Eight times their source-byte size covers base64/JSON expansion.
	//
	// A final 1 MiB fixed allowance covers object/volume identities, metadata,
	// hashes, the 16-byte content prefix, warnings, timestamps, and JSON keys.
	maxNativeStreamSourceBytes     = 4 * 1024 * 1024
	maxSecurityDescriptorBytes     = 128 * 1024
	maxSACLDescriptorBytes         = 128 * 1024
	maxReparseSourceBytes          = 16 * 1024
	maxFinalPathUTF16Units         = 64 * 1024
	maxObservationPathFields       = 4
	observationFixedAllowanceBytes = 1 * 1024 * 1024

	MaxObservationBytes = 12*maxNativeStreamSourceBytes +
		4*(maxSecurityDescriptorBytes+maxSACLDescriptorBytes+maxReparseSourceBytes) +
		8*(maxObservationPathFields*maxFinalPathUTF16Units*2) +
		observationFixedAllowanceBytes
)

var (
	requestMagic  = [4]byte{'F', 'I', 'O', 'Q'}
	responseMagic = [4]byte{'F', 'I', 'O', 'R'}
)

type request struct {
	Operation           uint16
	GovernedRoot        string
	FileReferenceNumber uint64
	SequenceNumber      uint16
}

type response struct {
	Data      []byte
	ErrorCode uint32
	Error     string
}

type remoteError struct {
	Code    uint32
	Message string
}

func (err *remoteError) Error() string {
	if err == nil {
		return ""
	}
	if err.Code != 0 {
		return "FIObjReader error " + decimalUint32(err.Code) + ": " + err.Message
	}
	return "FIObjReader error: " + err.Message
}

func readRequest(reader io.Reader) (request, error) {
	var header [requestHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return request{}, err
	}
	if [4]byte(header[0:4]) != requestMagic {
		return request{}, errors.New("invalid FI object request magic")
	}
	if binary.LittleEndian.Uint16(header[4:6]) != ProtocolVersion {
		return request{}, errors.New("unsupported FI object protocol version")
	}

	operation := binary.LittleEndian.Uint16(header[6:8])
	rootLength := binary.LittleEndian.Uint32(header[8:12])
	fileReferenceNumber := binary.LittleEndian.Uint64(header[12:20])
	sequenceNumber := binary.LittleEndian.Uint16(header[20:22])
	reserved := binary.LittleEndian.Uint16(header[22:24])

	if operation != operationObserveObject {
		return request{}, errors.New("unsupported FI object operation")
	}
	if rootLength == 0 || rootLength > maxRootBytes {
		return request{}, errors.New("invalid FI object governed-root length")
	}
	if fileReferenceNumber >= 1<<48 {
		return request{}, errors.New("FI object file reference exceeds 48 bits")
	}
	if reserved != 0 {
		return request{}, errors.New("FI object request reserved field is not zero")
	}

	rootBytes := make([]byte, int(rootLength))
	if _, err := io.ReadFull(reader, rootBytes); err != nil {
		return request{}, err
	}
	if !utf8.Valid(rootBytes) {
		return request{}, errors.New("FI object governed root is not valid UTF-8")
	}

	return request{
		Operation:           operation,
		GovernedRoot:        string(rootBytes),
		FileReferenceNumber: fileReferenceNumber,
		SequenceNumber:      sequenceNumber,
	}, nil
}

func writeRequest(writer io.Writer, value request) error {
	if value.Operation != operationObserveObject {
		return errors.New("unsupported FI object operation")
	}

	rootBytes := []byte(value.GovernedRoot)
	if len(rootBytes) == 0 || len(rootBytes) > maxRootBytes || !utf8.Valid(rootBytes) {
		return errors.New("invalid FI object governed root")
	}
	if value.FileReferenceNumber >= 1<<48 {
		return errors.New("FI object file reference exceeds 48 bits")
	}

	var header [requestHeaderSize]byte
	copy(header[0:4], requestMagic[:])
	binary.LittleEndian.PutUint16(header[4:6], ProtocolVersion)
	binary.LittleEndian.PutUint16(header[6:8], value.Operation)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(rootBytes)))
	binary.LittleEndian.PutUint64(header[12:20], value.FileReferenceNumber)
	binary.LittleEndian.PutUint16(header[20:22], value.SequenceNumber)

	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, rootBytes)
}

func readResponse(reader io.Reader) (response, error) {
	var header [responseHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return response{}, err
	}
	if [4]byte(header[0:4]) != responseMagic {
		return response{}, errors.New("invalid FI object response magic")
	}
	if binary.LittleEndian.Uint16(header[4:6]) != ProtocolVersion {
		return response{}, errors.New("unsupported FI object protocol version")
	}

	status := binary.LittleEndian.Uint16(header[6:8])
	if status > 1 {
		return response{}, errors.New("invalid FI object response status")
	}

	value := response{
		ErrorCode: binary.LittleEndian.Uint32(header[8:12]),
	}
	dataLength := binary.LittleEndian.Uint32(header[12:16])
	errorLength := binary.LittleEndian.Uint32(header[16:20])

	if dataLength > MaxObservationBytes {
		return response{}, errors.New("FI object response exceeds observation limit")
	}
	if errorLength > maxErrorBytes {
		return response{}, errors.New("FI object response exceeds error limit")
	}
	if status == 0 && errorLength != 0 {
		return response{}, errors.New("successful FI object response contains an error")
	}
	if status == 1 && dataLength != 0 {
		return response{}, errors.New("failed FI object response contains observation data")
	}

	if dataLength != 0 {
		value.Data = make([]byte, int(dataLength))
		if _, err := io.ReadFull(reader, value.Data); err != nil {
			return response{}, err
		}
	}
	if errorLength != 0 {
		errorBytes := make([]byte, int(errorLength))
		if _, err := io.ReadFull(reader, errorBytes); err != nil {
			return response{}, err
		}
		if !utf8.Valid(errorBytes) {
			return response{}, errors.New("FI object response error is not valid UTF-8")
		}
		value.Error = string(errorBytes)
	}
	if status == 1 && value.Error == "" {
		value.Error = "unspecified helper failure"
	}

	return value, nil
}

func writeResponse(writer io.Writer, value response) error {
	if len(value.Data) > MaxObservationBytes {
		return errors.New("FI object response exceeds observation limit")
	}
	if len(value.Error) > maxErrorBytes || !utf8.ValidString(value.Error) {
		return errors.New("invalid FI object response error")
	}
	if value.Error != "" && len(value.Data) != 0 {
		return errors.New("failed FI object response must not contain observation data")
	}

	status := uint16(0)
	if value.Error != "" {
		status = 1
	}

	var header [responseHeaderSize]byte
	copy(header[0:4], responseMagic[:])
	binary.LittleEndian.PutUint16(header[4:6], ProtocolVersion)
	binary.LittleEndian.PutUint16(header[6:8], status)
	binary.LittleEndian.PutUint32(header[8:12], value.ErrorCode)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(value.Data)))
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(value.Error)))

	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	if err := writeAll(writer, value.Data); err != nil {
		return err
	}
	return writeAll(writer, []byte(value.Error))
}

func writeAll(writer io.Writer, value []byte) error {
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

func decimalUint32(value uint32) string {
	if value == 0 {
		return "0"
	}

	var digits [10]byte
	index := len(digits)
	for value != 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
