// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	ProtocolVersion = 1
	MaxUSNDataBytes = 1024 * 1024

	operationQuery       uint16 = 1
	operationRead        uint16 = 2
	operationContainment uint16 = 3

	requestHeaderSize  = 24
	responseHeaderSize = 76
	maxRootBytes       = 32 * 1024
	maxErrorBytes      = 4 * 1024
)

var (
	requestMagic  = [4]byte{'F', 'I', 'U', 'Q'}
	responseMagic = [4]byte{'F', 'I', 'U', 'R'}
)

type ContainmentResult byte

const (
	ContainmentContained   ContainmentResult = 1
	ContainmentOutside     ContainmentResult = 2
	ContainmentUnavailable ContainmentResult = 3
)

type Journal struct {
	JournalID       uint64
	FirstUSN        int64
	NextUSN         int64
	LowestValidUSN  int64
	MaxUSN          int64
	MaximumSize     uint64
	AllocationDelta uint64
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
		return fmt.Sprintf("FIUSNReader error %d: %s", err.Code, err.Message)
	}
	return "FIUSNReader error: " + err.Message
}

type request struct {
	Operation           uint16
	GovernedRoot        string
	StartUSN            int64
	FileReferenceNumber uint64
	SequenceNumber      uint16
}

type response struct {
	Journal   Journal
	Data      []byte
	ErrorCode uint32
	Error     string
}

func readRequest(reader io.Reader) (request, error) {
	var header [requestHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return request{}, err
	}
	if [4]byte(header[0:4]) != requestMagic {
		return request{}, errors.New("invalid FI USN request magic")
	}
	if binary.LittleEndian.Uint16(header[4:6]) != ProtocolVersion {
		return request{}, errors.New("unsupported FI USN protocol version")
	}

	operation := binary.LittleEndian.Uint16(header[6:8])
	rootLength := binary.LittleEndian.Uint32(header[8:12])
	payload := binary.LittleEndian.Uint64(header[12:20])
	auxiliary := binary.LittleEndian.Uint32(header[20:24])
	if rootLength == 0 || rootLength > maxRootBytes {
		return request{}, errors.New("invalid FI USN governed-root length")
	}

	value := request{Operation: operation}
	switch operation {
	case operationQuery:
		if payload != 0 || auxiliary != 0 {
			return request{}, errors.New("FI USN query request contains unexpected fields")
		}
	case operationRead:
		value.StartUSN = int64(payload)
		if value.StartUSN < 0 {
			return request{}, errors.New("FI USN start USN must not be negative")
		}
		if auxiliary != 0 {
			return request{}, errors.New("FI USN read request reserved field is not zero")
		}
	case operationContainment:
		if payload >= 1<<48 {
			return request{}, errors.New("FI USN containment file reference exceeds 48 bits")
		}
		if auxiliary>>16 != 0 {
			return request{}, errors.New("FI USN containment reserved field is not zero")
		}
		value.FileReferenceNumber = payload
		value.SequenceNumber = uint16(auxiliary)
	default:
		return request{}, errors.New("unsupported FI USN operation")
	}

	rootBytes := make([]byte, int(rootLength))
	if _, err := io.ReadFull(reader, rootBytes); err != nil {
		return request{}, err
	}
	if !utf8.Valid(rootBytes) {
		return request{}, errors.New("FI USN governed root is not valid UTF-8")
	}
	value.GovernedRoot = string(rootBytes)
	return value, nil
}

func writeRequest(writer io.Writer, value request) error {
	rootBytes := []byte(value.GovernedRoot)
	if len(rootBytes) == 0 || len(rootBytes) > maxRootBytes || !utf8.Valid(rootBytes) {
		return errors.New("invalid FI USN governed root")
	}

	var payload uint64
	var auxiliary uint32
	switch value.Operation {
	case operationQuery:
		if value.StartUSN != 0 || value.FileReferenceNumber != 0 || value.SequenceNumber != 0 {
			return errors.New("FI USN query request contains unexpected fields")
		}
	case operationRead:
		if value.StartUSN < 0 {
			return errors.New("FI USN start USN must not be negative")
		}
		if value.FileReferenceNumber != 0 || value.SequenceNumber != 0 {
			return errors.New("FI USN read request contains unexpected containment fields")
		}
		payload = uint64(value.StartUSN)
	case operationContainment:
		if value.StartUSN != 0 {
			return errors.New("FI USN containment request has unexpected start USN")
		}
		if value.FileReferenceNumber >= 1<<48 {
			return errors.New("FI USN containment file reference exceeds 48 bits")
		}
		payload = value.FileReferenceNumber
		auxiliary = uint32(value.SequenceNumber)
	default:
		return errors.New("unsupported FI USN operation")
	}

	var header [requestHeaderSize]byte
	copy(header[0:4], requestMagic[:])
	binary.LittleEndian.PutUint16(header[4:6], ProtocolVersion)
	binary.LittleEndian.PutUint16(header[6:8], value.Operation)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(rootBytes)))
	binary.LittleEndian.PutUint64(header[12:20], payload)
	binary.LittleEndian.PutUint32(header[20:24], auxiliary)

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
		return response{}, errors.New("invalid FI USN response magic")
	}
	if binary.LittleEndian.Uint16(header[4:6]) != ProtocolVersion {
		return response{}, errors.New("unsupported FI USN protocol version")
	}

	status := binary.LittleEndian.Uint16(header[6:8])
	if status > 1 {
		return response{}, errors.New("invalid FI USN response status")
	}

	value := response{
		ErrorCode: binary.LittleEndian.Uint32(header[8:12]),
		Journal: Journal{
			JournalID:       binary.LittleEndian.Uint64(header[12:20]),
			FirstUSN:        int64(binary.LittleEndian.Uint64(header[20:28])),
			NextUSN:         int64(binary.LittleEndian.Uint64(header[28:36])),
			LowestValidUSN:  int64(binary.LittleEndian.Uint64(header[36:44])),
			MaxUSN:          int64(binary.LittleEndian.Uint64(header[44:52])),
			MaximumSize:     binary.LittleEndian.Uint64(header[52:60]),
			AllocationDelta: binary.LittleEndian.Uint64(header[60:68]),
		},
	}
	dataLength := binary.LittleEndian.Uint32(header[68:72])
	errorLength := binary.LittleEndian.Uint32(header[72:76])
	if dataLength > MaxUSNDataBytes {
		return response{}, errors.New("FI USN response exceeds data limit")
	}
	if errorLength > maxErrorBytes {
		return response{}, errors.New("FI USN response exceeds error limit")
	}
	if status == 0 && errorLength != 0 {
		return response{}, errors.New("successful FI USN response contains an error")
	}
	if status == 1 && dataLength != 0 {
		return response{}, errors.New("failed FI USN response contains data")
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
			return response{}, errors.New("FI USN response error is not valid UTF-8")
		}
		value.Error = string(errorBytes)
	}
	if status == 1 && value.Error == "" {
		value.Error = "unspecified helper failure"
	}
	return value, nil
}

func writeResponse(writer io.Writer, value response) error {
	if len(value.Data) > MaxUSNDataBytes {
		return errors.New("FI USN response exceeds data limit")
	}
	if len(value.Error) > maxErrorBytes || !utf8.ValidString(value.Error) {
		return errors.New("invalid FI USN response error")
	}
	if value.Error != "" && len(value.Data) != 0 {
		return errors.New("failed FI USN response must not contain data")
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
	binary.LittleEndian.PutUint64(header[12:20], value.Journal.JournalID)
	binary.LittleEndian.PutUint64(header[20:28], uint64(value.Journal.FirstUSN))
	binary.LittleEndian.PutUint64(header[28:36], uint64(value.Journal.NextUSN))
	binary.LittleEndian.PutUint64(header[36:44], uint64(value.Journal.LowestValidUSN))
	binary.LittleEndian.PutUint64(header[44:52], uint64(value.Journal.MaxUSN))
	binary.LittleEndian.PutUint64(header[52:60], value.Journal.MaximumSize)
	binary.LittleEndian.PutUint64(header[60:68], value.Journal.AllocationDelta)
	binary.LittleEndian.PutUint32(header[68:72], uint32(len(value.Data)))
	binary.LittleEndian.PutUint32(header[72:76], uint32(len(value.Error)))

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
