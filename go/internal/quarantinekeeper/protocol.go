// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package quarantinekeeper defines the bounded worker-to-keeper wire contract.
// Transport authentication, source enrollment, and storage custody are enforced
// by the separate keeper server, not by parsing a protocol message.
package quarantinekeeper

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	ProtocolVersion = 1
	MaxFrameBytes   = 4096
)

type Operation string

const (
	OperationRead    Operation = "read"
	OperationPublish Operation = "publish"
)

type Status string

const (
	StatusClear       Status = "clear"
	StatusQuarantined Status = "quarantined"
	StatusError       Status = "error"
)

type Request struct {
	Version      int       `json:"version"`
	Operation    Operation `json:"operation"`
	SourceID     string    `json:"source_id"`
	Reason       string    `json:"reason,omitempty"`
	GenerationID string    `json:"generation_id,omitempty"`
	Detail       string    `json:"detail,omitempty"`
}

type Response struct {
	Version   int    `json:"version"`
	SourceID  string `json:"source_id"`
	Status    Status `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

func (request Request) Validate() error {
	if request.Version != ProtocolVersion {
		return errors.New("unsupported quarantine keeper protocol version")
	}

	if !validSourceID(request.SourceID) {
		return errors.New("invalid quarantine keeper source ID")
	}

	switch request.Operation {
	case OperationRead:
		if request.Reason != "" ||
			request.GenerationID != "" ||
			request.Detail != "" {
			return errors.New(
				"quarantine read request must not carry publication fields",
			)
		}

	case OperationPublish:
		if !validUpperCode(request.Reason, 64) ||
			!validGenerationID(request.GenerationID) ||
			request.Detail == "" ||
			len(request.Detail) > 1024 ||
			strings.ContainsAny(request.Detail, "\x00\r\n") {
			return errors.New("invalid quarantine publication")
		}

	default:
		return errors.New("unsupported quarantine keeper operation")
	}

	return nil
}

func (response Response) Validate() error {
	if response.Version != ProtocolVersion ||
		!validSourceID(response.SourceID) {
		return errors.New("invalid quarantine keeper response identity")
	}

	switch response.Status {
	case StatusClear, StatusQuarantined:
		if response.ErrorCode != "" {
			return errors.New(
				"quarantine keeper success must not carry an error",
			)
		}

	case StatusError:
		if !validUpperCode(response.ErrorCode, 64) {
			return errors.New(
				"quarantine keeper error requires a bounded code",
			)
		}

	default:
		return errors.New(
			"unsupported quarantine keeper response status",
		)
	}

	return nil
}

func WriteRequest(writer io.Writer, request Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	return writeFrame(writer, request)
}

func ReadRequest(reader io.Reader) (Request, error) {
	var request Request

	err := readFrame(
		reader,
		&request,
		"version",
		"operation",
		"source_id",
		"reason",
		"generation_id",
		"detail",
	)
	if err != nil {
		return Request{}, err
	}

	if err := request.Validate(); err != nil {
		return Request{}, err
	}

	return request, nil
}

func WriteResponse(writer io.Writer, response Response) error {
	if err := response.Validate(); err != nil {
		return err
	}
	return writeFrame(writer, response)
}

func ReadResponse(reader io.Reader) (Response, error) {
	var response Response

	err := readFrame(
		reader,
		&response,
		"version",
		"source_id",
		"status",
		"error_code",
	)
	if err != nil {
		return Response{}, err
	}

	if err := response.Validate(); err != nil {
		return Response{}, err
	}

	return response, nil
}

func validSourceID(value string) bool {
	if len(value) == 0 ||
		len(value) > 253 ||
		strings.Contains(value, "..") {
		return false
	}

	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 ||
			len(label) > 63 ||
			!isLowerAlphanumeric(label[0]) ||
			!isLowerAlphanumeric(label[len(label)-1]) {
			return false
		}

		for i := 1; i+1 < len(label); i++ {
			if !isLowerAlphanumeric(label[i]) &&
				label[i] != '-' {
				return false
			}
		}
	}

	return true
}

func isLowerAlphanumeric(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9'
}

func validUpperCode(value string, limit int) bool {
	if len(value) == 0 ||
		len(value) > limit ||
		value[0] < 'A' ||
		value[0] > 'Z' {
		return false
	}

	for i := 1; i < len(value); i++ {
		c := value[i]

		if !(c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' ||
			c == '_') {
			return false
		}
	}

	return true
}

func validGenerationID(value string) bool {
	if len(value) > 256 {
		return false
	}

	for i := 0; i < len(value); i++ {
		c := value[i]

		if !(c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' ||
			c == '_' || c == '-' ||
			c == '.' || c == ':') {
			return false
		}
	}

	return !strings.Contains(value, "..")
}

func writeFrame(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if len(data) == 0 || len(data) > MaxFrameBytes {
		return errors.New(
			"quarantine keeper frame exceeds limit",
		)
	}

	frame := make([]byte, 4+len(data))

	binary.BigEndian.PutUint32(
		frame[:4],
		uint32(len(data)),
	)

	copy(frame[4:], data)

	for len(frame) > 0 {
		n, err := writer.Write(frame)
		if err != nil {
			return err
		}

		if n <= 0 || n > len(frame) {
			return io.ErrShortWrite
		}

		frame = frame[n:]
	}

	return nil
}

func readFrame(
	reader io.Reader,
	target any,
	allowed ...string,
) error {
	var header [4]byte

	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf(
			"read quarantine keeper frame header: %w",
			err,
		)
	}

	length := binary.BigEndian.Uint32(header[:])

	if length == 0 || length > MaxFrameBytes {
		return errors.New(
			"invalid quarantine keeper frame length",
		)
	}

	data := make([]byte, int(length))

	if _, err := io.ReadFull(reader, data); err != nil {
		return fmt.Errorf(
			"read quarantine keeper frame: %w",
			err,
		)
	}

	if err := validateStrictObject(data, allowed); err != nil {
		return err
	}

	return json.Unmarshal(data, target)
}

// validateStrictObject rejects unknown and duplicate properties.
// Duplicate JSON keys must not silently override earlier values.
func validateStrictObject(
	data []byte,
	allowed []string,
) error {
	decoder := json.NewDecoder(bytes.NewReader(data))

	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New(
			"quarantine keeper message must be a JSON object",
		)
	}

	accepted := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		accepted[name] = true
	}

	seen := make(map[string]bool, len(allowed))

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}

		key, ok := token.(string)

		if !ok || !accepted[key] || seen[key] {
			return errors.New(
				"unknown or duplicate quarantine keeper message property",
			)
		}

		seen[key] = true

		var value json.RawMessage

		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}

	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return errors.New(
			"invalid quarantine keeper JSON object ending",
		)
	}

	if _, err := decoder.Token(); err != io.EOF {
		return errors.New(
			"trailing quarantine keeper JSON data",
		)
	}

	return nil
}
