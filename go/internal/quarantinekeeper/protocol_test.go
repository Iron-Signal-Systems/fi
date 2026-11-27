// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package quarantinekeeper

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

const testSource = "iss-fs-2019.iss.local"

func TestKeeperReadAndPublicationFrames(t *testing.T) {
	cases := []Request{
		{
			Version:   ProtocolVersion,
			Operation: OperationRead,
			SourceID:  testSource,
		},
		{
			Version:      ProtocolVersion,
			Operation:    OperationPublish,
			SourceID:     testSource,
			Reason:       "RELATIONAL_CONFLICT",
			GenerationID: "m1-conflict",
			Detail:       "receipt mismatch",
		},
	}

	for _, request := range cases {
		var wire bytes.Buffer

		if err := WriteRequest(&wire, request); err != nil {
			t.Fatal(err)
		}

		decoded, err := ReadRequest(&wire)
		if err != nil {
			t.Fatal(err)
		}

		if decoded != request {
			t.Fatalf("request round trip: %#v", decoded)
		}
	}
}

func TestKeeperResponseStates(t *testing.T) {
	for _, status := range []Status{
		StatusClear,
		StatusQuarantined,
		StatusError,
	} {
		response := Response{
			Version:  ProtocolVersion,
			SourceID: testSource,
			Status:   status,
		}

		if status == StatusError {
			response.ErrorCode = "STORE_FAILURE"
		}

		var wire bytes.Buffer

		if err := WriteResponse(&wire, response); err != nil {
			t.Fatal(err)
		}

		got, err := ReadResponse(&wire)
		if err != nil {
			t.Fatal(err)
		}

		if got != response {
			t.Fatalf("response: %#v", got)
		}
	}
}

func TestKeeperProtocolHasNoReleaseOperation(t *testing.T) {
	cases := []Request{
		{
			Version:   ProtocolVersion,
			Operation: "release",
			SourceID:  testSource,
		},
		{
			Version:   ProtocolVersion,
			Operation: OperationRead,
			SourceID:  "../escape",
		},
		{
			Version:   ProtocolVersion,
			Operation: OperationRead,
			SourceID:  testSource,
			Reason:    "RELATIONAL_CONFLICT",
		},
		{
			Version:   ProtocolVersion,
			Operation: OperationPublish,
			SourceID:  testSource,
			Reason:    "RELATIONAL_CONFLICT",
			Detail:    "wrong\nnewline",
		},
		{
			Version:      ProtocolVersion,
			Operation:    OperationPublish,
			SourceID:     testSource,
			Reason:       "RELATIONAL_CONFLICT",
			Detail:       "missing valid generation",
			GenerationID: "../../escape",
		},
	}

	for i, request := range cases {
		var wire bytes.Buffer

		if err := WriteRequest(&wire, request); err == nil {
			t.Errorf("unsafe request %d accepted", i)
		}
	}
}

func TestKeeperRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"operation":"read","source_id":"` + testSource + `","operator":"claimed-admin"}`,
		`{"version":1,"operation":"read","source_id":"` + testSource + `","operation":"publish"}`,
		`{"version":1,"operation":"release","source_id":"` + testSource + `"}`,
		`{"version":1,"operation":"read","source_id":"` + testSource + `"} true`,
	} {
		wire := wireJSON(body)

		if _, err := ReadRequest(&wire); err == nil {
			t.Fatalf("unsafe JSON accepted: %q", body)
		}
	}
}

func TestKeeperRejectsTruncatedAndOversizedFrames(
	t *testing.T,
) {
	var oversized bytes.Buffer
	var header [4]byte

	binary.BigEndian.PutUint32(
		header[:],
		MaxFrameBytes+1,
	)

	oversized.Write(header[:])

	if _, err := ReadRequest(&oversized); err == nil {
		t.Fatal("oversized header accepted")
	}

	var truncated bytes.Buffer

	binary.BigEndian.PutUint32(header[:], 18)
	truncated.Write(header[:])
	truncated.WriteString(`{"version":1}`)

	if _, err := ReadRequest(&truncated); err == nil {
		t.Fatal("truncated frame accepted")
	}
}

func TestKeeperResponseCannotClaimClearWithError(
	t *testing.T,
) {
	response := Response{
		Version:   ProtocolVersion,
		SourceID:  testSource,
		Status:    StatusClear,
		ErrorCode: "STORE_FAILURE",
	}

	if err := WriteResponse(
		io.Discard,
		response,
	); err == nil {
		t.Fatal("clear response with error accepted")
	}

	request := Request{
		Version:   ProtocolVersion,
		Operation: OperationPublish,
		SourceID:  testSource,
		Reason:    "RELATIONAL_CONFLICT",
		Detail:    strings.Repeat("x", 5000),
	}

	if err := WriteRequest(
		io.Discard,
		request,
	); err == nil {
		t.Fatal("oversize publication accepted")
	}
}

func wireJSON(body string) bytes.Buffer {
	var wire bytes.Buffer
	var header [4]byte

	binary.BigEndian.PutUint32(
		header[:],
		uint32(len(body)),
	)

	wire.Write(header[:])
	wire.WriteString(body)

	return wire
}
