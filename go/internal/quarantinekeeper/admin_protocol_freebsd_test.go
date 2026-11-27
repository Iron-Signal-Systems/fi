// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func testAdminReleaseRequest() AdminReleaseRequest {
	return AdminReleaseRequest{
		Version:       AdminProtocolVersion,
		Operation:     "release",
		SourceID:      "m1-fixture-fs2019.local",
		ConfirmSource: "m1-fixture-fs2019.local",
		Reference:     "FI-M6A-TEST",
		Justification: "reviewed synthetic quarantine release",
	}
}

func TestAdminReleaseProtocolAcceptsExactConfirmation(t *testing.T) {
	request := testAdminReleaseRequest()
	var output bytes.Buffer
	if err := WriteAdminReleaseRequest(&output, request); err != nil {
		t.Fatal(err)
	}
	parsed, err := ReadAdminReleaseRequest(&output)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != request {
		t.Fatalf("round-trip mismatch: %+v", parsed)
	}
}

func TestAdminReleaseProtocolRejectsUnconfirmedSource(t *testing.T) {
	cases := []AdminReleaseRequest{
		{Version: 1, Operation: "release", SourceID: "m1-fixture-fs2019.local", ConfirmSource: "m1-fixture-fs22.local", Reference: "FI-1", Justification: "wrong source"},
		{Version: 1, Operation: "publish", SourceID: "m1-fixture-fs2019.local", ConfirmSource: "m1-fixture-fs2019.local", Reference: "FI-1", Justification: "wrong operation"},
		{Version: 1, Operation: "release", SourceID: "m1-fixture-fs2019.local", ConfirmSource: "m1-fixture-fs2019.local", Reference: "", Justification: "missing reference"},
	}
	for _, request := range cases {
		if err := request.Validate(); err == nil {
			t.Fatalf("accepted invalid request %+v", request)
		}
	}
}

func TestAdminReleaseProtocolRejectsDuplicateAndUnknownProperties(t *testing.T) {
	payloads := []string{
		`{"version":1,"operation":"release","source_id":"m1-fixture-fs2019.local","source_id":"m1-fixture-fs22.local","confirm_source":"m1-fixture-fs2019.local","reference":"FI-1","justification":"test"}`,
		`{"version":1,"operation":"release","source_id":"m1-fixture-fs2019.local","confirm_source":"m1-fixture-fs2019.local","reference":"FI-1","justification":"test","operator_uid":0}`,
	}
	for _, payload := range payloads {
		var framed bytes.Buffer
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
		framed.Write(length[:])
		framed.WriteString(payload)
		if _, err := ReadAdminReleaseRequest(&framed); err == nil {
			t.Fatalf("accepted untrusted property: %s", payload)
		}
	}
}

func TestAdminReleaseResponseRejectsAmbiguousStatus(t *testing.T) {
	cases := []AdminReleaseResponse{
		{Version: 1, Status: "released", AuditPath: ""},
		{Version: 1, Status: "released", AuditPath: "/tmp/intent", ErrorCode: "UNAUTHORIZED"},
		{Version: 1, Status: "error", AuditPath: "/tmp/intent", ErrorCode: "REJECTED"},
		{Version: 1, Status: "error", ErrorCode: ""},
	}
	for _, response := range cases {
		if err := response.Validate(); err == nil {
			t.Fatalf("accepted invalid response: %+v", response)
		}
	}
	ok := AdminReleaseResponse{Version: 1, Status: "error", ErrorCode: "RELEASE_REJECTED"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (AdminReleaseRequest{
		Version: 1, Operation: "release", SourceID: "m1-fixture-fs2019.local",
		ConfirmSource: "m1-fixture-fs2019.local", Reference: "FI-M6A",
		Justification: strings.Repeat("x", 2049),
	}).Validate(); err == nil {
		t.Fatal("oversized justification accepted")
	}
}
