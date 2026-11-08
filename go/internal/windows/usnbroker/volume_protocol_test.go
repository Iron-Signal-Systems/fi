// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestVolumeUSNWireRoundTrip(t *testing.T) {
	for _, want := range []request{
		{Operation: operationQueryVolume, EnrollmentID: "data"},
		{Operation: operationReadVolume, EnrollmentID: "system-volume", StartUSN: 15172277},
	} {
		var b bytes.Buffer
		if err := writeRequest(&b, want); err != nil {
			t.Fatal(err)
		}
		got, err := readRequest(&b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("decoded %+v, expected %+v", got, want)
		}
		if got.GovernedRoot != "" {
			t.Fatalf("volume operation accepted a raw path: %+v", got)
		}
	}
}

func TestVolumeUSNWireRejectsCallerDevicePathAndMixedFields(t *testing.T) {
	for _, tc := range []request{
		{Operation: operationQueryVolume, EnrollmentID: `\\.\C:`},
		{Operation: operationQueryVolume, EnrollmentID: `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`},
		{Operation: operationQueryVolume, EnrollmentID: "DATA"},
		{Operation: operationQueryVolume, EnrollmentID: "../data"},
		{Operation: operationQueryVolume, EnrollmentID: "data", GovernedRoot: `C:\FI`},
		{Operation: operationQueryVolume, EnrollmentID: "data", StartUSN: 1},
		{Operation: operationReadVolume, EnrollmentID: "data", FileReferenceNumber: 3},
		{Operation: operationReadVolume, EnrollmentID: "data", StartUSN: -1},
		{Operation: operationReadVolume, EnrollmentID: strings.Repeat("a", 65)},
		{Operation: operationQuery, GovernedRoot: `C:\FI`, EnrollmentID: "data"},
		{Operation: operationAuditPolicy, EnrollmentID: "data"},
	} {
		var b bytes.Buffer
		if err := writeRequest(&b, tc); err == nil || b.Len() != 0 {
			t.Fatalf("unsafe request %+v was encoded or partially emitted", tc)
		}
	}
}

func TestVolumeUSNWireRejectsMalformedNativeFrames(t *testing.T) {
	var valid bytes.Buffer
	if err := writeRequest(&valid, request{Operation: operationQueryVolume, EnrollmentID: "data"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		name string
		change func([]byte)
	}{
		{"empty enrollment", func(w []byte) { binary.LittleEndian.PutUint32(w[8:12], 0) }},
		{"path instead of enrollment", func(w []byte) { copy(w[requestHeaderSize:], []byte{'.', '.', '/', 'a'}) }},
		{"nonzero query parameter", func(w []byte) { binary.LittleEndian.PutUint64(w[12:20], 1) }},
		{"unknown operation", func(w []byte) { binary.LittleEndian.PutUint16(w[6:8], 65535) }},
	} {
		t.Run(bad.name, func(t *testing.T) {
			frame := append([]byte(nil), valid.Bytes()...)
			bad.change(frame)
			if _, err := readRequest(bytes.NewReader(frame)); err == nil {
				t.Fatal("unsafe volume wire frame accepted")
			}
		})
	}
}

func TestVolumeQueryReadDoNotChangeLegacyWireContract(t *testing.T) {
	for _, want := range []request{
		{Operation: operationQuery, GovernedRoot: `C:\FI-Lab`},
		{Operation: operationRead, GovernedRoot: `D:\Shares`, StartUSN: 34},
		{Operation: operationContainment, GovernedRoot: `D:\Shares`, FileReferenceNumber: 28, SequenceNumber: 4},
		{Operation: operationSACL, GovernedRoot: `D:\Shares`, FileReferenceNumber: 29, SequenceNumber: 2},
		{Operation: operationAuditPolicy},
	} {
		var b bytes.Buffer
		if err := writeRequest(&b, want); err != nil {
			t.Fatal(err)
		}
		got, err := readRequest(&b)
		if err != nil || got != want {
			t.Fatalf("legacy request %+v decoded %+v, error %v", want, got, err)
		}
	}
}
