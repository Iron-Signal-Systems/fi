// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnbroker

import (
	"errors"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnraw"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

type fakeVolumeUSNSource struct {
	queryCalls int
	readCalls int
	guid string
	serial string
	startUSN int64
	err error
	raw []byte
}

func (source *fakeVolumeUSNSource) Query(guid, serial string) (usnraw.Journal, error) {
	source.queryCalls++
	source.guid, source.serial = guid, serial
	return usnraw.Journal{JournalID: 12, FirstUSN: 1, NextUSN: 100}, source.err
}
func (source *fakeVolumeUSNSource) Read(guid, serial string, startUSN int64) (usnraw.Journal, []byte, error) {
	source.readCalls++
	source.guid, source.serial, source.startUSN = guid, serial, startUSN
	if source.err != nil {
		return usnraw.Journal{}, nil, source.err
	}
	return usnraw.Journal{JournalID: 12, FirstUSN: 1, NextUSN: 100}, source.raw, nil
}

func TestVolumeUSNDispatchUsesOnlyServerSelectedIdentity(t *testing.T) {
	authority, err := newVolumeAuthoritySnapshot(approvedVolumeFixture(t), volumeDiscoveryFixture())
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeVolumeUSNSource{raw: make([]byte, 8)}
	result, err := dispatchEnrolledUSN(
		request{Operation: operationQueryVolume, EnrollmentID: "data"}, &authority, source,
	)
	if err != nil || result.Journal.JournalID != 12 || source.queryCalls != 1 ||
		source.guid != volumeDataGUID || source.serial != "15172277115761558407" ||
		source.readCalls != 0 {
		t.Fatalf("query violated target authorization: result=%+v source=%+v err=%v", result, source, err)
	}
	result, err = dispatchEnrolledUSN(
		request{Operation: operationReadVolume, EnrollmentID: "system", StartUSN: 55}, &authority, source,
	)
	if err != nil || source.readCalls != 1 || source.guid != volumeSystemGUID ||
		source.serial != "14888954410052949637" || source.startUSN != 55 ||
		len(result.Data) != 8 {
		t.Fatalf("read violated target authorization: result=%+v source=%+v err=%v", result, source, err)
	}
}

func TestVolumeUSNDispatchDenialDoesNotInvokeRawAccess(t *testing.T) {
	authority, err := newVolumeAuthoritySnapshot(approvedVolumeFixture(t), volumeDiscoveryFixture())
	if err != nil {
		t.Fatal(err)
	}
	tests := []request{
		{Operation: operationQueryVolume, EnrollmentID: "unapproved"},
		{Operation: operationQueryVolume, EnrollmentID: "../data"},
		{Operation: operationQueryVolume, EnrollmentID: "data", GovernedRoot: `\\.\C:`},
		{Operation: operationReadVolume, EnrollmentID: "data", StartUSN: -1},
		{Operation: operationReadVolume, EnrollmentID: "data", FileReferenceNumber: 1},
		{Operation: operationQuery, EnrollmentID: "data"},
	}
	for _, request := range tests {
		source := &fakeVolumeUSNSource{raw: make([]byte, 8)}
		_, err := dispatchEnrolledUSN(request, &authority, source)
		if !errors.Is(err, ErrVolumeAccessDenied) || source.queryCalls != 0 || source.readCalls != 0 {
			t.Fatalf("unsafe request %+v used native source: %+v error=%v", request, source, err)
		}
	}
	source := &fakeVolumeUSNSource{}
	if _, err := dispatchEnrolledUSN(request{Operation: operationQueryVolume, EnrollmentID: "data"}, nil, source); !errors.Is(err, ErrVolumeAccessDenied) {
		t.Fatal("volume-mode broker accepted absent volume authority")
	}
}

func TestVolumeUSNDispatchOfflineVolumeDoesNotBlockOthers(t *testing.T) {
	found := volumeDiscoveryFixture()
	found[0].Status = volumediscovery.Unavailable
	found[0].Detail = "offline"
	found[0].Serial64 = ""
	authority, err := newVolumeAuthoritySnapshot(approvedVolumeFixture(t), found)
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeVolumeUSNSource{}
	_, err = dispatchEnrolledUSN(request{Operation: operationQueryVolume, EnrollmentID: "data"}, &authority, source)
	if !errors.Is(err, ErrVolumeAccessDenied) || source.queryCalls != 0 {
		t.Fatalf("offline volume accessed: %v %+v", err, source)
	}
	_, err = dispatchEnrolledUSN(request{Operation: operationQueryVolume, EnrollmentID: "system"}, &authority, source)
	if err != nil || source.queryCalls != 1 {
		t.Fatalf("healthy unrelated volume blocked: %v %+v", err, source)
	}
}

func TestVolumeUSNDispatchPropagatesSourceErrorsAndRejectsMalformedBuffer(t *testing.T) {
	authority, err := newVolumeAuthoritySnapshot(approvedVolumeFixture(t), volumeDiscoveryFixture())
	if err != nil {
		t.Fatal(err)
	}
	nativeError := errors.New("Windows raw handle identity mismatch")
	source := &fakeVolumeUSNSource{err: nativeError}
	_, err = dispatchEnrolledUSN(request{Operation: operationQueryVolume, EnrollmentID: "data"}, &authority, source)
	if !errors.Is(err, nativeError) {
		t.Fatalf("source error concealed: %v", err)
	}
	source.err = nil
	for _, length := range []int{0, 7, MaxUSNDataBytes + 1} {
		source.raw = make([]byte, length)
		_, err := dispatchEnrolledUSN(request{Operation: operationReadVolume, EnrollmentID: "data", StartUSN: 10}, &authority, source)
		if err == nil || !strings.Contains(err.Error(), "bounded") {
			t.Fatalf("invalid raw buffer length %d was accepted: %v", length, err)
		}
	}
}
