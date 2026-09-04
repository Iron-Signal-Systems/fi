// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"strconv"
	"testing"
)

func TestValidateContentPrefixObservationPresent(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: []byte{}},
		{name: "short", raw: []byte{0x25, 0x50, 0x44, 0x46}},
		{name: "maximum", raw: []byte{0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := ContentPrefixObservation{
				State:           ContentPrefixPresent,
				BytesObserved:   strconv.Itoa(len(test.raw)),
				PrefixBase64URL: base64.RawURLEncoding.EncodeToString(test.raw),
			}
			if err := ValidateContentPrefixObservation(value); err != nil {
				t.Fatalf("ValidateContentPrefixObservation() error = %v", err)
			}
		})
	}
}

func TestValidateContentPrefixObservationRejectsOversize(t *testing.T) {
	raw := make([]byte, ContentPrefixMaxBytes+1)
	value := ContentPrefixObservation{
		State:           ContentPrefixPresent,
		BytesObserved:   "17",
		PrefixBase64URL: base64.RawURLEncoding.EncodeToString(raw),
	}
	if err := ValidateContentPrefixObservation(value); err == nil {
		t.Fatal("ValidateContentPrefixObservation() error = nil, want oversize rejection")
	}
}

func TestValidateContentPrefixObservationRejectsLengthMismatch(t *testing.T) {
	value := ContentPrefixObservation{
		State:           ContentPrefixPresent,
		BytesObserved:   "4",
		PrefixBase64URL: base64.RawURLEncoding.EncodeToString([]byte{0x50, 0x4b, 0x03}),
	}
	if err := ValidateContentPrefixObservation(value); err == nil {
		t.Fatal("ValidateContentPrefixObservation() error = nil, want length mismatch rejection")
	}
}

func TestValidateContentPrefixObservationRejectsPaddedBase64(t *testing.T) {
	value := ContentPrefixObservation{
		State:           ContentPrefixPresent,
		BytesObserved:   "1",
		PrefixBase64URL: "TQ==",
	}
	if err := ValidateContentPrefixObservation(value); err == nil {
		t.Fatal("ValidateContentPrefixObservation() error = nil, want padded Base64URL rejection")
	}
}

func TestValidateContentPrefixObservationErrorState(t *testing.T) {
	value := ContentPrefixObservation{
		State:      ContentPrefixError,
		ReasonCode: "ContentReadFailed",
		Detail:     "read failed",
	}
	if err := ValidateContentPrefixObservation(value); err != nil {
		t.Fatalf("ValidateContentPrefixObservation() error = %v", err)
	}
}

func TestValidateContentPrefixObservationNotApplicableState(t *testing.T) {
	value := ContentPrefixObservation{State: ContentPrefixNotApplicable}
	if err := ValidateContentPrefixObservation(value); err != nil {
		t.Fatalf("ValidateContentPrefixObservation() error = %v", err)
	}
}
