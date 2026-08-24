// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import "testing"

func TestValidateContentHashObservationPresent(t *testing.T) {
	value := ContentHashObservation{
		State:       ContentHashPresent,
		BytesHashed: "3",
		MD5:         "900150983cd24fb0d6963f7d28e17f72",
		SHA1:        "a9993e364706816aba3e25717850c26c9cd0d89d",
		SHA256:      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	if err := ValidateContentHashObservation(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateContentHashObservationRejectsUppercase(t *testing.T) {
	value := ContentHashObservation{
		State:       ContentHashPresent,
		BytesHashed: "3",
		MD5:         "900150983CD24FB0D6963F7D28E17F72",
		SHA1:        "a9993e364706816aba3e25717850c26c9cd0d89d",
		SHA256:      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	if err := ValidateContentHashObservation(value); err == nil {
		t.Fatal("uppercase MD5 accepted")
	}
}

func TestValidateContentHashObservationError(t *testing.T) {
	value := ContentHashObservation{State: ContentHashError, ReasonCode: "ContentOpenFailed", Detail: "access denied"}
	if err := ValidateContentHashObservation(value); err != nil {
		t.Fatal(err)
	}
}
