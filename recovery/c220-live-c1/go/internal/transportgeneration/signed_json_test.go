// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSignedGenerationJSONRoundTrip(
	t *testing.T,
) {
	key, certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	signed, err :=
		NewSignedGeneration(
			testGenerationDescriptor(),
			certificate,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	raw, err :=
		MarshalSignedGeneration(
			signed,
		)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err :=
		UnmarshalSignedGeneration(
			raw,
		)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Version !=
		signed.Version {
		t.Fatalf(
			"decoded version = %q, want %q",
			decoded.Version,
			signed.Version,
		)
	}

	if decoded.Descriptor !=
		signed.Descriptor {
		t.Fatal(
			"decoded generation descriptor changed",
		)
	}

	if !bytes.Equal(
		decoded.Signature,
		signed.Signature,
	) {
		t.Fatal(
			"decoded generation signature changed",
		)
	}

	if !bytes.Equal(
		decoded.BatchSigningCertificateDER,
		signed.BatchSigningCertificateDER,
	) {
		t.Fatal(
			"decoded generation certificate changed",
		)
	}
}

func TestSignedGenerationJSONRejectsUnknownField(
	t *testing.T,
) {
	key, certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	signed, err :=
		NewSignedGeneration(
			testGenerationDescriptor(),
			certificate,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	raw, err :=
		json.Marshal(
			struct {
				SignedGeneration

				Unexpected string `json:"unexpected"`
			}{
				SignedGeneration: signed,

				Unexpected: "must-fail",
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if _,
		err :=
		UnmarshalSignedGeneration(
			raw,
		); err == nil {
		t.Fatal(
			"signed generation metadata with unknown field was accepted",
		)
	}
}

func TestSignedGenerationJSONRejectsTrailingJSON(
	t *testing.T,
) {
	key, certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	signed, err :=
		NewSignedGeneration(
			testGenerationDescriptor(),
			certificate,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	raw, err :=
		MarshalSignedGeneration(
			signed,
		)
	if err != nil {
		t.Fatal(err)
	}

	raw =
		append(
			raw,
			[]byte(
				`{"trailing":true}`,
			)...,
		)

	if _,
		err :=
		UnmarshalSignedGeneration(
			raw,
		); err == nil {
		t.Fatal(
			"signed generation metadata with trailing JSON was accepted",
		)
	}
}

func TestSignedGenerationJSONRejectsTamperedDescriptor(
	t *testing.T,
) {
	key, certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	signed, err :=
		NewSignedGeneration(
			testGenerationDescriptor(),
			certificate,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	signed.Descriptor.SourceBytes++

	raw, err :=
		json.Marshal(
			signed,
		)
	if err != nil {
		t.Fatal(err)
	}

	if _,
		err :=
		UnmarshalSignedGeneration(
			raw,
		); err == nil {
		t.Fatal(
			"signed generation metadata with tampered descriptor was accepted",
		)
	}
}

func TestMarshalSignedGenerationRejectsInvalidSignature(
	t *testing.T,
) {
	key, certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	signed, err :=
		NewSignedGeneration(
			testGenerationDescriptor(),
			certificate,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	signed.Signature[0] ^= 0xff

	if _,
		err :=
		MarshalSignedGeneration(
			signed,
		); err == nil {
		t.Fatal(
			"signed generation with invalid signature was serialized",
		)
	}
}
