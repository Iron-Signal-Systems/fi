// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestSignedGenerationRoundTripAndTamperDetection(
	t *testing.T,
) {
	key, certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	descriptor :=
		testGenerationDescriptor()

	signed, err :=
		NewSignedGeneration(
			descriptor,
			certificate,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	if signed.Descriptor !=
		descriptor {
		t.Fatal(
			"signed generation descriptor changed",
		)
	}

	parsed, err :=
		signed.BatchSigningCertificate()
	if err != nil {
		t.Fatal(err)
	}

	publicKey, ok :=
		parsed.PublicKey.(*rsa.PublicKey)

	if !ok ||
		publicKey == nil {
		t.Fatal(
			"signed generation certificate is not RSA",
		)
	}

	if err :=
		VerifySignedGenerationSignature(
			signed,
			publicKey,
		); err != nil {
		t.Fatal(err)
	}

	tampered :=
		signed

	digest :=
		sha256.Sum256(
			[]byte(
				"tampered-generation",
			),
		)

	tampered.Descriptor.EncodedDataSHA256 =
		hex.EncodeToString(
			digest[:],
		)

	if err :=
		VerifySignedGenerationSignature(
			tampered,
			publicKey,
		); err == nil {
		t.Fatal(
			"tampered generation descriptor verified",
		)
	}
}

func TestGenerationDescriptorValidation(
	t *testing.T,
) {
	tests :=
		[]struct {
			name   string
			mutate func(*Descriptor)
		}{
			{
				name: "wrong descriptor version",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.Version =
						"other"
				},
			},
			{
				name: "empty source ID",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.SourceID =
						""
				},
			},
			{
				name: "generation path separator",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.GenerationID =
						"bad/generation"
				},
			},
			{
				name: "wrong canonical version",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.CanonicalVersion =
						"other"
				},
			},
			{
				name: "wrong encoding",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.DataEncoding =
						"identity"
				},
			},
			{
				name: "zero artifacts",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.ArtifactCount =
						0
				},
			},
			{
				name: "zero canonical bytes",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.CanonicalBytes =
						0
				},
			},
			{
				name: "zero encoded bytes",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.EncodedDataBytes =
						0
				},
			},
			{
				name: "uppercase canonical hash",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.CanonicalSHA256 =
						strings.ToUpper(
							descriptor.CanonicalSHA256,
						)
				},
			},
			{
				name: "oversized source bytes",

				mutate: func(
					descriptor *Descriptor,
				) {
					descriptor.SourceBytes =
						uint64(
							1 << 63,
						)
				},
			},
		}

	for _, test := range tests {
		t.Run(
			test.name,
			func(
				t *testing.T,
			) {
				descriptor :=
					testGenerationDescriptor()

				test.mutate(
					&descriptor,
				)

				if err :=
					descriptor.Validate(); err == nil {
					t.Fatal(
						"invalid generation descriptor accepted",
					)
				}
			},
		)
	}
}

func TestSignedGenerationRejectsMismatchedSigner(
	t *testing.T,
) {
	_,
		certificate :=
		testGenerationSigningCertificate(
			t,
			"iss-fs-01.iss.local",
		)

	otherKey, err :=
		rsa.GenerateKey(
			rand.Reader,
			2048,
		)
	if err != nil {
		t.Fatal(err)
	}

	if _,
		err :=
		NewSignedGeneration(
			testGenerationDescriptor(),
			certificate,
			otherKey,
		); err == nil {
		t.Fatal(
			"mismatched generation signer accepted",
		)
	}
}

func testGenerationDescriptor() Descriptor {
	canonical :=
		sha256.Sum256(
			[]byte(
				"canonical-generation",
			),
		)

	encoded :=
		sha256.Sum256(
			[]byte(
				"encoded-generation",
			),
		)

	return Descriptor{
		Version: DescriptorVersion,

		SourceID: "iss-fs-01.iss.local",

		GenerationID: "20260918T130000.000000000Z-0011223344556677",

		CanonicalVersion: CanonicalVersion,

		DataEncoding: transportencoding.DataEncodingZstd,

		ArtifactCount: 912,

		SourceBytes: 32 << 20,

		CanonicalBytes: 33 << 20,

		CanonicalSHA256: hex.EncodeToString(
			canonical[:],
		),

		EncodedDataBytes: 8 << 20,

		EncodedDataSHA256: hex.EncodeToString(
			encoded[:],
		),
	}
}

func testGenerationSigningCertificate(
	t *testing.T,
	sourceID string,
) (
	*rsa.PrivateKey,
	*x509.Certificate,
) {
	t.Helper()

	key, err :=
		rsa.GenerateKey(
			rand.Reader,
			2048,
		)
	if err != nil {
		t.Fatal(err)
	}

	template :=
		&x509.Certificate{
			SerialNumber: big.NewInt(
				1,
			),

			Subject: pkix.Name{
				CommonName: sourceID,

				OrganizationalUnit: []string{
					transporttrust.BatchSigningOrganizationalUnit,
				},
			},

			NotBefore: time.Now().
				Add(
					-time.Hour,
				),

			NotAfter: time.Now().
				Add(
					time.Hour,
				),

			KeyUsage: x509.KeyUsageDigitalSignature,

			BasicConstraintsValid: true,
		}

	raw, err :=
		x509.CreateCertificate(
			rand.Reader,
			template,
			template,
			&key.PublicKey,
			key,
		)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err :=
		x509.ParseCertificate(
			raw,
		)
	if err != nil {
		t.Fatal(err)
	}

	return key, certificate
}
