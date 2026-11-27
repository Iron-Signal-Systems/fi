// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerationOfferRoundTrip(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	offer, err :=
		OfferFromPublished(
			published,
		)
	if err != nil {
		t.Fatal(err)
	}

	if offer.Descriptor !=
		published.Signed.Descriptor {
		t.Fatal(
			"generation offer changed signed descriptor",
		)
	}

	var wire bytes.Buffer

	if err :=
		WriteOffer(
			&wire,
			offer,
		); err != nil {
		t.Fatal(err)
	}

	decoded, err :=
		ReadOffer(
			&wire,
		)
	if err != nil {
		t.Fatal(err)
	}

	if decoded !=
		offer {
		t.Fatal(
			"generation offer changed during protocol round trip",
		)
	}
}

func TestGenerationDecisionBindsOfferedIdentity(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	offer, err :=
		OfferFromPublished(
			published,
		)
	if err != nil {
		t.Fatal(err)
	}

	accepted, err :=
		NewDecision(
			offer,
			true,
			"",
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		DecisionMatchesOffer(
			accepted,
			offer,
		); err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer

	if err :=
		WriteDecision(
			&wire,
			accepted,
		); err != nil {
		t.Fatal(err)
	}

	decoded, err :=
		ReadDecision(
			&wire,
		)
	if err != nil {
		t.Fatal(err)
	}

	if decoded !=
		accepted {
		t.Fatal(
			"generation decision changed during protocol round trip",
		)
	}

	mismatched :=
		decoded

	mismatched.GenerationID =
		"20260918T150000.000000000Z-ffffffffffffffff"

	if err :=
		DecisionMatchesOffer(
			mismatched,
			offer,
		); err == nil {
		t.Fatal(
			"decision for another generation matched offer",
		)
	}

	rejected, err :=
		NewDecision(
			offer,
			false,
			"receiver capacity policy rejected generation",
		)
	if err != nil {
		t.Fatal(err)
	}

	if rejected.Accepted {
		t.Fatal(
			"rejected generation decision became accepted",
		)
	}
}

func TestGenerationAcknowledgementBindsExactTransfer(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	var transfer bytes.Buffer

	result, err :=
		WritePublishedGeneration(
			&transfer,
			published,
		)
	if err != nil {
		t.Fatal(err)
	}

	for _, outcome := range []string{
		AcknowledgementOutcomeRecorded,
		AcknowledgementOutcomeAlreadyRecorded,
	} {
		t.Run(
			outcome,
			func(
				t *testing.T,
			) {
				acknowledgement, err :=
					NewAcknowledgement(
						outcome,
						result,
					)
				if err != nil {
					t.Fatal(err)
				}

				if err :=
					AcknowledgementMatches(
						acknowledgement,
						result,
					); err != nil {
					t.Fatal(err)
				}

				var wire bytes.Buffer

				if err :=
					WriteAcknowledgement(
						&wire,
						acknowledgement,
					); err != nil {
					t.Fatal(err)
				}

				decoded, err :=
					ReadAcknowledgement(
						&wire,
					)
				if err != nil {
					t.Fatal(err)
				}

				if decoded !=
					acknowledgement {
					t.Fatal(
						"generation acknowledgement changed during protocol round trip",
					)
				}

				if err :=
					AcknowledgementMatches(
						decoded,
						result,
					); err != nil {
					t.Fatal(err)
				}
			},
		)
	}

	acknowledgement, err :=
		NewAcknowledgement(
			AcknowledgementOutcomeRecorded,
			result,
		)
	if err != nil {
		t.Fatal(err)
	}

	acknowledgement.TransferSHA256 =
		strings.Repeat(
			"0",
			64,
		)

	if err :=
		AcknowledgementMatches(
			acknowledgement,
			result,
		); err == nil {
		t.Fatal(
			"acknowledgement with different transfer SHA-256 matched",
		)
	}
}

func TestGenerationProtocolRejectsUnknownField(
	t *testing.T,
) {
	descriptor :=
		testGenerationDescriptor()

	raw, err :=
		json.Marshal(
			struct {
				Version string `json:"version"`

				Descriptor Descriptor `json:"descriptor"`

				MetadataBytes uint64 `json:"metadata_bytes"`

				MetadataSHA256 string `json:"metadata_sha256"`

				Unexpected bool `json:"unexpected"`
			}{
				Version: OfferVersion,

				Descriptor: descriptor,

				MetadataBytes: 100,

				MetadataSHA256: strings.Repeat(
					"a",
					64,
				),

				Unexpected: true,
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer

	var header [protocolHeaderBytes]byte

	copy(
		header[0:8],
		[]byte(
			OfferMagic,
		),
	)

	binary.BigEndian.PutUint32(
		header[8:12],
		uint32(
			len(raw),
		),
	)

	wire.Write(
		header[:],
	)

	wire.Write(
		raw,
	)

	if _,
		err :=
		ReadOffer(
			&wire,
		); err == nil {
		t.Fatal(
			"generation protocol accepted unknown JSON field",
		)
	}
}

func TestGenerationProtocolRejectsTrailingJSONInsideFrame(
	t *testing.T,
) {
	descriptor :=
		testGenerationDescriptor()

	offer :=
		Offer{
			Version: OfferVersion,

			Descriptor: descriptor,

			MetadataBytes: 100,

			MetadataSHA256: strings.Repeat(
				"a",
				64,
			),
		}

	raw, err :=
		json.Marshal(
			offer,
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

	var wire bytes.Buffer

	var header [protocolHeaderBytes]byte

	copy(
		header[0:8],
		[]byte(
			OfferMagic,
		),
	)

	binary.BigEndian.PutUint32(
		header[8:12],
		uint32(
			len(raw),
		),
	)

	wire.Write(
		header[:],
	)

	wire.Write(
		raw,
	)

	if _,
		err :=
		ReadOffer(
			&wire,
		); err == nil {
		t.Fatal(
			"generation protocol accepted trailing JSON inside framed object",
		)
	}
}

func TestGenerationAcknowledgementRejectsInconsistentTransferBytes(
	t *testing.T,
) {
	config :=
		testCreateGenerationConfig(
			t,
		)

	published, err :=
		CreateSealedGeneration(
			context.Background(),
			config,
		)
	if err != nil {
		t.Fatal(err)
	}

	var transfer bytes.Buffer

	result, err :=
		WritePublishedGeneration(
			&transfer,
			published,
		)
	if err != nil {
		t.Fatal(err)
	}

	acknowledgement, err :=
		NewAcknowledgement(
			AcknowledgementOutcomeRecorded,
			result,
		)
	if err != nil {
		t.Fatal(err)
	}

	acknowledgement.TransferBytes++

	if err :=
		acknowledgement.Validate(); err == nil {
		t.Fatal(
			"generation acknowledgement accepted inconsistent transfer byte count",
		)
	}
}
