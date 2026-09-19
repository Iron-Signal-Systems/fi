// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	SignedGenerationMetadataName = "signed-generation.json"

	maxSignedGenerationMetadataBytes = 512 << 10
)

// MarshalSignedGeneration serializes one already-validated signed generation
// metadata object.
//
// The signature is over Descriptor.SignatureInput(), not over the JSON
// representation. JSON is the durable metadata envelope only.
func MarshalSignedGeneration(
	value SignedGeneration,
) ([]byte, error) {
	if err :=
		validateSignedGenerationCryptographically(
			value,
		); err != nil {
		return nil, err
	}

	raw, err :=
		json.Marshal(
			value,
		)
	if err != nil {
		return nil,
			fmt.Errorf(
				"marshal signed FI generation metadata: %w",
				err,
			)
	}

	if len(raw) == 0 ||
		len(raw) >
			maxSignedGenerationMetadataBytes {
		return nil,
			errors.New(
				"signed FI generation metadata size is outside bounds",
			)
	}

	return raw, nil
}

// UnmarshalSignedGeneration strictly parses and cryptographically validates
// one signed-generation metadata object.
//
// Trust-chain authorization is deliberately not performed here. This function
// proves that the embedded certificate and signature are internally
// self-consistent with the signed descriptor. Receiver authorization remains a
// separate transport-trust decision.
func UnmarshalSignedGeneration(
	raw []byte,
) (SignedGeneration, error) {
	if len(raw) == 0 ||
		len(raw) >
			maxSignedGenerationMetadataBytes {
		return SignedGeneration{},
			errors.New(
				"signed FI generation metadata size is outside bounds",
			)
	}

	decoder :=
		json.NewDecoder(
			bytes.NewReader(
				raw,
			),
		)

	decoder.DisallowUnknownFields()

	var value SignedGeneration

	if err :=
		decoder.Decode(
			&value,
		); err != nil {
		return SignedGeneration{},
			fmt.Errorf(
				"decode signed FI generation metadata: %w",
				err,
			)
	}

	var extra any

	if err :=
		decoder.Decode(
			&extra,
		); err != io.EOF {
		return SignedGeneration{},
			errors.New(
				"signed FI generation metadata contains trailing JSON",
			)
	}

	if err :=
		validateSignedGenerationCryptographically(
			value,
		); err != nil {
		return SignedGeneration{}, err
	}

	return value, nil
}

func validateSignedGenerationCryptographically(
	value SignedGeneration,
) error {
	if err :=
		value.Validate(); err != nil {
		return err
	}

	certificate, err :=
		value.BatchSigningCertificate()
	if err != nil {
		return err
	}

	publicKey, ok :=
		certificate.PublicKey.(*rsa.PublicKey)

	if !ok ||
		publicKey == nil {
		return errors.New(
			"signed FI generation certificate RSA public key is required",
		)
	}

	if err :=
		VerifySignedGenerationSignature(
			value,
			publicKey,
		); err != nil {
		return fmt.Errorf(
			"verify signed FI generation metadata: %w",
			err,
		)
	}

	return nil
}
