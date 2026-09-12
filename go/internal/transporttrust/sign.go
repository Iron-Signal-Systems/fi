// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
)

// SignBatchDescriptor signs one validated FI transport batch descriptor using
// the Phase 2.2 batch-signature contract.
//
// The signer is expressed as crypto.Signer so the transport contract does not
// require an exportable private key. Version 0.1 requires an RSA signing key and
// produces RSA-PSS with SHA-256 using a salt length equal to the hash length.
func SignBatchDescriptor(
	descriptor transportbatch.Descriptor,
	signer crypto.Signer,
) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("batch signer is required")
	}

	input, err := descriptor.SignatureInput()
	if err != nil {
		return nil, fmt.Errorf("construct batch signature input: %w", err)
	}

	publicKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok || publicKey == nil {
		return nil, fmt.Errorf(
			"batch signer public key must be RSA for %s",
			BatchSignatureAlgorithm,
		)
	}

	digest := sha256.Sum256(input)
	options := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}

	signature, err := signer.Sign(
		rand.Reader,
		digest[:],
		options,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"sign FI batch using %s: %w",
			BatchSignatureAlgorithm,
			err,
		)
	}
	if len(signature) == 0 {
		return nil, errors.New("batch signer returned an empty signature")
	}

	if err := rsa.VerifyPSS(
		publicKey,
		crypto.SHA256,
		digest[:],
		signature,
		options,
	); err != nil {
		return nil, fmt.Errorf(
			"batch signer produced a signature invalid for %s: %w",
			BatchSignatureAlgorithm,
			err,
		)
	}

	return signature, nil
}
