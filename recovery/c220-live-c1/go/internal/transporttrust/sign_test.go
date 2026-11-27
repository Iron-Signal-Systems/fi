// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
)

// Test types.

type invalidBatchSigner struct {
	publicKey *rsa.PublicKey
}

type recordingBatchSigner struct {
	key     *rsa.PrivateKey
	options crypto.SignerOpts
}

// Tests.

func TestSignBatchDescriptor(t *testing.T) {
	key := newBatchSigningPrivateKey(t)
	descriptor := validSourceSigningDescriptor()

	signature, err := SignBatchDescriptor(descriptor, key)
	if err != nil {
		t.Fatalf("SignBatchDescriptor() error = %v", err)
	}
	if len(signature) == 0 {
		t.Fatal("SignBatchDescriptor() returned empty signature")
	}

	input, err := descriptor.SignatureInput()
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input)
	if err := rsa.VerifyPSS(
		&key.PublicKey,
		crypto.SHA256,
		digest[:],
		signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	); err != nil {
		t.Fatalf("rsa.VerifyPSS() error = %v", err)
	}
}

func TestSignBatchDescriptorRejectsInvalidDescriptor(t *testing.T) {
	key := newBatchSigningPrivateKey(t)
	descriptor := validSourceSigningDescriptor()
	descriptor.BatchID = ""

	if _, err := SignBatchDescriptor(descriptor, key); err == nil {
		t.Fatal("SignBatchDescriptor() error = nil, want invalid descriptor rejection")
	}
}

func TestSignBatchDescriptorRejectsInvalidSignerOutput(t *testing.T) {
	key := newBatchSigningPrivateKey(t)
	signer := &invalidBatchSigner{publicKey: &key.PublicKey}

	_, err := SignBatchDescriptor(validSourceSigningDescriptor(), signer)
	if err == nil {
		t.Fatal("SignBatchDescriptor() error = nil, want invalid signature rejection")
	}
	if !strings.Contains(err.Error(), "produced a signature invalid") {
		t.Fatalf(
			"SignBatchDescriptor() error = %q, want invalid signature rejection",
			err,
		)
	}
}

func TestSignBatchDescriptorRejectsNilSigner(t *testing.T) {
	if _, err := SignBatchDescriptor(
		validSourceSigningDescriptor(),
		nil,
	); err == nil {
		t.Fatal("SignBatchDescriptor() error = nil, want nil signer rejection")
	}
}

func TestSignBatchDescriptorRejectsNonRSAKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	_, err = SignBatchDescriptor(validSourceSigningDescriptor(), privateKey)
	if err == nil {
		t.Fatal("SignBatchDescriptor() error = nil, want non-RSA rejection")
	}
	if !strings.Contains(err.Error(), "public key must be RSA") {
		t.Fatalf(
			"SignBatchDescriptor() error = %q, want RSA-key rejection",
			err,
		)
	}
}

func TestSignBatchDescriptorUsesFixedPSSContract(t *testing.T) {
	key := newBatchSigningPrivateKey(t)
	signer := &recordingBatchSigner{key: key}

	if _, err := SignBatchDescriptor(
		validSourceSigningDescriptor(),
		signer,
	); err != nil {
		t.Fatalf("SignBatchDescriptor() error = %v", err)
	}

	options, ok := signer.options.(*rsa.PSSOptions)
	if !ok {
		t.Fatalf("signer options type = %T, want *rsa.PSSOptions", signer.options)
	}
	if options.Hash != crypto.SHA256 {
		t.Fatalf("PSS hash = %v, want SHA-256", options.Hash)
	}
	if options.SaltLength != rsa.PSSSaltLengthEqualsHash {
		t.Fatalf(
			"PSS salt length = %d, want rsa.PSSSaltLengthEqualsHash",
			options.SaltLength,
		)
	}
}

// Test helpers.

func (signer *invalidBatchSigner) Public() crypto.PublicKey {
	return signer.publicKey
}

func (signer *invalidBatchSigner) Sign(
	_ io.Reader,
	_ []byte,
	_ crypto.SignerOpts,
) ([]byte, error) {
	return []byte{0x00}, nil
}

func newBatchSigningPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}

func (signer *recordingBatchSigner) Public() crypto.PublicKey {
	return &signer.key.PublicKey
}

func (signer *recordingBatchSigner) Sign(
	random io.Reader,
	digest []byte,
	options crypto.SignerOpts,
) ([]byte, error) {
	signer.options = options
	return signer.key.Sign(random, digest, options)
}

func validSourceSigningDescriptor() transportbatch.Descriptor {
	return transportbatch.Descriptor{
		Version:     transportbatch.DescriptorVersion,
		SourceID:    "iss-fs-01.iss.local",
		BatchID:     "batch-0001",
		RecordCount: 7,
		DataBytes:   4096,
		DataSHA256: "0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef",
		ManifestSHA256: "abcdef0123456789abcdef0123456789" +
			"abcdef0123456789abcdef0123456789",
	}
}

var _ crypto.Signer = (*invalidBatchSigner)(nil)
var _ crypto.Signer = (*recordingBatchSigner)(nil)
