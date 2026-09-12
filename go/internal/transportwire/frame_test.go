// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportwire

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestReadHeader(t *testing.T) {
	want, encoded, _ := encodedWireTestHeader(t)
	reader := bytes.NewReader(append(encoded, []byte("manifest-start")...))

	got, err := ReadHeader(reader)
	if err != nil {
		t.Fatalf("ReadHeader() error = %v", err)
	}
	assertWireHeadersEqual(t, got, want)

	remaining := make([]byte, len("manifest-start"))
	if _, err := reader.Read(remaining); err != nil {
		t.Fatalf("read remaining payload marker: %v", err)
	}
	if string(remaining) != "manifest-start" {
		t.Fatalf("remaining bytes = %q, want manifest-start", remaining)
	}
}

func TestReadHeaderRejectsBadMagic(t *testing.T) {
	_, encoded, _ := encodedWireTestHeader(t)
	encoded[0] ^= 0xff

	_, err := ReadHeader(bytes.NewReader(encoded))
	if err == nil {
		t.Fatal("ReadHeader() error = nil, want bad magic rejection")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Fatalf("ReadHeader() error = %q, want bad magic rejection", err)
	}
}

func TestReadHeaderRejectsOversizedCertificateLengthBeforeAllocation(t *testing.T) {
	_, encoded, _ := encodedWireTestHeader(t)
	binary.BigEndian.PutUint32(
		encoded[116:120],
		transportpackage.MaxBatchSigningCertificateDERBytes+1,
	)

	_, err := ReadHeader(bytes.NewReader(encoded[:fixedHeaderBytes]))
	if err == nil {
		t.Fatal("ReadHeader() error = nil, want certificate length rejection")
	}
	if !strings.Contains(err.Error(), "certificate DER length is invalid") {
		t.Fatalf("ReadHeader() error = %q, want certificate length rejection", err)
	}
}

func TestReadHeaderRejectsOversizedSourceIDBeforeAllocation(t *testing.T) {
	_, encoded, _ := encodedWireTestHeader(t)
	binary.BigEndian.PutUint32(encoded[16:20], MaxTextBytes+1)

	_, err := ReadHeader(bytes.NewReader(encoded[:fixedHeaderBytes]))
	if err == nil {
		t.Fatal("ReadHeader() error = nil, want source ID length rejection")
	}
	if !strings.Contains(err.Error(), "source ID length is invalid") {
		t.Fatalf("ReadHeader() error = %q, want source ID length rejection", err)
	}
}

func TestReadHeaderRejectsTruncatedVariableHeader(t *testing.T) {
	_, encoded, _ := encodedWireTestHeader(t)

	_, err := ReadHeader(bytes.NewReader(encoded[:len(encoded)-1]))
	if err == nil {
		t.Fatal("ReadHeader() error = nil, want truncation rejection")
	}
}

func TestReadHeaderRejectsZeroManifestLength(t *testing.T) {
	_, encoded, _ := encodedWireTestHeader(t)
	binary.BigEndian.PutUint64(encoded[40:48], 0)

	_, err := ReadHeader(bytes.NewReader(encoded))
	if err == nil {
		t.Fatal("ReadHeader() error = nil, want manifest length rejection")
	}
	if !strings.Contains(err.Error(), "published manifest length is invalid") {
		t.Fatalf("ReadHeader() error = %q, want manifest length rejection", err)
	}
}

func TestWriteHeader(t *testing.T) {
	signedBatch, manifest := newWireTestBatch(t)

	var encoded bytes.Buffer
	if err := WriteHeader(&encoded, signedBatch, manifest); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}

	decoded, err := ReadHeader(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("ReadHeader() error = %v", err)
	}
	if decoded.ManifestBytes != uint64(len(manifest)) {
		t.Fatalf("ManifestBytes = %d, want %d", decoded.ManifestBytes, len(manifest))
	}
}

func TestWriteHeaderDeterministic(t *testing.T) {
	signedBatch, manifest := newWireTestBatch(t)

	var first bytes.Buffer
	if err := WriteHeader(&first, signedBatch, manifest); err != nil {
		t.Fatalf("WriteHeader(first) error = %v", err)
	}
	var second bytes.Buffer
	if err := WriteHeader(&second, signedBatch, manifest); err != nil {
		t.Fatalf("WriteHeader(second) error = %v", err)
	}

	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("WriteHeader() produced non-deterministic bytes")
	}
}

func TestWriteHeaderRejectsManifestHashMismatch(t *testing.T) {
	signedBatch, manifest := newWireTestBatch(t)
	manifest = append(append([]byte(nil), manifest...), 'x')

	err := WriteHeader(&bytes.Buffer{}, signedBatch, manifest)
	if err == nil {
		t.Fatal("WriteHeader() error = nil, want manifest hash rejection")
	}
	if !strings.Contains(err.Error(), "does not match signed descriptor") {
		t.Fatalf("WriteHeader() error = %q, want manifest hash rejection", err)
	}
}

func TestWriteHeaderRejectsNilWriter(t *testing.T) {
	signedBatch, manifest := newWireTestBatch(t)

	if err := WriteHeader(nil, signedBatch, manifest); err == nil {
		t.Fatal("WriteHeader() error = nil, want nil writer rejection")
	}
}

func TestWriteHeaderRejectsOversizedManifest(t *testing.T) {
	signedBatch, _ := newWireTestBatch(t)
	manifest := make([]byte, MaxManifestBytes+1)

	err := WriteHeader(&bytes.Buffer{}, signedBatch, manifest)
	if err == nil {
		t.Fatal("WriteHeader() error = nil, want manifest size rejection")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("WriteHeader() error = %q, want manifest size rejection", err)
	}
}

func assertWireHeadersEqual(t *testing.T, got Header, want Header) {
	t.Helper()

	if got.ManifestBytes != want.ManifestBytes {
		t.Fatalf("ManifestBytes = %d, want %d", got.ManifestBytes, want.ManifestBytes)
	}
	if got.SignedBatch.Version != want.SignedBatch.Version {
		t.Fatalf("signed version = %q, want %q", got.SignedBatch.Version, want.SignedBatch.Version)
	}
	if got.SignedBatch.Descriptor != want.SignedBatch.Descriptor {
		t.Fatalf("descriptor = %#v, want %#v", got.SignedBatch.Descriptor, want.SignedBatch.Descriptor)
	}
	if !bytes.Equal(got.SignedBatch.Signature, want.SignedBatch.Signature) {
		t.Fatal("signature mismatch")
	}
	if !bytes.Equal(
		got.SignedBatch.BatchSigningCertificateDER,
		want.SignedBatch.BatchSigningCertificateDER,
	) {
		t.Fatal("certificate DER mismatch")
	}
}

func encodedWireTestHeader(t *testing.T) (Header, []byte, []byte) {
	t.Helper()

	signedBatch, manifest := newWireTestBatch(t)
	var encoded bytes.Buffer
	if err := WriteHeader(&encoded, signedBatch, manifest); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	value, err := ReadHeader(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("ReadHeader() error = %v", err)
	}

	return value, encoded.Bytes(), manifest
}

func newWireTestBatch(t *testing.T) (transportpackage.SignedBatch, []byte) {
	t.Helper()

	const sourceID = "iss-fs-01.iss.local"
	manifest := []byte("{\n  \"version\": \"fi-batch-manifest/0.1\"\n}\n")
	manifestDigest := sha256.Sum256(manifest)
	dataDigest := sha256.Sum256([]byte("{\"record\":1}\n"))

	descriptor := transportbatch.Descriptor{
		Version:        transportbatch.DescriptorVersion,
		SourceID:       sourceID,
		BatchID:        "20260912T190000.000000000Z-0011223344556677",
		RecordCount:    1,
		DataBytes:      13,
		DataSHA256:     hex.EncodeToString(dataDigest[:]),
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			CommonName:         sourceID,
			OrganizationalUnit: []string{transporttrust.BatchSigningOrganizationalUnit},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	raw, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	signedBatch, err := transportpackage.NewSignedBatch(
		descriptor,
		certificate,
		key,
	)
	if err != nil {
		t.Fatalf("transportpackage.NewSignedBatch() error = %v", err)
	}

	return signedBatch, manifest
}
