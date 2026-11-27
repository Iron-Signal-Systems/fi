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
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestReadHeaderV2(t *testing.T) {
	want, encoded, _ := encodedWireTestHeaderV2(t)
	reader := bytes.NewReader(append(encoded, []byte("manifest-start")...))

	got, err := ReadHeaderV2(reader)
	if err != nil {
		t.Fatalf("ReadHeaderV2() error = %v", err)
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

func TestReadHeaderV2RejectsOversizedEncodingBeforeAllocation(t *testing.T) {
	_, encoded, _ := encodedWireTestHeaderV2(t)
	binary.BigEndian.PutUint32(
		encoded[24:28],
		MaxDataEncodingBytes+1,
	)

	_, err := ReadHeaderV2(
		bytes.NewReader(encoded[:fixedHeaderBytesV2]),
	)
	if err == nil {
		t.Fatal("ReadHeaderV2() error = nil, want encoding length rejection")
	}
	if !strings.Contains(err.Error(), "data encoding length is invalid") {
		t.Fatalf(
			"ReadHeaderV2() error = %q, want encoding length rejection",
			err,
		)
	}
}

func TestWriteHeaderV2(t *testing.T) {
	signedBatch, manifest := newWireTestBatchV2(t)

	var encoded bytes.Buffer
	if err := WriteHeaderV2(&encoded, signedBatch, manifest); err != nil {
		t.Fatalf("WriteHeaderV2() error = %v", err)
	}
	if !bytes.Equal(encoded.Bytes()[:8], []byte(frameMagicV2)) {
		t.Fatalf(
			"wire magic = %q, want %q",
			encoded.Bytes()[:8],
			frameMagicV2,
		)
	}

	decoded, err := ReadHeaderV2(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("ReadHeaderV2() error = %v", err)
	}
	if decoded.ManifestBytes != uint64(len(manifest)) {
		t.Fatalf(
			"ManifestBytes = %d, want %d",
			decoded.ManifestBytes,
			len(manifest),
		)
	}
	if decoded.SignedBatch.Descriptor.DataEncoding !=
		transportencoding.DataEncodingZstd {
		t.Fatalf(
			"DataEncoding = %q, want %q",
			decoded.SignedBatch.Descriptor.DataEncoding,
			transportencoding.DataEncodingZstd,
		)
	}
}

func TestWriteHeaderV2RejectsV1Descriptor(t *testing.T) {
	signedBatch, manifest := newWireTestBatch(t)

	err := WriteHeaderV2(&bytes.Buffer{}, signedBatch, manifest)
	if err == nil {
		t.Fatal("WriteHeaderV2() error = nil, want V1 descriptor rejection")
	}
	if !strings.Contains(err.Error(), "descriptor version") {
		t.Fatalf(
			"WriteHeaderV2() error = %q, want descriptor version rejection",
			err,
		)
	}
}

func encodedWireTestHeaderV2(
	t testing.TB,
) (Header, []byte, []byte) {
	t.Helper()

	signedBatch, manifest := newWireTestBatchV2(t)
	var encoded bytes.Buffer
	if err := WriteHeaderV2(&encoded, signedBatch, manifest); err != nil {
		t.Fatalf("WriteHeaderV2() error = %v", err)
	}
	value, err := ReadHeaderV2(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("ReadHeaderV2() error = %v", err)
	}

	return value, encoded.Bytes(), manifest
}

func newWireTestBatchV2(
	t testing.TB,
) (transportpackage.SignedBatch, []byte) {
	t.Helper()

	const sourceID = "iss-fs-01.iss.local"
	manifest := []byte("{\n  \"version\": \"fi-batch-manifest/0.1\"\n}\n")
	manifestDigest := sha256.Sum256(manifest)
	data := []byte("{\"record\":1}\n")
	dataDigest := sha256.Sum256(data)
	encodedData := []byte("encoded-zstd-placeholder")
	encodedDataDigest := sha256.Sum256(encodedData)

	descriptor := transportbatch.Descriptor{
		Version:           transportbatch.DescriptorVersionV2,
		SourceID:          sourceID,
		BatchID:           "20260912T190000.000000000Z-0011223344556677",
		RecordCount:       1,
		DataBytes:         uint64(len(data)),
		DataSHA256:        hex.EncodeToString(dataDigest[:]),
		DataEncoding:      transportencoding.DataEncodingZstd,
		EncodedDataBytes:  uint64(len(encodedData)),
		EncodedDataSHA256: hex.EncodeToString(encodedDataDigest[:]),
		ManifestSHA256:    hex.EncodeToString(manifestDigest[:]),
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject: pkix.Name{
			CommonName: sourceID,
			OrganizationalUnit: []string{
				transporttrust.BatchSigningOrganizationalUnit,
			},
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
