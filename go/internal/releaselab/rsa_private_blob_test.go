// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releaselab

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestRSAPrivateKeyBlobHeaderAndLength(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := rsaPrivateKeyBlob(
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	if encoded[0] != capiPrivateKeyBlob {
		t.Fatalf(
			"blob_type=0x%02X",
			encoded[0],
		)
	}
	if encoded[1] != capiBlobVersion {
		t.Fatalf(
			"blob_version=0x%02X",
			encoded[1],
		)
	}
	if observed := binary.LittleEndian.Uint32(
		encoded[4:8],
	); observed != calgRSASign {
		t.Fatalf(
			"alg_id=0x%08X",
			observed,
		)
	}
	if observed := binary.LittleEndian.Uint32(
		encoded[8:12],
	); observed != rsa2Magic {
		t.Fatalf(
			"magic=0x%08X",
			observed,
		)
	}
	if observed := binary.LittleEndian.Uint32(
		encoded[12:16],
	); observed != 2048 {
		t.Fatalf(
			"bit_length=%d",
			observed,
		)
	}
	if observed := binary.LittleEndian.Uint32(
		encoded[16:20],
	); observed != uint32(privateKey.E) {
		t.Fatalf(
			"public_exponent=%d",
			observed,
		)
	}

	// 20 byte header + N + P + Q + DP + DQ + QINV + D.
	// For a 2048-bit key:
	//   20 + 256 + 5*128 + 256 = 1172.
	if len(encoded) != 1172 {
		t.Fatalf(
			"encoded_length=%d want=1172",
			len(encoded),
		)
	}
}

func TestLittleEndianFixed(t *testing.T) {
	t.Parallel()

	value := []byte{
		0x01,
		0x02,
		0x03,
	}
	integer := new(big.Int).SetBytes(value)

	encoded, err := littleEndianFixed(
		"test",
		integer,
		5,
	)
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		0x03,
		0x02,
		0x01,
		0x00,
		0x00,
	}
	for index := range expected {
		if encoded[index] != expected[index] {
			t.Fatalf(
				"encoded[%d]=0x%02X want=0x%02X",
				index,
				encoded[index],
				expected[index],
			)
		}
	}
}
