// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releaselab

import (
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
)

const (
	capiPrivateKeyBlob = 0x07
	capiBlobVersion    = 0x02
	calgRSASign        = 0x00002400
	rsa2Magic          = 0x32415352
)

// rsaPrivateKeyBlob encodes an RSA private key in the legacy CryptoAPI
// PRIVATEKEYBLOB format required by CryptImportKey.
//
// The release lab uses this format only as a short-lived bridge into a
// temporary Windows CSP key container so Mssign32 can produce Authenticode
// signatures. It is not used as a persisted FI key format.
func rsaPrivateKeyBlob(
	privateKey *rsa.PrivateKey,
) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf(
			"RSA private key is required",
		)
	}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf(
			"validate RSA private key: %w",
			err,
		)
	}
	if len(privateKey.Primes) != 2 {
		return nil, fmt.Errorf(
			"RSA private key must contain exactly two primes; observed=%d",
			len(privateKey.Primes),
		)
	}
	if privateKey.E <= 0 ||
		privateKey.E > int(^uint32(0)) {
		return nil, fmt.Errorf(
			"RSA public exponent is outside CryptoAPI DWORD range: %d",
			privateKey.E,
		)
	}

	bitLength := privateKey.N.BitLen()
	if bitLength == 0 || bitLength%8 != 0 {
		return nil, fmt.Errorf(
			"RSA modulus bit length must be a non-zero multiple of eight; observed=%d",
			bitLength,
		)
	}
	modulusBytes := bitLength / 8
	if modulusBytes%2 != 0 {
		return nil, fmt.Errorf(
			"RSA modulus byte length must be even; observed=%d",
			modulusBytes,
		)
	}
	primeBytes := modulusBytes / 2

	privateKey.Precompute()

	dp := privateKey.Precomputed.Dp
	dq := privateKey.Precomputed.Dq
	qInv := privateKey.Precomputed.Qinv
	if dp == nil || dq == nil || qInv == nil {
		return nil, fmt.Errorf(
			"RSA CRT precomputation is unavailable",
		)
	}

	// PUBLICKEYSTRUC (8 bytes) + RSAPUBKEY (12 bytes).
	encoded := make(
		[]byte,
		20,
		20+modulusBytes+(primeBytes*5)+modulusBytes,
	)
	encoded[0] = capiPrivateKeyBlob
	encoded[1] = capiBlobVersion
	binary.LittleEndian.PutUint16(
		encoded[2:4],
		0,
	)
	binary.LittleEndian.PutUint32(
		encoded[4:8],
		calgRSASign,
	)
	binary.LittleEndian.PutUint32(
		encoded[8:12],
		rsa2Magic,
	)
	binary.LittleEndian.PutUint32(
		encoded[12:16],
		uint32(bitLength),
	)
	binary.LittleEndian.PutUint32(
		encoded[16:20],
		uint32(privateKey.E),
	)

	values := []struct {
		name  string
		value *big.Int
		size  int
	}{
		{
			name:  "modulus",
			value: privateKey.N,
			size:  modulusBytes,
		},
		{
			name:  "prime1",
			value: privateKey.Primes[0],
			size:  primeBytes,
		},
		{
			name:  "prime2",
			value: privateKey.Primes[1],
			size:  primeBytes,
		},
		{
			name:  "exponent1",
			value: dp,
			size:  primeBytes,
		},
		{
			name:  "exponent2",
			value: dq,
			size:  primeBytes,
		},
		{
			name:  "coefficient",
			value: qInv,
			size:  primeBytes,
		},
		{
			name:  "privateExponent",
			value: privateKey.D,
			size:  modulusBytes,
		},
	}

	for _, item := range values {
		value, err := littleEndianFixed(
			item.name,
			item.value,
			item.size,
		)
		if err != nil {
			return nil, err
		}
		encoded = append(
			encoded,
			value...,
		)
	}

	return encoded, nil
}

func littleEndianFixed(
	name string,
	value *big.Int,
	size int,
) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf(
			"%s is required",
			name,
		)
	}
	if value.Sign() < 0 {
		return nil, fmt.Errorf(
			"%s must not be negative",
			name,
		)
	}

	bigEndian := value.Bytes()
	if len(bigEndian) > size {
		return nil, fmt.Errorf(
			"%s requires %d bytes; maximum=%d",
			name,
			len(bigEndian),
			size,
		)
	}

	encoded := make(
		[]byte,
		size,
	)
	for index := range bigEndian {
		encoded[index] = bigEndian[len(bigEndian)-1-index]
	}
	return encoded, nil
}
