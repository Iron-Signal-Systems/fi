// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releasecms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

var (
	oidCMSData = asn1.ObjectIdentifier{
		1, 2, 840, 113549, 1, 7, 1,
	}
	oidCMSSignedData = asn1.ObjectIdentifier{
		1, 2, 840, 113549, 1, 7, 2,
	}
	oidRSAEncryption = asn1.ObjectIdentifier{
		1, 2, 840, 113549, 1, 1, 1,
	}
	oidSHA256 = asn1.ObjectIdentifier{
		2, 16, 840, 1, 101, 3, 4, 2, 1,
	}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	ContentInfo      encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SignerIdentifier   issuerAndSerialNumber
	DigestAlgorithm    algorithmIdentifier
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
}

// SignDetached creates a detached CMS/PKCS#7 SignedData object over the exact
// bytes in content. The signer certificate is embedded in the signature. The
// content itself is not embedded.
func SignDetached(
	content []byte,
	certificate *x509.Certificate,
	privateKey *rsa.PrivateKey,
) ([]byte, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf(
			"content must not be empty",
		)
	}
	if certificate == nil {
		return nil, fmt.Errorf(
			"certificate is required",
		)
	}
	if privateKey == nil {
		return nil, fmt.Errorf(
			"private key is required",
		)
	}
	if certificate.SerialNumber == nil {
		return nil, fmt.Errorf(
			"certificate serial number is required",
		)
	}
	if len(certificate.Raw) == 0 ||
		len(certificate.RawIssuer) == 0 {
		return nil, fmt.Errorf(
			"certificate must contain encoded certificate and issuer bytes",
		)
	}

	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(
			"certificate public key is %T; RSA is required",
			certificate.PublicKey,
		)
	}
	if publicKey.N.Cmp(privateKey.PublicKey.N) != 0 ||
		publicKey.E != privateKey.PublicKey.E {
		return nil, fmt.Errorf(
			"certificate public key does not match private key",
		)
	}

	contentDigest := sha256.Sum256(
		content,
	)
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		contentDigest[:],
	)
	if err != nil {
		return nil, fmt.Errorf(
			"sign detached CMS content: %w",
			err,
		)
	}

	nullParameters := asn1.RawValue{
		Tag: 5,
	}

	value := signedData{
		Version: 1,
		DigestAlgorithms: []algorithmIdentifier{
			{
				Algorithm:  oidSHA256,
				Parameters: nullParameters,
			},
		},
		ContentInfo: encapsulatedContentInfo{
			EContentType: oidCMSData,
		},
		// CertificateSet is [0] IMPLICIT. The raw certificate DER is the
		// content of that context-specific constructed value.
		Certificates: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      append([]byte(nil), certificate.Raw...),
		},
		SignerInfos: []signerInfo{
			{
				Version: 1,
				SignerIdentifier: issuerAndSerialNumber{
					Issuer: asn1.RawValue{
						FullBytes: append(
							[]byte(nil),
							certificate.RawIssuer...,
						),
					},
					SerialNumber: new(
						big.Int,
					).Set(
						certificate.SerialNumber,
					),
				},
				DigestAlgorithm: algorithmIdentifier{
					Algorithm:  oidSHA256,
					Parameters: nullParameters,
				},
				SignatureAlgorithm: algorithmIdentifier{
					Algorithm:  oidRSAEncryption,
					Parameters: nullParameters,
				},
				Signature: signature,
			},
		},
	}

	signedDataDER, err := asn1.Marshal(
		value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode CMS SignedData: %w",
			err,
		)
	}

	encoded, err := asn1.Marshal(
		contentInfo{
			ContentType: oidCMSSignedData,
			Content: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      signedDataDER,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode CMS ContentInfo: %w",
			err,
		)
	}

	return encoded, nil
}
